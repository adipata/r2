// Interactive key session tests (spec §4.9.7, §11 D34; owner R7): `LineIo::interactive`
// over a recording TerminalDriver — when a session opens at all (styled sink, a reader with
// a live terminal, no spinner), the in-place drawing ops of each frame, clipping, the erase
// on close, terminal failures (degrade after `f`, line prompts after a failed enter), panic
// safety — and crossterm's events mapped to session keys.
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseEvent, MouseEventKind,
};
use r2_core::io::{ConsoleIo, Frame, Key, Line, Span, Tone};
use zeroize::Zeroizing;

use crate::io::line::{Sink, SinkTarget, WidthRule};
use crate::io::session::clip_line;
use crate::io::terminal::key_of;
use crate::io::{LineIo, LineReader, ReadOutcome, SecretRead, SinkStyle, TermOp, TerminalDriver};

/// What the recording driver saw.
#[derive(Default)]
struct DriverLog {
    entered: usize,
    left: usize,
    ops: Vec<Vec<TermOp>>,
}

/// A TerminalDriver over a shared log, scripted keys and sizes, with switchable failures.
struct RecordingDriver {
    log: Rc<RefCell<DriverLog>>,
    keys: Rc<RefCell<VecDeque<io::Result<Key>>>>,
    size: Rc<RefCell<(u16, u16)>>,
    fail_enter: bool,
}

impl TerminalDriver for RecordingDriver {
    fn enter(&mut self) -> io::Result<()> {
        self.log.borrow_mut().entered += 1;
        if self.fail_enter {
            return Err(io::Error::other("no raw mode"));
        }
        Ok(())
    }
    fn size(&self) -> io::Result<(u16, u16)> {
        Ok(*self.size.borrow())
    }
    fn read_key(&mut self) -> io::Result<Key> {
        self.keys
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(io::Error::other("no more keys")))
    }
    fn apply(&mut self, ops: &[TermOp]) -> io::Result<()> {
        let copy = ops
            .iter()
            .map(|op| match op {
                TermOp::Up(n) => TermOp::Up(*n),
                TermOp::Column(c) => TermOp::Column(*c),
                TermOp::ClearLineRight => TermOp::ClearLineRight,
                TermOp::ClearDown => TermOp::ClearDown,
                TermOp::ClearScreen => TermOp::ClearScreen,
                TermOp::Text(text) => TermOp::Text(text.clone()),
                TermOp::Newline => TermOp::Newline,
                TermOp::ShowCursor => TermOp::ShowCursor,
                TermOp::HideCursor => TermOp::HideCursor,
            })
            .collect();
        self.log.borrow_mut().ops.push(copy);
        Ok(())
    }
    fn leave(&mut self) {
        self.log.borrow_mut().left += 1;
    }
}

/// A LineReader whose terminal is the recording driver (one per `terminal_driver` call)
/// until it is told to degrade; line reads are never expected.
struct TerminalReader {
    log: Rc<RefCell<DriverLog>>,
    keys: Rc<RefCell<VecDeque<io::Result<Key>>>>,
    size: Rc<RefCell<(u16, u16)>>,
    has_terminal: bool,
    fail_enter: bool,
    degraded: Rc<RefCell<Vec<String>>>,
}

impl LineReader for TerminalReader {
    fn read_command(&mut self, _prompt: &str) -> io::Result<ReadOutcome> {
        Ok(ReadOutcome::Eof)
    }
    fn read_param(&mut self, _prompt: &str, _choices: &[String]) -> io::Result<ReadOutcome> {
        Ok(ReadOutcome::Eof)
    }
    fn read_secret(&mut self, _prompt: &str) -> io::Result<SecretRead> {
        Ok(SecretRead::Eof)
    }
    fn terminal_driver(&mut self) -> Option<Box<dyn TerminalDriver>> {
        self.has_terminal.then(|| {
            Box::new(RecordingDriver {
                log: Rc::clone(&self.log),
                keys: Rc::clone(&self.keys),
                size: Rc::clone(&self.size),
                fail_enter: self.fail_enter,
            }) as Box<dyn TerminalDriver>
        })
    }
    fn degrade(&mut self, err: &io::Error) {
        self.degraded.borrow_mut().push(err.to_string());
        self.has_terminal = false;
    }
}

struct Rig {
    io: LineIo<TerminalReader>,
    log: Rc<RefCell<DriverLog>>,
    keys: Rc<RefCell<VecDeque<io::Result<Key>>>>,
    size: Rc<RefCell<(u16, u16)>>,
    degraded: Rc<RefCell<Vec<String>>>,
}

fn rig_with(style: SinkStyle, has_terminal: bool, fail_enter: bool) -> Rig {
    let log = Rc::new(RefCell::new(DriverLog::default()));
    let keys = Rc::new(RefCell::new(VecDeque::new()));
    let size = Rc::new(RefCell::new((80, 24)));
    let degraded = Rc::new(RefCell::new(Vec::new()));
    let reader = TerminalReader {
        log: Rc::clone(&log),
        keys: Rc::clone(&keys),
        size: Rc::clone(&size),
        has_terminal,
        fail_enter,
        degraded: Rc::clone(&degraded),
    };
    let sink = Sink {
        style,
        target: SinkTarget::Capture(Rc::new(RefCell::new(Vec::new()))),
        width: WidthRule::Fixed(80),
    };
    Rig {
        io: LineIo::new(reader, sink, 2, 32, false),
        log,
        keys,
        size,
        degraded,
    }
}

fn rig() -> Rig {
    rig_with(SinkStyle::NoColor, true, false)
}

fn plain(text: &str) -> Line {
    vec![Span {
        text: text.to_owned(),
        tone: Tone::Plain,
    }]
}

fn frame(lines: &[&str], cursor: Option<(usize, usize)>) -> Frame {
    Frame {
        lines: lines.iter().map(|text| plain(text)).collect(),
        cursor,
    }
}

fn text(value: &str) -> TermOp {
    TermOp::Text(Zeroizing::new(value.to_owned()))
}

// ---------------------------------------------------------------------------------------
// when a session opens
// ---------------------------------------------------------------------------------------

#[test]
fn no_session_on_the_plain_sink() {
    let rig = rig_with(SinkStyle::Plain, true, false);
    let mut called = false;
    assert!(!rig.io.interactive(&mut |_| called = true));
    assert!(!called);
    assert_eq!(rig.log.borrow().entered, 0, "the terminal is never touched");
}

#[test]
fn no_session_without_a_live_terminal() {
    let rig = rig_with(SinkStyle::Full, false, false);
    let mut called = false;
    assert!(!rig.io.interactive(&mut |_| called = true));
    assert!(!called);
}

#[test]
fn a_failed_enter_degrades_the_reader_and_runs_nothing() {
    let rig = rig_with(SinkStyle::Full, true, true);
    let mut called = false;
    assert!(!rig.io.interactive(&mut |_| called = true));
    assert!(!called);
    let log = rig.log.borrow();
    assert_eq!(
        (log.entered, log.left),
        (1, 1),
        "a half-entered terminal is left again"
    );
    assert_eq!(*rig.degraded.borrow(), ["no raw mode"]);
}

// ---------------------------------------------------------------------------------------
// drawing
// ---------------------------------------------------------------------------------------

#[test]
fn frames_are_drawn_in_place_and_the_last_one_is_erased() {
    let rig = rig();
    let opened = rig.io.interactive(&mut |session| {
        assert_eq!(session.size(), (80, 24));
        session.draw(&frame(&["a", "b"], None)).unwrap();
        session
            .draw(&frame(&["c", "d", "e"], Some((1, 2))))
            .unwrap();
        session.draw(&frame(&["f"], None)).unwrap();
    });
    assert!(opened);
    let log = rig.log.borrow();
    assert_eq!((log.entered, log.left), (1, 1));
    assert_eq!(
        log.ops[0],
        vec![
            TermOp::HideCursor,
            TermOp::Column(0),
            text("a"),
            TermOp::ClearLineRight,
            TermOp::Newline,
            text("b"),
            TermOp::ClearLineRight,
            TermOp::ClearDown,
        ]
    );
    // back up from the last row of the first frame; then the cursor goes to (1, 2)
    assert_eq!(
        log.ops[1],
        vec![
            TermOp::HideCursor,
            TermOp::Up(1),
            TermOp::Column(0),
            text("c"),
            TermOp::ClearLineRight,
            TermOp::Newline,
            text("d"),
            TermOp::ClearLineRight,
            TermOp::Newline,
            text("e"),
            TermOp::ClearLineRight,
            TermOp::ClearDown,
            TermOp::Up(1),
            TermOp::Column(2),
            TermOp::ShowCursor,
        ]
    );
    // the cursor was on row 1: up one row; a one-row frame clears what is below it
    assert_eq!(
        log.ops[2],
        vec![
            TermOp::HideCursor,
            TermOp::Up(1),
            TermOp::Column(0),
            text("f"),
            TermOp::ClearLineRight,
            TermOp::ClearDown,
        ]
    );
    // close: erase from the frame's first row, cursor shown
    assert_eq!(
        log.ops[3],
        vec![TermOp::Column(0), TermOp::ClearDown, TermOp::ShowCursor]
    );
    assert!(rig.degraded.borrow().is_empty());
}

#[test]
fn a_session_that_never_drew_only_shows_the_cursor_again() {
    let rig = rig();
    assert!(rig.io.interactive(&mut |_| {}));
    assert_eq!(rig.log.borrow().ops, vec![vec![TermOp::ShowCursor]]);
}

#[test]
fn rows_are_clipped_to_the_width_and_the_frame_to_the_height() {
    let rig = rig();
    *rig.size.borrow_mut() = (10, 4);
    rig.io.interactive(&mut |session| {
        session
            .draw(&frame(
                &["abcdefghijkl", "日本語日本語", "\u{1b}[2J", "4", "5"],
                Some((9, 99)),
            ))
            .unwrap();
    });
    let log = rig.log.borrow();
    let texts: Vec<&TermOp> = log.ops[0]
        .iter()
        .filter(|op| matches!(op, TermOp::Text(_)))
        .collect();
    // 9 cells per row, 3 rows (the screen height minus one)
    assert_eq!(
        texts,
        [&text("abcdefghi"), &text("日本語日"), &text("\u{fffd}[2J")]
    );
    // the cursor is clamped to the last drawn row and the clip width
    assert_eq!(
        log.ops[0][log.ops[0].len() - 2..],
        [TermOp::Column(9), TermOp::ShowCursor]
    );
}

#[test]
fn clip_line_keeps_tones_and_cuts_between_spans() {
    let line = vec![
        Span {
            text: "ab".into(),
            tone: Tone::Bold,
        },
        Span {
            text: "cd\u{7}".into(),
            tone: Tone::Dim,
        },
    ];
    assert_eq!(
        clip_line(&line, 3),
        vec![
            Span {
                text: "ab".into(),
                tone: Tone::Bold
            },
            Span {
                text: "c".into(),
                tone: Tone::Dim
            },
        ]
    );
    assert_eq!(clip_line(&line, 2).len(), 1);
    assert_eq!(clip_line(&line, 10)[1].text, "cd\u{fffd}");
}

#[test]
fn a_narrower_terminal_redraws_from_a_cleared_screen() {
    let rig = rig();
    rig.io.interactive(&mut |session| {
        session.draw(&frame(&["a", "b"], None)).unwrap();
        *rig.size.borrow_mut() = (60, 24);
        session.draw(&frame(&["a", "b"], None)).unwrap();
        *rig.size.borrow_mut() = (70, 24);
        session.draw(&frame(&["a", "b"], None)).unwrap();
    });
    let log = rig.log.borrow();
    assert_eq!(log.ops[1][..2], [TermOp::HideCursor, TermOp::ClearScreen]);
    // wider again: back to the in-place redraw
    assert_eq!(
        log.ops[2][..3],
        [TermOp::HideCursor, TermOp::Up(1), TermOp::Column(0)]
    );
}

#[test]
fn rows_are_rendered_in_the_sink_style() {
    let error_line = vec![Span {
        text: "bad".into(),
        tone: Tone::Error,
    }];
    let rendered = |style: SinkStyle| -> String {
        let rig = rig_with(style, true, false);
        rig.io.interactive(&mut |session| {
            session
                .draw(&Frame {
                    lines: vec![error_line.clone()],
                    cursor: None,
                })
                .unwrap();
        });
        let log = rig.log.borrow();
        match &log.ops[0][2] {
            TermOp::Text(text) => text.as_str().to_owned(),
            other => panic!("{other:?}"),
        }
    };
    let full = rendered(SinkStyle::Full);
    let no_color = rendered(SinkStyle::NoColor);
    assert!(
        full.contains("bad") && full.contains("31"),
        "red in Full: {full:?}"
    );
    assert!(
        no_color.contains("bad") && !no_color.contains("31"),
        "{no_color:?}"
    );
    assert!(
        no_color.contains("\u{1b}[1m"),
        "bold kept without colour: {no_color:?}"
    );
}

// ---------------------------------------------------------------------------------------
// keys and failures
// ---------------------------------------------------------------------------------------

#[test]
fn keys_come_from_the_driver() {
    let rig = rig();
    rig.keys
        .borrow_mut()
        .extend([Ok(Key::Down), Ok(Key::Paste("c0fe".into()))]);
    let mut keys = Vec::new();
    rig.io.interactive(&mut |session| {
        keys.push(session.read_key().unwrap());
        keys.push(session.read_key().unwrap());
    });
    assert_eq!(keys, [Key::Down, Key::Paste("c0fe".into())]);
}

#[test]
fn a_terminal_error_ends_the_session_and_degrades_the_reader_afterwards() {
    let rig = rig();
    rig.keys
        .borrow_mut()
        .push_back(Err(io::Error::other("tty gone")));
    let mut seen = Vec::new();
    let opened = rig.io.interactive(&mut |session| {
        session.draw(&frame(&["a"], None)).unwrap();
        let err = session.read_key().unwrap_err();
        seen.push(err.message.clone());
        // nothing more is drawn or read after the failure
        seen.push(session.draw(&frame(&["b"], None)).unwrap_err().message);
        seen.push(session.read_key().unwrap_err().message);
        // the reader is not degraded while the session is open
        assert!(rig.degraded.borrow().is_empty());
    });
    assert!(opened);
    assert_eq!(
        seen,
        [
            "terminal error: tty gone",
            "terminal error: tty gone",
            "terminal error: tty gone"
        ]
    );
    assert_eq!(*rig.degraded.borrow(), ["tty gone"]);
    let log = rig.log.borrow();
    assert_eq!(log.ops.len(), 1, "no erase on a failed terminal");
    assert_eq!(log.left, 1);
    drop(log);
    // the degraded reader offers no terminal any more
    let mut called = false;
    assert!(!rig.io.interactive(&mut |_| called = true));
    assert!(!called);
}

#[test]
fn the_terminal_is_left_when_f_panics() {
    let rig = rig();
    let result = catch_unwind(AssertUnwindSafe(|| {
        rig.io.interactive(&mut |session| {
            session.draw(&frame(&["a"], None)).unwrap();
            panic!("boom");
        })
    }));
    assert!(result.is_err());
    let log = rig.log.borrow();
    assert_eq!(log.left, 1, "raw mode is undone while unwinding");
    assert_eq!(log.ops.len(), 1, "nothing is drawn while panicking");
}

#[test]
fn degrading_reader_offers_a_terminal_until_it_degrades() {
    use crate::io::terminal::ReedlineReader;
    use crate::io::{DegradingReader, PlainReader};
    let mut reader = DegradingReader::new(
        ReedlineReader::new(None, false),
        PlainReader::new(false, None),
    );
    assert!(reader.terminal_driver().is_some());
    reader.degrade(&io::Error::other("tty gone"));
    assert!(reader.terminal_driver().is_none());
    // a second degrade is a no-op
    reader.degrade(&io::Error::other("again"));
    assert!(reader.terminal_driver().is_none());
}

// ---------------------------------------------------------------------------------------
// crossterm events → keys
// ---------------------------------------------------------------------------------------

fn press(code: KeyCode, modifiers: KeyModifiers) -> Event {
    Event::Key(KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    })
}

#[test]
fn crossterm_events_map_to_session_keys() {
    let none = KeyModifiers::NONE;
    assert_eq!(
        key_of(press(KeyCode::Char('a'), none)),
        Some(Key::Char('a'))
    );
    assert_eq!(
        key_of(press(KeyCode::Char('A'), KeyModifiers::SHIFT)),
        Some(Key::Char('A'))
    );
    assert_eq!(
        key_of(press(KeyCode::Char('C'), KeyModifiers::CONTROL)),
        Some(Key::Ctrl('c'))
    );
    // AltGr on Windows arrives as Ctrl+Alt: the character itself
    assert_eq!(
        key_of(press(
            KeyCode::Char('@'),
            KeyModifiers::CONTROL | KeyModifiers::ALT
        )),
        Some(Key::Char('@'))
    );
    assert_eq!(key_of(press(KeyCode::Char('x'), KeyModifiers::ALT)), None);
    for (code, key) in [
        (KeyCode::Enter, Key::Enter),
        (KeyCode::Esc, Key::Esc),
        (KeyCode::Tab, Key::Tab),
        (KeyCode::BackTab, Key::BackTab),
        (KeyCode::Backspace, Key::Backspace),
        (KeyCode::Delete, Key::Delete),
        (KeyCode::Insert, Key::Insert),
        (KeyCode::Up, Key::Up),
        (KeyCode::Down, Key::Down),
        (KeyCode::Left, Key::Left),
        (KeyCode::Right, Key::Right),
        (KeyCode::Home, Key::Home),
        (KeyCode::End, Key::End),
        (KeyCode::PageUp, Key::PageUp),
        (KeyCode::PageDown, Key::PageDown),
    ] {
        assert_eq!(key_of(press(code, none)), Some(key));
    }
    assert_eq!(key_of(press(KeyCode::F(1), none)), None);
    // Windows also reports releases: ignored; repeats count
    let release = Event::Key(KeyEvent {
        code: KeyCode::Char('a'),
        modifiers: none,
        kind: KeyEventKind::Release,
        state: KeyEventState::NONE,
    });
    assert_eq!(key_of(release), None);
    let repeat = Event::Key(KeyEvent {
        code: KeyCode::Down,
        modifiers: none,
        kind: KeyEventKind::Repeat,
        state: KeyEventState::NONE,
    });
    assert_eq!(key_of(repeat), Some(Key::Down));
    assert_eq!(
        key_of(Event::Paste("0xc0fe".into())),
        Some(Key::Paste("0xc0fe".into()))
    );
    assert_eq!(key_of(Event::Resize(100, 40)), Some(Key::Resize));
    assert_eq!(key_of(Event::FocusGained), None);
    let mouse = Event::Mouse(MouseEvent {
        kind: MouseEventKind::Moved,
        column: 0,
        row: 0,
        modifiers: none,
    });
    assert_eq!(key_of(mouse), None);
}
