// The interactive template panel (spec §5.12, §11 D34; owner R10): the checklist editor's
// face on a terminal, drawn in place below the command through `ConsoleIo::interactive`.
//
// The panel is a pure state machine — `handle(key)` changes the working template and the
// mode, `frame(width, height)` lays out what to draw — and `run` only loops over a
// `KeySession`, so every behavior is unit-tested without a terminal. Values are parsed by
// the line editor's own `parse_value`, names resolved by its `kind_of`, and the `:` line is
// its grammar (`apply`), so messages and hints are the line checklist's word for word.
use indexmap::IndexMap;
use r2_config::model::CustomAttributeDef;
use r2_core::catalog::{self, CKA_CATALOG};
use r2_core::error::ConsoleError;
use r2_core::io::{Frame, Key, KeySession, Line, Span, Tone};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_core::text::py_strip;
use r2_services::templatefile::NON_CREATION_ATTRS;
use zeroize::Zeroize;

use super::{HELP, apply, glyph, identity_note, kind_of, parse_value, truthy};
use crate::io::session::{char_cells, text_cells};

/// Smaller terminals get the line checklist (the panel would not show a useful table).
pub(crate) const MIN_COLUMNS: usize = 40;
pub(crate) const MIN_ROWS: usize = 10;
/// Most candidates the add list shows at once.
const PICK_ROWS: usize = 8;
/// The value column never gets narrower than this while names can still be shortened.
const VALUE_MIN: usize = 12;
const MARKER: &str = "❯ ";
const NO_MARKER: &str = "  ";

/// How a panel session ended.
#[derive(Debug)]
pub(crate) enum End {
    /// Enter on the OK row, or `:ok`.
    Accept,
    /// Esc in the table, or `:cancel` / `:abort` → UserAbort "template edit cancelled".
    Cancel,
    /// Ctrl-C (Ctrl-D in the table) → UserAbort "aborted while entering 'template'".
    Abort,
    /// The terminal is smaller than MIN_COLUMNS × MIN_ROWS: the line checklist takes over.
    TooSmall,
    /// The terminal failed: the line checklist takes over with the edits made so far.
    TerminalLost,
    /// A non-Param error from the grammar (none is known; propagated, never swallowed).
    Failed(ConsoleError),
}

/// The status line under the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Message {
    /// An input error: message and hint, as the line checklist's error panel shows them.
    Error(String, Option<String>),
    /// Information (the §4.7 identity note, "already row n").
    Note(String),
}

impl Message {
    fn from_error(err: &ConsoleError) -> Self {
        Message::Error(
            err.message.clone(),
            err.hint.clone().filter(|hint| !hint.is_empty()),
        )
    }
}

/// A one-line text input: the text and the cursor as a byte offset on a char boundary. The
/// text may be key material (a CKA_VALUE): wiped on drop.
#[derive(Debug, Default)]
pub(crate) struct Input {
    text: String,
    at: usize,
}

impl Drop for Input {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

impl Input {
    fn new(text: String) -> Self {
        let at = text.len();
        Self { text, at }
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    fn insert(&mut self, text: &str) {
        self.text.insert_str(self.at, text);
        self.at += text.len();
    }

    fn previous(&self) -> Option<char> {
        self.text
            .get(..self.at)
            .and_then(|before| before.chars().next_back())
    }

    fn next(&self) -> Option<char> {
        self.text
            .get(self.at..)
            .and_then(|after| after.chars().next())
    }

    /// The editing keys every input shares; true when `key` was one of them.
    fn edit(&mut self, key: &Key) -> bool {
        match key {
            Key::Backspace => {
                if let Some(c) = self.previous() {
                    self.at -= c.len_utf8();
                    self.text.replace_range(self.at..self.at + c.len_utf8(), "");
                }
            }
            Key::Delete | Key::Ctrl('d') => {
                if let Some(c) = self.next() {
                    self.text.replace_range(self.at..self.at + c.len_utf8(), "");
                }
            }
            Key::Left => {
                if let Some(c) = self.previous() {
                    self.at -= c.len_utf8();
                }
            }
            Key::Right => {
                if let Some(c) = self.next() {
                    self.at += c.len_utf8();
                }
            }
            Key::Home | Key::Ctrl('a') => self.at = 0,
            Key::End | Key::Ctrl('e') => self.at = self.text.len(),
            Key::Ctrl('u') => {
                self.text.replace_range(..self.at, "");
                self.at = 0;
            }
            Key::Ctrl('k') => self.text.truncate(self.at),
            _ => return false,
        }
        true
    }
}

#[derive(Debug)]
enum Mode {
    /// Moving over the rows.
    Browse,
    /// Editing the value of an existing row.
    Edit { row: usize, input: Input },
    /// The add list: a filter and the chosen candidate.
    Pick { filter: Input, choice: usize },
    /// The value of an attribute picked from the add list (not yet a row).
    AddValue {
        name: String,
        kind: AttrKind,
        input: Input,
    },
    /// The `:` line (the §5.12 grammar).
    Command { input: Input },
}

/// One entry of the add list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) name: String,
    pub(crate) kind: AttrKind,
    /// A templates.custom_attributes entry (not in CKA_CATALOG).
    pub(crate) custom: bool,
}

/// The panel over a working copy of the template.
pub(crate) struct Panel<'a> {
    pub(crate) template: KeyTemplate,
    title: String,
    custom: &'a IndexMap<String, CustomAttributeDef>,
    /// The highlighted item: 0..rows are the attribute rows, `rows` is the OK row.
    cursor: usize,
    /// The first attribute row shown when the rows do not fit.
    top: usize,
    /// Attribute rows the last frame showed (the PageUp/PageDown step).
    page: usize,
    mode: Mode,
    message: Option<Message>,
}

impl<'a> Panel<'a> {
    pub(crate) fn new(
        template: KeyTemplate,
        title: &str,
        custom: &'a IndexMap<String, CustomAttributeDef>,
    ) -> Self {
        let mut panel = Self {
            template,
            title: title.to_owned(),
            custom,
            cursor: 0,
            top: 0,
            page: 1,
            mode: Mode::Browse,
            message: None,
        };
        panel.cursor = panel.first_item();
        panel
    }

    /// Draw, read, handle — until the session ends.
    pub(crate) fn run(&mut self, session: &mut dyn KeySession) -> End {
        let (width, height) = session.size();
        if width < MIN_COLUMNS || height < MIN_ROWS {
            return End::TooSmall;
        }
        loop {
            let (width, height) = session.size();
            let frame = self.frame(width, height);
            if session.draw(&frame).is_err() {
                return End::TerminalLost;
            }
            let Ok(key) = session.read_key() else {
                return End::TerminalLost;
            };
            if let Some(end) = self.handle(key) {
                return end;
            }
        }
    }

    #[cfg(test)]
    /// The highlighted item (rows, then the OK row at index `rows`).
    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    #[cfg(test)]
    pub(crate) fn message(&self) -> Option<&Message> {
        self.message.as_ref()
    }

    #[cfg(test)]
    /// The text of the open input (value, add filter, `:` line), if any.
    pub(crate) fn input(&self) -> Option<&str> {
        match &self.mode {
            Mode::Browse => None,
            Mode::Edit { input, .. }
            | Mode::Pick { filter: input, .. }
            | Mode::AddValue { input, .. }
            | Mode::Command { input } => Some(input.text()),
        }
    }

    // -- keys -------------------------------------------------------------------------

    /// One key; Some when the session ends.
    pub(crate) fn handle(&mut self, key: Key) -> Option<End> {
        if key == Key::Ctrl('c') {
            return Some(End::Abort);
        }
        if key == Key::Resize {
            return None;
        }
        match std::mem::replace(&mut self.mode, Mode::Browse) {
            Mode::Browse => self.browse(key),
            Mode::Edit { row, input } => self.edit_value(row, input, key),
            Mode::Pick { filter, choice } => self.pick(filter, choice, key),
            Mode::AddValue { name, kind, input } => self.add_value(name, kind, input, key),
            Mode::Command { input } => self.command(input, key),
        }
    }

    fn rows(&self) -> usize {
        self.template.attrs.len()
    }

    /// Locked rows are display-only: the cursor skips them.
    fn selectable(&self, item: usize) -> bool {
        self.template
            .attrs
            .get(item)
            .is_none_or(|attr| !attr.locked)
    }

    fn first_item(&self) -> usize {
        (0..=self.rows())
            .find(|&item| self.selectable(item))
            .unwrap_or(self.rows())
    }

    fn step(&mut self, down: bool, times: usize) {
        for _ in 0..times {
            let next = if down {
                (self.cursor + 1..=self.rows()).find(|&item| self.selectable(item))
            } else {
                (0..self.cursor).rev().find(|&item| self.selectable(item))
            };
            match next {
                Some(item) => self.cursor = item,
                None => break,
            }
        }
    }

    fn browse(&mut self, key: Key) -> Option<End> {
        self.message = None;
        let on_row = self.cursor < self.rows();
        match key {
            Key::Up => self.step(false, 1),
            Key::Down => self.step(true, 1),
            Key::PageUp => self.step(false, self.page.max(1)),
            Key::PageDown => self.step(true, self.page.max(1)),
            Key::Home => self.cursor = self.first_item(),
            Key::End => self.cursor = self.rows(),
            Key::Enter if !on_row => return Some(End::Accept),
            Key::Enter | Key::Char(' ') if on_row => self.activate(),
            Key::Char('-') | Key::Delete => self.set_enabled(false),
            Key::Char('+') => self.set_enabled(true),
            Key::Char('a') | Key::Insert => {
                self.mode = Mode::Pick {
                    filter: Input::default(),
                    choice: 0,
                };
            }
            Key::Char(':') => {
                self.mode = Mode::Command {
                    input: Input::default(),
                };
            }
            Key::Esc => return Some(End::Cancel),
            Key::Ctrl('d') => return Some(End::Abort),
            _ => {}
        }
        None
    }

    /// Space/Enter on a row: a disabled row is re-enabled; an enabled boolean flips; any
    /// other row opens its value for editing.
    fn activate(&mut self) {
        let row = self.cursor;
        let Some(attr) = self.template.attrs.get_mut(row) else {
            return;
        };
        if attr.locked {
            return;
        }
        if attr.kind == AttrKind::Bool {
            if attr.enabled {
                attr.value = AttrValue::Bool(!truthy(&attr.value));
            } else {
                attr.enabled = true;
            }
            return;
        }
        let input = Input::new(initial_text(&attr.value));
        self.mode = Mode::Edit { row, input };
    }

    fn set_enabled(&mut self, enabled: bool) {
        if let Some(attr) = self.template.attrs.get_mut(self.cursor)
            && !attr.locked
        {
            attr.enabled = enabled;
        }
    }

    fn edit_value(&mut self, row: usize, mut input: Input, key: Key) -> Option<End> {
        let attr = self.template.attrs.get(row)?;
        let (name, kind) = (attr.name.clone(), attr.kind);
        match key {
            Key::Esc => {
                self.message = None;
                return None;
            }
            Key::Enter => match parse_value(&name, kind, &submitted(kind, input.text())) {
                Ok(value) => {
                    // a value typed into a disabled row is meant to be used: enable it
                    if let Some(attr) = self.template.attrs.get_mut(row) {
                        attr.value = value;
                        attr.enabled = true;
                    }
                    self.message = None;
                    return None;
                }
                Err(err) => self.message = Some(Message::from_error(&err)),
            },
            other => self.message = type_into(&mut input, &name, kind, other),
        }
        self.mode = Mode::Edit { row, input };
        None
    }

    fn pick(&mut self, mut filter: Input, mut choice: usize, key: Key) -> Option<End> {
        self.message = None;
        let count = self.candidates(filter.text()).len();
        match key {
            Key::Esc => return None,
            Key::Up => choice = choice.saturating_sub(1),
            Key::Down => choice = (choice + 1).min(count.saturating_sub(1)),
            Key::PageUp => choice = choice.saturating_sub(PICK_ROWS),
            Key::PageDown => choice = (choice + PICK_ROWS).min(count.saturating_sub(1)),
            Key::Enter => match self.candidates(filter.text()).into_iter().nth(choice) {
                Some(candidate) => return self.choose(candidate),
                None => {
                    // nothing matches: the line editor's unknown-name error
                    if let Err(err) = kind_of(py_strip(filter.text()), self.custom) {
                        self.message = Some(Message::from_error(&err));
                    }
                }
            },
            Key::Char(c) if !c.is_control() => {
                filter.insert(c.encode_utf8(&mut [0; 4]));
                choice = 0;
            }
            Key::Paste(text) => {
                filter.insert(&one_line(&text));
                choice = 0;
            }
            other => {
                if filter.edit(&other) {
                    choice = 0;
                }
            }
        }
        self.mode = Mode::Pick { filter, choice };
        None
    }

    /// Enter in the add list: a name already in the template moves the cursor there; a
    /// boolean is added as true (Space flips it); any other kind asks for its value.
    fn choose(&mut self, candidate: Candidate) -> Option<End> {
        let Candidate { name, kind, .. } = candidate;
        if let Some(index) = self
            .template
            .attrs
            .iter()
            .position(|attr| attr.name == name)
        {
            if self.selectable(index) {
                self.cursor = index;
            }
            self.message = Some(Message::Note(format!(
                "{name} is already row {}",
                index + 1
            )));
            return None;
        }
        self.message = None;
        if kind == AttrKind::Bool {
            self.template
                .attrs
                .push(TemplateAttr::new(name, kind, AttrValue::Bool(true)));
            self.cursor = self.rows() - 1;
            return None;
        }
        self.mode = Mode::AddValue {
            name,
            kind,
            input: Input::default(),
        };
        None
    }

    fn add_value(
        &mut self,
        name: String,
        kind: AttrKind,
        mut input: Input,
        key: Key,
    ) -> Option<End> {
        match key {
            Key::Esc => {
                self.message = None;
                return None;
            }
            Key::Enter => match parse_value(&name, kind, &submitted(kind, input.text())) {
                Ok(value) => {
                    self.message = identity_note(&name).map(|note| Message::Note(note.to_owned()));
                    self.template
                        .attrs
                        .push(TemplateAttr::new(name, kind, value));
                    self.cursor = self.rows() - 1;
                    return None;
                }
                Err(err) => self.message = Some(Message::from_error(&err)),
            },
            other => self.message = type_into(&mut input, &name, kind, other),
        }
        self.mode = Mode::AddValue { name, kind, input };
        None
    }

    fn command(&mut self, mut input: Input, key: Key) -> Option<End> {
        self.message = None;
        match key {
            Key::Esc => return None,
            Key::Enter => {
                let line = py_strip(input.text()).to_owned();
                match line.as_str() {
                    "" => return None,
                    "ok" => return Some(End::Accept),
                    "cancel" | "abort" => return Some(End::Cancel),
                    _ => {}
                }
                let rows = self.rows();
                match apply(&mut self.template, &line, self.custom) {
                    Ok(note) => {
                        self.message = note.map(|note| Message::Note(note.to_owned()));
                        if self.rows() > rows {
                            self.cursor = self.rows() - 1;
                        }
                        return None;
                    }
                    // keep the line so it can be corrected
                    Err(err) if err.param_name().is_some() => {
                        self.message = Some(Message::from_error(&err));
                    }
                    Err(err) => return Some(End::Failed(err)),
                }
            }
            Key::Char(c) if !c.is_control() => input.insert(c.encode_utf8(&mut [0; 4])),
            Key::Paste(text) => input.insert(&one_line(&text)),
            other => {
                input.edit(&other);
            }
        }
        self.mode = Mode::Command { input };
        None
    }

    /// The add list for `filter`: CKA_CATALOG (its order), then the custom attributes not in
    /// it. An empty filter lists everything; otherwise names whose part after `CKA_` starts
    /// with the filter come first, then names containing it (case-insensitive, an own
    /// `CKA_` prefix ignored).
    pub(crate) fn candidates(&self, filter: &str) -> Vec<Candidate> {
        let all = CKA_CATALOG
            .iter()
            .map(|entry| Candidate {
                name: entry.name.to_owned(),
                kind: entry.kind,
                custom: false,
            })
            .chain(
                self.custom
                    .iter()
                    .filter(|(name, _)| catalog::cka(name).is_none())
                    .map(|(name, def)| Candidate {
                        name: name.clone(),
                        kind: def.kind,
                        custom: true,
                    }),
            );
        let query = py_strip(filter).to_uppercase();
        let query = query.strip_prefix("CKA_").unwrap_or(&query);
        if query.is_empty() {
            return all.collect();
        }
        let mut ranked: Vec<(usize, Candidate)> = all
            .filter_map(|candidate| {
                let upper = candidate.name.to_uppercase();
                let bare = upper.strip_prefix("CKA_").unwrap_or(&upper);
                if bare.starts_with(query) {
                    Some((0, candidate))
                } else if upper.contains(query) {
                    Some((1, candidate))
                } else {
                    None
                }
            })
            .collect();
        ranked.sort_by_key(|(rank, _)| *rank);
        ranked.into_iter().map(|(_, candidate)| candidate).collect()
    }

    // -- layout -----------------------------------------------------------------------

    /// What to draw at this terminal size (it also scrolls the rows to keep the cursor
    /// visible).
    pub(crate) fn frame(&mut self, width: usize, height: usize) -> Frame {
        let clip = width.saturating_sub(1).max(1);
        let max_lines = height.saturating_sub(1).max(1);
        let layout = Layout::new(&self.template, clip);
        let rows = self.rows();

        let head = vec![
            vec![span(self.title.clone(), Tone::Bold)],
            vec![span(layout.header(), Tone::Dim)],
            vec![span("─".repeat(clip), Tone::Dim)],
        ];
        let messages = self.message_lines(clip);
        let footer = self.footer_lines(clip);
        // the add list takes what is left after one table row
        let reserved = head.len() + 2 + messages.len() + footer.len() + 1;
        let (extras, extras_cursor) = self.extras(clip, max_lines.saturating_sub(reserved + 1));

        let fixed = head.len() + 2 + extras.len() + messages.len() + footer.len();
        let room = max_lines.saturating_sub(fixed);
        let (visible, indicator) = if rows <= room {
            (rows, false)
        } else {
            (room.saturating_sub(1).max(1), true)
        };
        if self.cursor < rows {
            if self.cursor < self.top {
                self.top = self.cursor;
            } else if self.cursor >= self.top + visible {
                self.top = self.cursor + 1 - visible;
            }
        }
        self.top = self.top.min(rows.saturating_sub(visible));
        self.page = visible;

        let mut lines = head;
        let mut cursor = None;
        for row in self.top..(self.top + visible).min(rows) {
            let (line, column) = self.row_line(row, &layout);
            if let Some(column) = column {
                cursor = Some((lines.len(), column));
            }
            lines.push(line);
        }
        if indicator {
            let last = (self.top + visible).min(rows);
            lines.push(vec![span(
                format!(
                    "{NO_MARKER}rows {}–{last} of {rows} (↑↓ scroll)",
                    self.top + 1
                ),
                Tone::Dim,
            )]);
        }
        lines.push(self.ok_line(&layout));
        lines.push(vec![span("─".repeat(clip), Tone::Dim)]);
        if let Some((row, column)) = extras_cursor {
            cursor = Some((lines.len() + row, column));
        }
        lines.extend(extras);
        lines.extend(messages);
        lines.extend(footer);
        Frame { lines, cursor }
    }

    /// One attribute row; the column of the input cursor when the row is being edited.
    fn row_line(&self, row: usize, layout: &Layout) -> (Line, Option<usize>) {
        let attr = &self.template.attrs[row];
        let selected = self.cursor == row;
        let tone = if selected {
            Tone::Bold
        } else if attr.locked || !attr.enabled {
            Tone::Dim
        } else {
            Tone::Plain
        };
        let mut line = vec![
            span(if selected { MARKER } else { NO_MARKER }, Tone::Success),
            span(
                format!(
                    "{:>index$}  {:<5}  {}  {:<5}  ",
                    row + 1,
                    glyph(attr),
                    fit(&attr.name, layout.name),
                    attr.kind.as_str(),
                    index = layout.index,
                ),
                tone,
            ),
        ];
        if let Mode::Edit {
            row: editing,
            input,
        } = &self.mode
            && *editing == row
        {
            let (spans, column) = value_input(attr.kind, input, layout.value);
            line.extend(spans);
            return (line, Some(layout.value_column() + column));
        }
        line.push(span(cut(&attr.value.render_value(), layout.value), tone));
        (line, None)
    }

    fn ok_line(&self, layout: &Layout) -> Line {
        let selected = self.cursor == self.rows();
        let indent = " ".repeat(layout.index + 2 + 5 + 2);
        vec![
            span(if selected { MARKER } else { NO_MARKER }, Tone::Success),
            span(indent, Tone::Plain),
            span("[ OK ]", if selected { Tone::Success } else { Tone::Bold }),
        ]
    }

    /// The mode's lines under the table and the cursor among them: (row, column).
    fn extras(&self, clip: usize, room: usize) -> (Vec<Line>, Option<(usize, usize)>) {
        match &self.mode {
            Mode::Browse | Mode::Edit { .. } => (Vec::new(), None),
            Mode::Pick { filter, choice } => {
                let prompt = "add › ";
                let (shown, column) = window(
                    filter.text(),
                    filter.at,
                    clip.saturating_sub(text_cells(prompt)),
                );
                let mut lines = vec![vec![span(prompt, Tone::Bold), span(shown, Tone::Plain)]];
                let cursor = Some((0, text_cells(prompt) + column));
                let candidates = self.candidates(filter.text());
                if candidates.is_empty() {
                    lines.push(vec![span(
                        format!("{NO_MARKER}no attribute matches"),
                        Tone::Dim,
                    )]);
                    return (lines, cursor);
                }
                // all candidates when they fit; else as many as fit next to the "n of m" line
                let budget = room.clamp(1, PICK_ROWS);
                let shown_rows = if candidates.len() <= budget {
                    candidates.len()
                } else {
                    budget.saturating_sub(1).max(1)
                };
                let choice = (*choice).min(candidates.len() - 1);
                let first = (choice + 1).saturating_sub(shown_rows);
                // marker 2, name, 2, kind 5, 2, note: names keep their full width
                let name_cells = candidates
                    .iter()
                    .map(|candidate| text_cells(&candidate.name))
                    .max()
                    .unwrap_or(0)
                    .min(clip.saturating_sub(11))
                    .max(9);
                for (index, candidate) in candidates.iter().enumerate().skip(first).take(shown_rows)
                {
                    let selected = index == choice;
                    let present = self
                        .template
                        .attrs
                        .iter()
                        .position(|attr| attr.name == candidate.name);
                    let note = match present {
                        Some(position) => format!("row {}", position + 1),
                        None if NON_CREATION_ATTRS.contains(&candidate.name.as_str()) => {
                            "set automatically".to_owned()
                        }
                        None if candidate.custom => "custom".to_owned(),
                        None => String::new(),
                    };
                    let tone = if selected {
                        Tone::Bold
                    } else if present.is_some() {
                        Tone::Dim
                    } else {
                        Tone::Plain
                    };
                    lines.push(vec![
                        span(if selected { MARKER } else { NO_MARKER }, Tone::Success),
                        span(
                            format!(
                                "{}  {:<5}  ",
                                fit(&candidate.name, name_cells),
                                candidate.kind.as_str()
                            ),
                            tone,
                        ),
                        span(note, Tone::Dim),
                    ]);
                }
                if candidates.len() > shown_rows {
                    lines.push(vec![span(
                        format!(
                            "{NO_MARKER}{} of {} (↑↓ choose)",
                            choice + 1,
                            candidates.len()
                        ),
                        Tone::Dim,
                    )]);
                }
                (lines, cursor)
            }
            Mode::AddValue { name, kind, input } => {
                let label = format!("{name} = ");
                let (spans, column) =
                    value_input(*kind, input, clip.saturating_sub(text_cells(&label)));
                let mut line = vec![span(label.clone(), Tone::Bold)];
                line.extend(spans);
                (vec![line], Some((0, text_cells(&label) + column)))
            }
            Mode::Command { input } => {
                let prompt = ": ";
                let (shown, column) = window(input.text(), input.at, clip.saturating_sub(2));
                (
                    vec![vec![span(prompt, Tone::Bold), span(shown, Tone::Plain)]],
                    Some((0, 2 + column)),
                )
            }
        }
    }

    fn message_lines(&self, clip: usize) -> Vec<Line> {
        match &self.message {
            None => Vec::new(),
            Some(Message::Note(note)) => vec![vec![span(cut(note, clip), Tone::Plain)]],
            Some(Message::Error(message, hint)) => {
                let mut lines = vec![vec![span(cut(&format!("✗ {message}"), clip), Tone::Error)]];
                if let Some(hint) = hint {
                    lines.push(vec![span(cut(&format!("  hint: {hint}"), clip), Tone::Dim)]);
                }
                lines
            }
        }
    }

    fn footer_lines(&self, clip: usize) -> Vec<Line> {
        let parts: Vec<&str> = match &self.mode {
            Mode::Browse => {
                let full = [
                    "↑↓ move",
                    "space/enter toggle or edit",
                    "- disable",
                    "+ enable",
                    "a add",
                    ": command",
                    "enter on OK accepts",
                    "esc cancel",
                ];
                let rows = wrap_parts(&full, " · ", clip);
                // narrow terminals: the short form (two rows at MIN_COLUMNS)
                let rows = if rows.len() <= 2 {
                    rows
                } else {
                    let short = [
                        "↑↓ move",
                        "space/enter edit",
                        "a add",
                        "-/+ off/on",
                        ": command",
                        "esc cancel",
                    ];
                    wrap_parts(&short, " · ", clip)
                };
                return rows
                    .into_iter()
                    .map(|text| vec![span(text, Tone::Dim)])
                    .collect();
            }
            Mode::Edit { row, .. } => {
                let kind = self
                    .template
                    .attrs
                    .get(*row)
                    .map_or(AttrKind::Str, |attr| attr.kind);
                vec![value_hint(kind), "enter set", "esc keep"]
            }
            Mode::AddValue { kind, .. } => vec![value_hint(*kind), "enter add", "esc back"],
            Mode::Pick { .. } => vec!["type to filter", "↑↓ choose", "enter add", "esc back"],
            Mode::Command { .. } => {
                let mut lines: Vec<Line> =
                    wrap_parts(&HELP.split(" | ").collect::<Vec<_>>(), " | ", clip)
                        .into_iter()
                        .map(|text| vec![span(text, Tone::Dim)])
                        .collect();
                lines.push(vec![span("enter run · esc back", Tone::Dim)]);
                return lines;
            }
        };
        wrap_parts(&parts, " · ", clip)
            .into_iter()
            .map(|text| vec![span(text, Tone::Dim)])
            .collect()
    }
}

/// Column widths of the table at one terminal width.
struct Layout {
    /// Digits of the largest row number.
    index: usize,
    name: usize,
    value: usize,
}

impl Layout {
    /// marker 2, index, 2, state 5, 2, name, 2, kind 5, 2, value
    const FIXED: usize = 2 + 2 + 5 + 2 + 2 + 5 + 2;

    fn new(template: &KeyTemplate, clip: usize) -> Self {
        let index = template.attrs.len().max(1).to_string().len();
        let longest = template
            .attrs
            .iter()
            .map(|attr| text_cells(&attr.name))
            .max()
            .unwrap_or(0)
            .max("attribute".len());
        let room = clip.saturating_sub(Self::FIXED + index);
        let name = longest
            .min(room.saturating_sub(VALUE_MIN))
            .max("attribute".len());
        let value = room.saturating_sub(name).max(1);
        Self { index, name, value }
    }

    fn header(&self) -> String {
        format!(
            "{NO_MARKER}{:>index$}  state  {}  kind   value",
            "#",
            fit("attribute", self.name),
            index = self.index,
        )
    }

    /// Cells before the value column.
    fn value_column(&self) -> usize {
        Self::FIXED + self.index + self.name
    }
}

fn span(text: impl Into<String>, tone: Tone) -> Span {
    Span {
        text: text.into(),
        tone,
    }
}

/// `text` cut to `cells` (an ellipsis marks the cut), not padded.
fn cut(text: &str, cells: usize) -> String {
    if text_cells(text) <= cells {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let width = char_cells(c);
        if used + width + 1 > cells {
            break;
        }
        used += width;
        out.push(c);
    }
    out.push('…');
    out
}

/// `text` cut or padded to exactly `cells`.
fn fit(text: &str, cells: usize) -> String {
    let mut out = cut(text, cells);
    let used = text_cells(&out);
    out.push_str(&" ".repeat(cells.saturating_sub(used)));
    out
}

/// The part of an input shown in `cells` cells with the cursor visible: (text, cursor
/// column). Text cut off at the front is marked with an ellipsis.
fn window(text: &str, at: usize, cells: usize) -> (String, usize) {
    let cells = cells.max(2);
    let before = text.get(..at).unwrap_or("");
    let after = text.get(at..).unwrap_or("");
    let before_cells = text_cells(before);
    let (mut shown, column) = if before_cells < cells {
        (before.to_owned(), before_cells)
    } else {
        let mut tail = Vec::new();
        let mut used = 1; // the ellipsis
        for c in before.chars().rev() {
            let width = char_cells(c);
            if used + width + 1 > cells {
                break;
            }
            used += width;
            tail.push(c);
        }
        tail.reverse();
        let mut shown = String::from("…");
        shown.extend(tail);
        (shown, used)
    };
    let mut used = column;
    for c in after.chars() {
        let width = char_cells(c);
        if used + width > cells {
            break;
        }
        used += width;
        shown.push(c);
    }
    (shown, column)
}

/// A value input as spans in `cells` cells, and the cursor column among them. Bytes show a
/// fixed `0x` before the digits and the byte count after them; text shows its UTF-8 length.
fn value_input(kind: AttrKind, input: &Input, cells: usize) -> (Vec<Span>, usize) {
    let prefix = if kind == AttrKind::Bytes { "0x" } else { "" };
    let digits = input.text().len();
    let (status, tone) = match kind {
        AttrKind::Bytes if digits % 2 == 1 => {
            ("  odd number of hex digits".to_owned(), Tone::Error)
        }
        AttrKind::Bytes => (format!("  {}", byte_count(digits / 2)), Tone::Dim),
        AttrKind::Str => (format!("  {}", byte_count(input.text().len())), Tone::Dim),
        _ => (String::new(), Tone::Dim),
    };
    let mut room = cells.saturating_sub(prefix.len());
    // the status goes first when space runs out
    let status = if room >= text_cells(&status) + 8 {
        room -= text_cells(&status);
        status
    } else {
        String::new()
    };
    let (shown, column) = window(input.text(), input.at, room);
    let spans = vec![
        span(prefix, Tone::Dim),
        span(shown, Tone::Plain),
        span(status, tone),
    ];
    (spans, prefix.len() + column)
}

fn byte_count(n: usize) -> String {
    if n == 1 {
        "1 byte".to_owned()
    } else {
        format!("{n} bytes")
    }
}

fn value_hint(kind: AttrKind) -> &'static str {
    match kind {
        AttrKind::Bytes => "hex digits (a pasted 0x, spaces and ':' are dropped)",
        AttrKind::Ulong => "decimal or 0x… hex",
        AttrKind::Str | AttrKind::Bool => "text",
    }
}

/// The text an input starts with when a row's value is edited (bytes without their `0x`).
fn initial_text(value: &AttrValue) -> String {
    let text = value.render_value();
    match value {
        AttrValue::Bytes(_) => text.strip_prefix("0x").unwrap_or(&text).to_owned(),
        _ => text,
    }
}

/// The line-editor value text of an input (bytes get their `0x` back).
fn submitted(kind: AttrKind, text: &str) -> String {
    if kind == AttrKind::Bytes {
        format!("0x{text}")
    } else {
        text.to_owned()
    }
}

/// Characters a value input takes as typed.
fn accepts(kind: AttrKind, c: char) -> bool {
    match kind {
        AttrKind::Bytes => c.is_ascii_hexdigit(),
        AttrKind::Ulong => c.is_ascii_hexdigit() || c == 'x' || c == 'X',
        AttrKind::Str => !c.is_control(),
        AttrKind::Bool => false,
    }
}

/// A paste into a value input, cleaned for the kind: bytes drop whitespace, ':' and one
/// leading `0x`; integers drop surrounding whitespace; text drops control characters
/// (line breaks included). None when the rest is not acceptable.
fn clean_paste(kind: AttrKind, text: &str) -> Option<String> {
    match kind {
        AttrKind::Bytes => {
            let compact: String = text
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ':')
                .collect();
            let digits = compact
                .strip_prefix("0x")
                .or_else(|| compact.strip_prefix("0X"))
                .unwrap_or(&compact);
            digits
                .chars()
                .all(|c| c.is_ascii_hexdigit())
                .then(|| digits.to_owned())
        }
        AttrKind::Ulong => {
            let trimmed = text.trim();
            trimmed
                .chars()
                .all(|c| accepts(kind, c))
                .then(|| trimmed.to_owned())
        }
        AttrKind::Str => Some(text.chars().filter(|c| !c.is_control()).collect()),
        AttrKind::Bool => None,
    }
}

/// A paste into a one-line input (filter, `:` line): control characters dropped.
fn one_line(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// Typing into a value input: editing keys, the characters the kind accepts, cleaned
/// pastes. Returns the message for a refused character or paste.
fn type_into(input: &mut Input, name: &str, kind: AttrKind, key: Key) -> Option<Message> {
    match key {
        Key::Char(c) if accepts(kind, c) => {
            input.insert(c.encode_utf8(&mut [0; 4]));
            None
        }
        Key::Char(_) => Some(refused(name, kind)),
        Key::Paste(text) => match clean_paste(kind, &text) {
            Some(clean) => {
                input.insert(&clean);
                None
            }
            None => Some(refused(name, kind)),
        },
        other => {
            input.edit(&other);
            None
        }
    }
}

fn refused(name: &str, kind: AttrKind) -> Message {
    let what = match kind {
        AttrKind::Bytes => "hex digits (0-9, a-f)",
        AttrKind::Ulong => "decimal digits or 0x… hex",
        AttrKind::Str | AttrKind::Bool => "text",
    };
    Message::Error(format!("{name} takes {what}"), None)
}

/// `parts` joined with `separator` in rows of at most `cells` cells (a part wider than a
/// row gets a row of its own; the session clips it).
fn wrap_parts(parts: &[&str], separator: &str, cells: usize) -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    let mut current = String::new();
    for part in parts {
        if current.is_empty() {
            current.push_str(part);
        } else if text_cells(&current) + text_cells(separator) + text_cells(part) <= cells {
            current.push_str(separator);
            current.push_str(part);
        } else {
            rows.push(std::mem::take(&mut current));
            current.push_str(part);
        }
    }
    if !current.is_empty() {
        rows.push(current);
    }
    rows
}
