//! Renderer tests (spec §4.9.2; c2 `tests/unit/console/test_render.py` renderer cases and the
//! R1 cases of `test_l13_hardening.py`, moved to R1 by spec §4.1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr
)]

#[path = "support/rich_panels.rs"]
mod rich_panels;

use r2_core::error::ConsoleError;
use r2_core::io::{PanelData, Renderable, Span, TableData, Tone, caret, error_panel, hex, table};
use r2_core::render::{RenderConfig, render, render_plain};

fn at(width: usize) -> RenderConfig {
    RenderConfig {
        width,
        hex_group: 2,
        hex_width: 32,
    }
}

#[test]
fn error_panel_matches_rich_vectors() {
    let mut failures = Vec::new();
    for &(message, hint, width, expected) in rich_panels::ERROR_PANELS {
        let got = render_plain(&error_panel(message, hint), &at(width));
        if got != expected {
            failures.push(format!(
                "message {message:?} hint {hint:?} width {width}\n--- rich\n{expected}\n--- r2\n{got}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn hex_panel_matches_rich_vectors() {
    let mut failures = Vec::new();
    for &(data, group, hex_width, title, width, expected) in rich_panels::HEX_PANELS {
        let cfg = RenderConfig {
            width,
            hex_group: group,
            hex_width,
        };
        let got = render_plain(&hex(data, title), &cfg);
        if got != expected {
            failures.push(format!(
                "data {} group {group} hex_width {hex_width} title {title:?} width {width}\n--- rich\n{expected}\n--- r2\n{got}",
                data.len()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// rich `Panel(Text(body), title=Text(t), subtitle=Text(s), expand=False)`: control codes
/// stripped, an empty (or all-control) title/subtitle is none, a content width below 1
/// renders no content line.
#[test]
fn generic_panel_matches_rich_vectors() {
    let mut failures = Vec::new();
    for &(title, subtitle, body, width, expected) in rich_panels::GENERIC_PANELS {
        let panel = Renderable::Panel(PanelData {
            title: title.map(str::to_owned),
            subtitle: subtitle.map(str::to_owned),
            border: Tone::Plain,
            body: body.map_or_else(Vec::new, |body| {
                body.split('\n')
                    .map(|line| {
                        vec![Span {
                            text: line.to_owned(),
                            tone: Tone::Plain,
                        }]
                    })
                    .collect()
            }),
        });
        let got = render_plain(&panel, &at(width));
        if got != expected {
            failures.push(format!(
                "title {title:?} subtitle {subtitle:?} body {body:?} width {width}\n--- rich\n{expected}\n--- r2\n{got}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// c2 prints a str with `console.print(s, markup=False)`: rich's Text layout (control codes
/// stripped, tabs expanded, words wrapped and long words folded at the console width).
#[test]
fn text_matches_rich_vectors() {
    let mut failures = Vec::new();
    for &(text, width, expected) in rich_panels::TEXTS {
        let got = render_plain(&Renderable::from(text), &at(width));
        if got != expected {
            failures.push(format!(
                "text {text:?} width {width}\n--- rich\n{expected:?}\n--- r2\n{got:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// The caret echo laid out by rich (row and caret line wrap independently), with r2's caret
/// column (§11 D14: display width of the tab-expanded, control-stripped prefix).
#[test]
fn caret_matches_rich_layout_vectors() {
    let mut failures = Vec::new();
    for &(line, pos, width, expected) in rich_panels::CARETS {
        let got = render_plain(&caret(line, pos), &at(width));
        if got != expected {
            failures.push(format!(
                "line {line:?} pos {pos} width {width}\n--- rich\n{expected:?}\n--- r2\n{got:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// rich 15 `cell_len` (its own Unicode 17 table, ZWJ/VS16 graphemes, C0/C1 = 0), observed
/// through the caret column of a caret placed after the whole text.
#[test]
fn cell_widths_match_rich_cell_len() {
    let mut failures = Vec::new();
    for &(text, expected) in rich_panels::CELL_LENS {
        let plain = render_plain(&caret(text, text.len()), &at(200));
        let caret_line = plain.rsplit('\n').next().unwrap();
        let got = caret_line.chars().count() - 1;
        if got != expected {
            let points: Vec<String> = text
                .chars()
                .map(|c| format!("U+{:04X}", u32::from(c)))
                .collect();
            failures.push(format!("{points:?}: rich {expected}, r2 {got}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// c2 `rendered()`: the tests print through a width-100 console.
fn rendered(renderable: &Renderable) -> String {
    render_plain(renderable, &at(100))
}

fn err_panel(err: &ConsoleError) -> Renderable {
    error_panel(&err.message, err.hint.as_deref())
}

#[test]
fn test_error_panel_message_and_hint() {
    let text = rendered(&err_panel(
        &ConsoleError::generic("boom happened").with_hint("try again"),
    ));
    assert!(text.contains("error"));
    assert!(text.contains("boom happened"));
    assert!(text.contains("hint: try again"));
}

#[test]
fn test_error_panel_without_hint() {
    let text = rendered(&err_panel(&ConsoleError::generic("just broken")));
    assert!(text.contains("just broken"));
    assert!(!text.contains("hint:"));
    // c2 `if err.hint:` — an empty hint renders no hint line either.
    assert_eq!(rendered(&error_panel("just broken", Some(""))), text);
}

#[test]
fn test_caret_text_single_line() {
    assert_eq!(
        render_plain(&caret("load mem xx", 9), &at(100)),
        "load mem xx\n         ^"
    );
}

#[test]
fn test_caret_text_lands_on_the_right_physical_row() {
    let line = "load \"a\nb\" trailing";
    let err = ConsoleError::parse("x", line, line.find("trailing").unwrap());
    let (line, pos) = err.parse_position().unwrap();
    assert_eq!(
        render_plain(&caret(line, pos), &at(100)),
        "b\" trailing\n   ^"
    );
}

#[test]
fn test_caret_text_clamps_out_of_range_pos() {
    assert_eq!(render_plain(&caret("ab", 99), &at(100)), "ab\n  ^");
    // c2's negative position (`pos=-5`) is unrepresentable (usize); 0 is the lower clamp.
    assert_eq!(render_plain(&caret("ab", 0), &at(100)), "ab\n^");
}

/// §11 D14: the caret column is the display width of the row prefix before the BYTE offset;
/// a position inside a multi-byte character snaps back to its start.
#[test]
fn caret_column_is_display_width() {
    let line = "key info ключ 日本 x";
    let pos = line.find('x').unwrap();
    let plain = render_plain(&caret(line, pos), &at(100));
    assert_eq!(plain, format!("{line}\n{}^", " ".repeat(19)));
    let inside = line.find('本').unwrap() + 1;
    let plain = render_plain(&caret(line, inside), &at(100));
    assert_eq!(plain, format!("{line}\n{}^", " ".repeat(16)));
    // A position on the '\n' itself belongs to the row it ends.
    assert_eq!(render_plain(&caret("ab\ncd", 2), &at(100)), "ab\n  ^");
    assert_eq!(render_plain(&caret("ab\ncd", 3), &at(100)), "cd\n^");
    assert_eq!(render_plain(&caret("", 0), &at(100)), "\n^");
    // The row is laid out like rich's Text (tabs expanded to 8, control codes stripped) and
    // the caret column is measured on that layout: under the character on screen (c2 put
    // it at the character index, §11 D14).
    assert_eq!(
        render_plain(&caret("a\tb:#zz", 2), &at(100)),
        "a       b:#zz\n        ^"
    );
    assert_eq!(
        render_plain(&caret("load\tmem x", 9), &at(100)),
        "load    mem x\n            ^"
    );
    assert_eq!(
        render_plain(&caret("abc\rdef", 5), &at(100)),
        "abcdef\n    ^"
    );
    // A combining mark is zero-width: the caret stays under the following 'x'.
    let combining = "key info e\u{301}x";
    assert_eq!(
        render_plain(&caret(combining, combining.len() - 1), &at(100)),
        format!("{combining}\n{}^", " ".repeat(10))
    );
    // The caret is bold red (Tone::Error).
    let Renderable::Styled(lines) = caret("ab", 1) else {
        panic!("caret is a Styled renderable");
    };
    assert_eq!(lines[1].last().unwrap().tone, Tone::Error);
}

#[test]
fn test_hex_panel_groups_and_length() {
    let cfg = RenderConfig {
        width: 100,
        hex_group: 2,
        hex_width: 4,
    };
    let text = render_plain(&hex(&(0..8).collect::<Vec<u8>>(), None), &cfg);
    assert!(text.contains("0001 0203"));
    assert!(text.contains("0405 0607"));
    assert!(text.contains("8 bytes"));
}

#[test]
fn test_hex_panel_empty() {
    let text = rendered(&hex(b"", None));
    assert!(text.contains("(empty — 0 bytes)"));
    assert!(!text.contains("0 bytes─"));
}

#[test]
fn test_make_table_cells_are_stringified() {
    let t = table(
        Some("things"),
        &["name", "n"],
        vec![
            vec!["aes".into(), 256.to_string()],
            vec!["rsa".into(), "None".into()],
        ],
    );
    let text = rendered(&t);
    assert!(text.contains("things"));
    assert!(text.contains("aes"));
    assert!(text.contains("256"));
    assert!(text.contains("None"));
}

/// l13: cells are data, never markup (rich ate "[x]" without Text wrapping).
#[test]
fn test_make_table_cells_render_verbatim() {
    let t = table(
        None,
        &["state", "attribute"],
        vec![
            vec!["[x]".into(), "CKA_TOKEN".into()],
            vec!["[ ]".into(), "CKA_WRAP".into()],
        ],
    );
    let text = rendered(&t);
    assert!(text.contains("[x]")); // the checked editor glyph must be visible (§5.12)
    assert!(text.contains("[ ]"));
}

/// l13: a hex panel title renders verbatim (no markup).
#[test]
fn test_hex_panel_title_renders_verbatim() {
    let panel = hex(&[0x01, 0x02], Some("ciphertext — [#custom]"));
    assert!(rendered(&panel).contains("[#custom]"));
}

/// D1 table layout: a header rule (`─`, spanning the computed width), rich's column gap
/// (padding + one blank vertical line), no edge spaces or blank edge rows, a centered
/// title line; the header cells are bold, the title italic.
#[test]
fn table_layout_is_simple_head() {
    let t = table(
        Some("things"),
        &["name", "n"],
        vec![
            vec!["aes".into(), "256".into()],
            vec!["rsa".into(), "None".into()],
        ],
    );
    assert_eq!(
        rendered(&t),
        "   things\n name   n\n─────────────\n aes    256\n rsa    None"
    );
    let styled = render(&t, &at(100));
    assert!(styled.contains("\u{1b}[1m name \u{1b}[0m"), "{styled:?}");
    assert!(styled.contains("\u{1b}[1m n\u{1b}[0m\n"), "{styled:?}");
    assert!(styled.contains("\u{1b}[3mthings\u{1b}[0m"), "{styled:?}");
    // No title, no rows: header and rule only.
    let empty = table(None, &["ref", "class"], vec![]);
    assert_eq!(rendered(&empty), " ref   class\n─────────────");
    // A title wider than the table wraps at the table width, each line centered.
    let narrow = table(Some("long titles"), &["name"], vec![vec!["aes".into()]]);
    assert_eq!(rendered(&narrow), " long\ntitles\n name\n──────\n aes");
    // … and words longer than the table fold (rich `overflow="fold"`).
    let tiny = table(Some("a long title"), &["a"], vec![vec!["1".into()]]);
    assert_eq!(rendered(&tiny), " a\nlon\n g\ntit\nle\n a\n───\n 1");
    // rich `if self.title:` — an empty (or all-control-code) title is no title; a table
    // with no columns renders nothing, title included.
    let untitled = table(None, &["a"], vec![vec!["x".into()]]);
    for title in ["", "\r", "\u{7}\u{8}"] {
        let t = table(Some(title), &["a"], vec![vec!["x".into()]]);
        assert_eq!(rendered(&t), rendered(&untitled), "{title:?}");
    }
    assert_eq!(rendered(&table(Some("t"), &[], vec![])), "");
    // Cells, headers and title hold rich's Text: BEL/BS/VT/FF/CR stripped (a CR would
    // otherwise move the terminal cursor and overwrite the row).
    let t = table(
        Some("ti\rtle"),
        &["re\u{7}f", "class"],
        vec![vec![
            "softhsm:label\r".into(),
            "sec\u{8}ret\u{b}\u{c}".into(),
        ]],
    );
    let plain = rendered(&t);
    assert_eq!(
        plain,
        "         title\n ref             class\n────────────────────────\n softhsm:label   secret"
    );
    // The width caps the table (Dynamic arrangement wraps cell content).
    let wide = table(None, &["text"], vec![vec!["word ".repeat(30)]]);
    let lines = render_plain(&wide, &at(40));
    assert!(
        lines.lines().all(|line| line.chars().count() <= 40),
        "{lines}"
    );
    assert!(lines.lines().count() > 3);
}

/// Text and Styled are laid out like rich's Text (§4.9.2): never markup, BEL/BS/VT/FF/CR
/// stripped, tabs expanded to 8 columns, wrapped at spaces and folded at the width (c2
/// printed every str through `console.print`).
#[test]
fn text_and_styled_render_like_rich_text() {
    let long = "x".repeat(300);
    assert_eq!(
        render_plain(&Renderable::Text(long.clone()), &at(80)),
        [&long[..80], &long[80..160], &long[160..240], &long[240..]].join("\n")
    );
    assert_eq!(
        render_plain(&Renderable::Text(long.clone()), &RenderConfig::CAPTURE),
        [&long[..200], &long[200..]].join("\n")
    );
    assert_eq!(
        render_plain(&Renderable::from("a [b] c\n  d"), &at(80)),
        "a [b] c\n  d"
    );
    assert_eq!(
        render_plain(&Renderable::from("a\tb"), &at(80)),
        "a       b"
    );
    assert_eq!(
        render_plain(&Renderable::from("one\rtwo\u{7}\u{8}\u{b}\u{c}"), &at(80)),
        "onetwo"
    );
    assert_eq!(
        render_plain(&Renderable::from("usage: one two three"), &at(10)),
        "usage: one\ntwo three"
    );
    // §11 D23: emoji shortcodes are data, never replaced (c2 printed "generated mem❌ok:y").
    assert_eq!(
        render(
            &Renderable::from("generated mem:x:ok:y (256-bit aes)"),
            &at(80)
        ),
        "generated mem:x:ok:y (256-bit aes)"
    );
    // ESC is not one of rich's stripped control codes (the `clear` sequence passes).
    assert_eq!(
        render(&Renderable::from("\u{1b}[2J\u{1b}[H"), &at(80)),
        "\u{1b}[2J\u{1b}[H"
    );
    let styled = Renderable::Styled(vec![
        vec![
            Span {
                text: "load ".into(),
                tone: Tone::Plain,
            },
            Span {
                text: "mem".into(),
                tone: Tone::Bold,
            },
        ],
        vec![Span {
            text: "^".into(),
            tone: Tone::Error,
        }],
    ]);
    assert_eq!(render_plain(&styled, &at(80)), "load mem\n^");
    let ansi = render(&styled, &at(80));
    assert_eq!(
        ansi,
        "load \u{1b}[1mmem\u{1b}[0m\n\u{1b}[1m\u{1b}[31m^\u{1b}[0m"
    );
    // A styled line folds like Text, keeping each character's tone.
    // (rich: 'loa\nd \nmem\n^' — the fold keeps "d " whole, rstrip_end only trims beyond
    // the width.)
    assert_eq!(render_plain(&styled, &at(3)), "loa\nd \nmem\n^");
    assert_eq!(
        render(&styled, &at(3)),
        "loa\nd \n\u{1b}[1mmem\u{1b}[0m\n\u{1b}[1m\u{1b}[31m^\u{1b}[0m"
    );
}

/// render() always styles: the error panel border is red, the message bold red, the hint
/// dim; render_plain strips every escape sequence.
#[test]
fn render_emits_ansi_and_render_plain_strips_it() {
    let panel = error_panel("boom", Some("try"));
    let ansi = render(&panel, &at(80));
    assert!(ansi.contains("\u{1b}[31m╭─\u{1b}[0m"), "{ansi:?}");
    assert!(ansi.contains("\u{1b}[1m\u{1b}[31mboom"), "{ansi:?}");
    assert!(ansi.contains("\u{1b}[2mhint: try"), "{ansi:?}");
    let plain = render_plain(&panel, &at(80));
    assert!(!plain.contains('\u{1b}'));
    assert_eq!(anstream::adapter::strip_str(&ansi).to_string(), plain);
    assert_eq!(
        plain,
        "╭─ error ───╮\n│ boom      │\n│ hint: try │\n╰───────────╯"
    );
}

/// The general Panel: title left in the top border, subtitle right in the bottom border.
#[test]
fn generic_panel_with_title_and_subtitle() {
    let panel = Renderable::Panel(PanelData {
        title: Some("t".into()),
        subtitle: Some("sub".into()),
        border: Tone::Plain,
        body: vec![
            vec![Span {
                text: "first line".into(),
                tone: Tone::Plain,
            }],
            vec![Span {
                text: "two\nrows".into(),
                tone: Tone::Bold,
            }],
        ],
    });
    assert_eq!(
        render_plain(&panel, &at(80)),
        "╭─ t ────────╮\n│ first line │\n│ two        │\n│ rows       │\n╰────── sub ─╯"
    );
    let no_title = Renderable::Panel(PanelData {
        title: None,
        subtitle: None,
        border: Tone::Danger,
        body: vec![],
    });
    // rich: no title and a content width of 0 → no content line at all.
    assert_eq!(render_plain(&no_title, &at(80)), "╭──╮\n╰──╯");
    // With a title the (empty) content gets its one blank line.
    let titled_empty = Renderable::Panel(PanelData {
        title: Some("t".into()),
        subtitle: None,
        border: Tone::Plain,
        body: vec![],
    });
    assert_eq!(
        render_plain(&titled_empty, &at(80)),
        "╭─ t ─╮\n│     │\n╰─────╯"
    );
}

#[test]
fn renderable_from_strings_is_text() {
    assert_eq!(Renderable::from("x"), Renderable::Text("x".into()));
    assert_eq!(
        Renderable::from("y".to_owned()),
        Renderable::Text("y".into())
    );
    let t = table(Some("t"), &["a"], vec![vec!["1".into()]]);
    assert_eq!(
        t,
        Renderable::Table(TableData {
            title: Some("t".into()),
            columns: vec!["a".into()],
            rows: vec![vec!["1".into()]],
        })
    );
    assert_eq!(
        hex(&[1], Some("h")),
        Renderable::Hex {
            data: vec![1],
            title: Some("h".into())
        }
    );
    assert_eq!(
        RenderConfig::CAPTURE,
        RenderConfig {
            width: 200,
            hex_group: 2,
            hex_width: 32
        }
    );
}

/// Degenerate console widths never panic (the live width comes from the terminal, §4.9.2).
#[test]
fn tiny_widths_never_panic() {
    let renderables = [
        error_panel("a fairly long message with words", Some("and a hint")),
        error_panel("", None),
        error_panel("日本語のエラー", Some("\ttabbed")),
        hex(&(0..40).collect::<Vec<u8>>(), Some("title")),
        hex(&[], None),
        table(
            Some("t"),
            &["a", "b"],
            vec![vec!["x".into(), "y".repeat(30)]],
        ),
        table(None, &[], vec![]),
        caret("abc", 2),
    ];
    for width in 0..14 {
        for renderable in &renderables {
            for (group, hex_width) in [(0, 0), (2, 32), (1, 1)] {
                let cfg = RenderConfig {
                    width,
                    hex_group: group,
                    hex_width,
                };
                let _ = render(renderable, &cfg);
            }
        }
    }
}
