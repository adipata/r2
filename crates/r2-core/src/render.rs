// The ConsoleIo renderer (spec §4.9.2; owner R1): Renderable → text. Panels (error panel,
// hex dump) are an own port of rich 15's Panel/Text layout and equal rich's output; tables
// are comfy-table with a rich `box.SIMPLE_HEAD` look (§11 D1).
use anstyle::{AnsiColor, Style};
use comfy_table::{
    Attribute, Cell, ContentArrangement, LineStyle, Table as ComfyTable, TableStyle,
};
use unicode_width::UnicodeWidthChar;

use crate::codec::format_hex;
use crate::io::{Line, PanelData, Renderable, Span, TableData, Tone};
use crate::text::{is_py_space, py_splitlines};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenderConfig {
    pub width: usize,
    pub hex_group: usize,
    pub hex_width: usize,
}
impl RenderConfig {
    /// c2's test rendering console (rich, width 200) — used by ScriptedIo.
    pub const CAPTURE: RenderConfig = RenderConfig {
        width: 200,
        hex_group: 2,
        hex_width: 32,
    };
}
/// ALWAYS emits ANSI SGR styling (the Sink decides whether it reaches the terminal). Lines
/// joined with "\n", no trailing newline.
pub fn render(renderable: &Renderable, cfg: &RenderConfig) -> String {
    match renderable {
        Renderable::Text(text) => text.clone(),
        Renderable::Styled(lines) => lines
            .iter()
            .map(|line| styled(&line_cells(line)))
            .collect::<Vec<_>>()
            .join("\n"),
        Renderable::Table(data) => render_table(data, cfg),
        Renderable::Hex { data, title } => {
            render_panel(&hex_panel(data, title.as_deref(), cfg), cfg.width)
        }
        Renderable::Panel(panel) => render_panel(panel, cfg.width),
    }
}
/// `anstream::adapter::strip_str(&render(r, cfg))` — tests, ScriptedIo, snapshots.
pub fn render_plain(renderable: &Renderable, cfg: &RenderConfig) -> String {
    anstream::adapter::strip_str(&render(renderable, cfg)).to_string()
}

// ---- cells ------------------------------------------------------------------------------

/// One character with its tone (the unit rich's Text/Segment model works in).
type Cells = Vec<(char, Tone)>;

/// rich `get_character_cell_size`: C0/C1 controls are zero-width, else the Unicode East
/// Asian width (unicode-width; rich's own table may differ for exotic code points).
fn char_width(c: char) -> usize {
    let code = u32::from(c);
    if (code != 0 && code < 0x20) || (0x7f..0xa0).contains(&code) {
        return 0;
    }
    c.width().unwrap_or(0)
}

/// Display width in terminal columns (rich `cell_len`).
pub(crate) fn display_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

fn cells_width(cells: &[(char, Tone)]) -> usize {
    cells.iter().map(|&(c, _)| char_width(c)).sum()
}

fn to_cells(text: &str, tone: Tone) -> Cells {
    text.chars().map(|c| (c, tone)).collect()
}

fn line_cells(line: &Line) -> Cells {
    line.iter()
        .flat_map(|span| span.text.chars().map(move |c| (c, span.tone)))
        .collect()
}

fn tone_style(tone: Tone) -> Style {
    match tone {
        Tone::Plain => Style::new(),
        Tone::Bold => Style::new().bold(),
        Tone::Dim => Style::new().dimmed(),
        Tone::Italic => Style::new().italic(),
        Tone::Error => Style::new().bold().fg_color(Some(AnsiColor::Red.into())),
        Tone::Danger => Style::new().fg_color(Some(AnsiColor::Red.into())),
    }
}

/// SGR-styled text of one line: each run of equal tone wrapped in its style + reset.
fn styled(cells: &[(char, Tone)]) -> String {
    let mut out = String::new();
    let mut index = 0;
    while index < cells.len() {
        let tone = cells[index].1;
        let run_end = cells[index..]
            .iter()
            .position(|&(_, t)| t != tone)
            .map_or(cells.len(), |offset| index + offset);
        let text: String = cells[index..run_end].iter().map(|&(c, _)| c).collect();
        let style = tone_style(tone);
        if style.is_plain() {
            out.push_str(&text);
        } else {
            out.push_str(&format!("{}{text}{}", style.render(), style.render_reset()));
        }
        index = run_end;
    }
    out
}

// ---- rich Text layout (wrap, truncate, tabs) ---------------------------------------------

/// rich `Text.expand_tabs(8)` for one line (no '\n' inside).
fn expand_tabs(line: &[(char, Tone)]) -> Cells {
    if !line.iter().any(|&(c, _)| c == '\t') {
        return line.to_vec();
    }
    let mut out = Cells::new();
    let mut position = 0;
    for &(c, tone) in line {
        if c == '\t' {
            out.push((' ', tone));
            position += 1;
            let remainder = position % 8;
            if remainder != 0 {
                for _ in 0..8 - remainder {
                    out.push((' ', tone));
                }
                position += 8 - remainder;
            }
        } else {
            out.push((c, tone));
            position += char_width(c);
        }
    }
    out
}

/// rich `set_cell_size` (crop only): the prefix of exactly `total` cells; a double-width
/// character straddling the edge becomes a space.
fn crop_cells(cells: &[(char, Tone)], total: usize) -> Cells {
    let mut out = Cells::new();
    let mut size = 0;
    for &(c, tone) in cells {
        let width = char_width(c);
        if size + width > total {
            if size < total {
                out.push((' ', tone));
            }
            break;
        }
        out.push((c, tone));
        size += width;
    }
    out
}

/// rich `Text.truncate(width)` (overflow fold, no pad): crop only when too wide.
fn truncate(cells: Cells, width: usize) -> Cells {
    if cells_width(&cells) > width {
        crop_cells(&cells, width)
    } else {
        cells
    }
}

/// rich `_wrap.words`: `\s*\S+\s*` matches from position 0 on, as (start, end) char ranges.
fn words(chars: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut position = 0;
    loop {
        let mut index = position;
        while index < chars.len() && is_py_space(chars[index]) {
            index += 1;
        }
        if index == chars.len() {
            return out;
        }
        while index < chars.len() && !is_py_space(chars[index]) {
            index += 1;
        }
        while index < chars.len() && is_py_space(chars[index]) {
            index += 1;
        }
        out.push((position, index));
        position = index;
    }
}

/// rich `chop_cells` (per char): pieces of at most `width` cells.
fn chop_cells(chars: &[char], width: usize) -> Vec<&[char]> {
    let mut pieces = Vec::new();
    let mut line_size = 0;
    let mut line_offset = 0;
    for (index, &c) in chars.iter().enumerate() {
        let size = char_width(c);
        if line_size + size > width {
            pieces.push(&chars[line_offset..index]);
            line_offset = index;
            line_size = 0;
        }
        line_size += size;
    }
    if line_size > 0 {
        pieces.push(&chars[line_offset..]);
    }
    pieces
}

/// rich `_wrap.divide_line(text, width, fold=True)`: char offsets to break the line at.
fn divide_line(chars: &[char], width: usize) -> Vec<usize> {
    let width_of = |slice: &[char]| slice.iter().map(|&c| char_width(c)).sum::<usize>();
    let mut breaks = Vec::new();
    let mut cell_offset = 0usize;
    for (start, end) in words(chars) {
        let word = &chars[start..end];
        let mut trimmed_end = word.len();
        while trimmed_end > 0 && is_py_space(word[trimmed_end - 1]) {
            trimmed_end -= 1;
        }
        let word_length = width_of(&word[..trimmed_end]);
        if cell_offset + word_length <= width {
            cell_offset += width_of(word);
        } else if word_length > width {
            let pieces = chop_cells(word, width);
            let mut piece_start = start;
            for (index, piece) in pieces.iter().enumerate() {
                if piece_start != 0 {
                    breaks.push(piece_start);
                }
                if index + 1 == pieces.len() {
                    cell_offset = width_of(piece);
                } else {
                    piece_start += piece.len();
                }
            }
        } else if cell_offset != 0 && start != 0 {
            breaks.push(start);
            cell_offset = width_of(word);
        }
    }
    breaks
}

/// rich `Text.rstrip_end(size)`: drop trailing whitespace beyond `size` CHARACTERS.
fn rstrip_end(mut line: Cells, size: usize) -> Cells {
    if line.len() > size {
        let excess = line.len() - size;
        let whitespace = line
            .iter()
            .rev()
            .take_while(|&&(c, _)| is_py_space(c))
            .count();
        line.truncate(line.len() - whitespace.min(excess));
    }
    line
}

/// rich `Text.wrap(console, width)` (justify "default", overflow "fold") for text that
/// holds no '\n'.
fn wrap_line(line: &[(char, Tone)], width: usize) -> Vec<Cells> {
    let line = expand_tabs(line);
    let chars: Vec<char> = line.iter().map(|&(c, _)| c).collect();
    let mut offsets = divide_line(&chars, width);
    offsets.push(line.len());
    let mut out = Vec::with_capacity(offsets.len());
    let mut start = 0;
    for end in offsets {
        let piece = line[start..end].to_vec();
        out.push(truncate(rstrip_end(piece, width), width));
        start = end;
    }
    out
}

/// rich `Text.split("\n", allow_blank=True)` over styled lines, then `wrap` each.
fn wrap_lines(lines: &[Cells], width: usize) -> Vec<Cells> {
    let mut out = Vec::new();
    for line in lines {
        for logical in line.split(|&(c, _)| c == '\n') {
            out.extend(wrap_line(logical, width));
        }
    }
    out
}

// ---- panels -------------------------------------------------------------------------------

/// The hex dump panel of c2 `render.hex_panel` (§4.9.2 "Hex").
fn hex_panel(data: &[u8], title: Option<&str>, cfg: &RenderConfig) -> PanelData {
    let (body, subtitle) = if data.is_empty() {
        ("(empty — 0 bytes)".to_owned(), None)
    } else {
        (
            format_hex(data, cfg.hex_group, cfg.hex_width),
            Some(format!("{} bytes", data.len())),
        )
    };
    PanelData {
        title: title.map(str::to_owned),
        subtitle,
        border: Tone::Plain,
        body: vec![vec![Span {
            text: body,
            tone: Tone::Plain,
        }]],
    }
}

/// rich `Panel._title` / `_subtitle`: newlines → spaces, tabs expanded, one space of padding
/// on each side.
fn annotation(text: &str, tone: Tone) -> Cells {
    let mut cells = vec![(' ', tone)];
    cells.extend(expand_tabs(&to_cells(&text.replace('\n', " "), tone)));
    cells.push((' ', tone));
    cells
}

/// rich Panel `align_text`: crop to `width`, then fill with `fill` (left: after, right:
/// before).
fn align_annotation(text: Cells, width: usize, left: bool, fill: (char, Tone)) -> Cells {
    let text = truncate(text, width);
    let excess = width.saturating_sub(cells_width(&text));
    let padding = vec![fill; excess];
    if left {
        [text, padding].concat()
    } else {
        [padding, text].concat()
    }
}

/// rich 15 `Panel(Text, box=ROUNDED, padding=(0, 1), expand=False, title_align="left",
/// subtitle_align="right")` rendered at console width `width`.
fn render_panel(panel: &PanelData, width: usize) -> String {
    let border = panel.border;
    // An empty body is rich's empty Text: one blank line.
    let mut body: Vec<Cells> = panel.body.iter().map(line_cells).collect();
    if body.is_empty() {
        body.push(Cells::new());
    }

    // Measurement (rich `Panel.__rich_console__` → `console.measure(Padding(text, (0, 1)))`
    // at max_width - 2; Text measures its widest `splitlines()` line).
    let inner_max = width.saturating_sub(2);
    let plain: String = body
        .iter()
        .map(|line| line.iter().map(|&(c, _)| c).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    let text_max = py_splitlines(&plain)
        .into_iter()
        .map(display_width)
        .max()
        .unwrap_or(0)
        .min(inner_max);
    let padded_max = if inner_max < 3 {
        inner_max
    } else {
        (text_max + 2).min(inner_max)
    };
    let title = panel
        .title
        .as_deref()
        .map(|title| annotation(title, border));
    let mut child_width = padded_max;
    if let Some(title) = &title {
        child_width = (cells_width(title) + 2).max(child_width).min(inner_max);
    }
    let panel_width = child_width + 2;

    // Content: Padding(expand=True) renders the text at child_width - 2, padded.
    let text_width = child_width.saturating_sub(2);
    let mut rows: Vec<String> = Vec::new();
    let side = |c: char| styled(&[(c, border)]);
    let top = match title {
        Some(title) if panel_width > 4 => {
            let aligned = align_annotation(title, panel_width - 4, true, ('─', border));
            format!(
                "{}{}{}",
                side_str("╭─", border),
                styled(&aligned),
                side_str("─╮", border)
            )
        }
        _ => side_str(
            &format!("╭{}╮", "─".repeat(panel_width.saturating_sub(2))),
            border,
        ),
    };
    rows.push(top);
    for line in wrap_lines(&body, text_width) {
        let mut cells = vec![(' ', Tone::Plain)];
        let fill = text_width.saturating_sub(cells_width(&line));
        cells.extend(line);
        cells.extend(std::iter::repeat_n((' ', Tone::Plain), fill + 1));
        rows.push(format!("{}{}{}", side('│'), styled(&cells), side('│')));
    }
    let subtitle = panel
        .subtitle
        .as_deref()
        .map(|text| annotation(text, border));
    let bottom = match subtitle {
        Some(subtitle) if panel_width > 4 => {
            let aligned = align_annotation(subtitle, panel_width - 4, false, ('─', border));
            format!(
                "{}{}{}",
                side_str("╰─", border),
                styled(&aligned),
                side_str("─╯", border)
            )
        }
        _ => side_str(
            &format!("╰{}╯", "─".repeat(panel_width.saturating_sub(2))),
            border,
        ),
    };
    rows.push(bottom);
    rows.join("\n")
}

fn side_str(text: &str, tone: Tone) -> String {
    styled(&to_cells(text, tone))
}

// ---- tables -------------------------------------------------------------------------------

/// rich `box.SIMPLE_HEAD` look: only a header rule (fill and junction '─'); the junction
/// makes comfy-table separate columns by one blank vertical line, as rich does.
const SIMPLE_HEAD: TableStyle =
    TableStyle::new().header_separator(LineStyle::none().fill('─').junction('─'));

fn render_table(data: &TableData, cfg: &RenderConfig) -> String {
    let mut table = ComfyTable::new();
    table
        .load_style(SIMPLE_HEAD)
        .force_no_tty()
        .enforce_styling()
        .set_width(u16::try_from(cfg.width).unwrap_or(u16::MAX))
        .set_content_arrangement(ContentArrangement::Dynamic);
    if !data.columns.is_empty() {
        table.set_header(
            data.columns
                .iter()
                .map(|column| Cell::new(column).add_attribute(Attribute::Bold))
                .collect::<Vec<_>>(),
        );
    }
    for row in &data.rows {
        table.add_row(row.iter().map(Cell::new).collect::<Vec<_>>());
    }
    let body = if data.columns.is_empty() && data.rows.is_empty() {
        String::new()
    } else {
        // `trim_fmt()` cannot see the padding inside a styled (bold) header cell, which
        // ends with its SGR reset: trim the trailing blanks before such sequences too.
        table
            .trim_fmt()
            .lines()
            .map(trim_styled_end)
            .collect::<Vec<_>>()
            .join("\n")
    };
    let Some(title) = &data.title else {
        return body;
    };
    // The title: an italic line (rich wraps it at the table width), centered over the body.
    let table_width = body
        .lines()
        .map(|line| display_width(&anstream::adapter::strip_str(line).to_string()))
        .max()
        .unwrap_or(0);
    let title_width = if table_width == 0 {
        display_width(title).max(1)
    } else {
        table_width
    };
    let mut lines: Vec<String> = wrap_lines(&[to_cells(title, Tone::Italic)], title_width)
        .into_iter()
        .map(|line| {
            let mut end = line.len();
            while end > 0 && is_py_space(line[end - 1].0) {
                end -= 1;
            }
            let line = &line[..end];
            let left = title_width.saturating_sub(cells_width(line)) / 2;
            format!("{}{}", " ".repeat(left), styled(line))
        })
        .collect();
    if !body.is_empty() {
        lines.push(body);
    }
    lines.join("\n")
}

/// Trailing blanks of a line removed in the PLAIN domain: spaces before (and between)
/// trailing SGR sequences go, the sequences stay.
fn trim_styled_end(line: &str) -> String {
    let mut rest = line;
    let mut suffix: Vec<&str> = Vec::new();
    loop {
        if let Some(stripped) = rest.strip_suffix(' ') {
            rest = stripped;
            continue;
        }
        let sgr_start = rest.rfind('\u{1b}').filter(|&start| {
            let sequence = &rest[start..];
            sequence.len() >= 3
                && sequence.starts_with("\u{1b}[")
                && sequence.ends_with('m')
                && sequence[2..sequence.len() - 1]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b';')
        });
        match sgr_start {
            Some(start) => {
                suffix.push(&rest[start..]);
                rest = &rest[..start];
            }
            None => break,
        }
    }
    let mut out = rest.to_owned();
    for sequence in suffix.iter().rev() {
        out.push_str(sequence);
    }
    out
}
