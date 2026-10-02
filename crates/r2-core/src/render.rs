// The ConsoleIo renderer (spec §4.9.2; owner R1): Renderable → text. Text, styled lines and
// panels (error panel, hex dump) are an own port of rich 15's Text/Panel layout — its cell
// widths (rich's own Unicode table, ZWJ/VS16 graphemes), control-code stripping, tab
// expansion and fold wrapping — and equal rich's output; tables are comfy-table with a rich
// `box.SIMPLE_HEAD` look (§11 D1).
use std::cmp::Ordering;

use anstyle::{AnsiColor, Style};
use comfy_table::{
    Attribute, Cell, ContentArrangement, LineStyle, Table as ComfyTable, TableStyle,
};

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
/// ALWAYS emits ANSI SGR styling (the Full sink). Lines joined with "\n", no trailing
/// newline.
pub fn render(renderable: &Renderable, cfg: &RenderConfig) -> String {
    render_with(renderable, cfg, Sgr::Full)
}
/// The same layout with no SGR at all (tones ignored) — rich's output to a non-terminal:
/// content bytes (ESC, NUL, DEL, other C0 controls kept by the rich Text model) pass
/// unchanged. Tests, ScriptedIo, snapshots and the Plain sink.
pub fn render_plain(renderable: &Renderable, cfg: &RenderConfig) -> String {
    render_with(renderable, cfg, Sgr::Off)
}
/// The same layout with colour-free SGR (bold/dim/italic only; rich `no_color`) — the
/// NoColor sink. Content bytes pass unchanged.
pub fn render_no_color(renderable: &Renderable, cfg: &RenderConfig) -> String {
    render_with(renderable, cfg, Sgr::NoColor)
}

/// Which SGR the renderer emits for the tones. Styling is decided here, never by stripping
/// escape sequences afterwards (which cannot tell the renderer's SGR from content bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sgr {
    Full,
    NoColor,
    Off,
}

fn render_with(renderable: &Renderable, cfg: &RenderConfig, sgr: Sgr) -> String {
    match renderable {
        Renderable::Text(text) => render_text(&[to_cells(text, Tone::Plain)], cfg.width, sgr),
        Renderable::Styled(lines) => {
            let lines: Vec<Cells> = lines.iter().map(line_cells).collect();
            render_text(&lines, cfg.width, sgr)
        }
        Renderable::Table(data) => render_table(data, cfg, sgr),
        Renderable::Hex { data, title } => {
            render_panel(&hex_panel(data, title.as_deref(), cfg), cfg.width, sgr)
        }
        Renderable::Panel(panel) => render_panel(panel, cfg.width, sgr),
    }
}

// ---- cells (rich 15 `rich.cells`) ----------------------------------------------------

/// One character with its tone (the unit rich's Text/Segment model works in).
type Cells = Vec<(char, Tone)>;

/// Zero-width joiner: rich joins the character after it into the current grapheme.
const ZWJ: char = '\u{200d}';
/// Variation selector 16: widens the preceding `NARROW_TO_WIDE` character by one cell.
const VS16: char = '\u{fe0f}';

/// rich `get_character_cell_size`: C0 (except NUL) and C1 controls are zero-width, else
/// rich's own cell table (`CELL_WIDTHS`, Unicode 17.0.0; outside it, 1 cell).
fn char_width(c: char) -> usize {
    let code = u32::from(c);
    if (code != 0 && code < 0x20) || (0x7f..0xa0).contains(&code) {
        return 0;
    }
    CELL_WIDTHS
        .binary_search_by(|&(start, end, _)| {
            if end < code {
                Ordering::Less
            } else if start > code {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        })
        .map_or(1, |index| usize::from(CELL_WIDTHS[index].2))
}

fn widens_with_vs16(c: char) -> bool {
    NARROW_TO_WIDE.binary_search(&u32::from(c)).is_ok()
}

/// rich `cell_len`: the per-character widths, except that a ZWJ swallows itself and the
/// character after it, and a VS16 adds one cell to the last measured character when that
/// is in `NARROW_TO_WIDE` (once).
fn cell_len(chars: impl IntoIterator<Item = char>) -> usize {
    let mut total = 0;
    let mut last_measured: Option<char> = None;
    let mut chars = chars.into_iter();
    while let Some(c) = chars.next() {
        match c {
            ZWJ => {
                chars.next();
            }
            VS16 => {
                if let Some(last) = last_measured.take()
                    && widens_with_vs16(last)
                {
                    total += 1;
                }
            }
            _ => {
                let width = char_width(c);
                if width > 0 {
                    last_measured = Some(c);
                    total += width;
                }
            }
        }
    }
    total
}

fn str_cell_len(text: &str) -> usize {
    cell_len(text.chars())
}

fn cells_len(cells: &[(char, Tone)]) -> usize {
    cell_len(cells.iter().map(|&(c, _)| c))
}

/// One rich grapheme: char range `start..end` and its cell width.
#[derive(Clone, Copy)]
struct Grapheme {
    start: usize,
    end: usize,
    width: usize,
}

/// rich `split_graphemes`: a measured character plus the zero-width characters after it
/// (a ZWJ also takes the character it joins; a VS16 may widen it); a zero-width character
/// with nothing before it is a grapheme of its own. Returns the graphemes and their total.
fn split_graphemes(chars: &[char]) -> (Vec<Grapheme>, usize) {
    let mut spans: Vec<Grapheme> = Vec::new();
    let mut total = 0;
    let mut last_measured: Option<char> = None;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if c == ZWJ || c == VS16 {
            let Some(span) = spans.last_mut() else {
                spans.push(Grapheme {
                    start: index,
                    end: index + 1,
                    width: 0,
                });
                index += 1;
                continue;
            };
            if c == ZWJ {
                index += if index + 1 < chars.len() { 2 } else { 1 };
            } else {
                index += 1;
                if let Some(last) = last_measured
                    && widens_with_vs16(last)
                {
                    last_measured = None;
                    span.width += 1;
                    total += 1;
                }
            }
            span.end = index;
            continue;
        }
        let width = char_width(c);
        if width > 0 {
            last_measured = Some(c);
            spans.push(Grapheme {
                start: index,
                end: index + 1,
                width,
            });
            total += width;
        } else if let Some(span) = spans.last_mut() {
            span.end = index + 1;
        } else {
            spans.push(Grapheme {
                start: index,
                end: index + 1,
                width: 0,
            });
        }
        index += 1;
    }
    (spans, total)
}

/// rich `_split_text(text, cell_position)`, left part only: the number of leading chars,
/// and whether a space follows them (the split fell inside a double-width grapheme). The
/// initial guess and the walk are rich's, so zero-width graphemes split where rich's do.
fn split_cells(chars: &[char], cell_position: usize) -> (usize, bool) {
    if cell_position == 0 {
        return (0, false);
    }
    let (spans, cell_length) = split_graphemes(chars);
    if spans.is_empty() || cell_length == 0 {
        return (chars.len(), false);
    }
    // Python: int((cell_position / cell_length) * len(spans)) — float division, truncated.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let guess = ((cell_position as f64 / cell_length as f64) * spans.len() as f64) as usize;
    let mut offset = guess.min(spans.len());
    let mut left_size: usize = spans[..offset].iter().map(|span| span.width).sum();
    loop {
        if left_size == cell_position {
            return spans
                .get(offset)
                .map_or((chars.len(), false), |span| (span.start, false));
        }
        if left_size < cell_position {
            let Some(span) = spans.get(offset) else {
                return (chars.len(), false);
            };
            if left_size + span.width > cell_position {
                return (span.start, true);
            }
            offset += 1;
            left_size += span.width;
        } else {
            let Some(span) = offset.checked_sub(1).and_then(|index| spans.get(index)) else {
                return (0, false);
            };
            if left_size - span.width < cell_position {
                return (span.start, true);
            }
            offset -= 1;
            left_size -= span.width;
        }
    }
}

/// rich `set_cell_size` when cropping: the prefix of exactly `total` cells; a double-width
/// grapheme straddling the edge becomes a space (in its tone).
fn crop_cells(cells: &[(char, Tone)], total: usize) -> Cells {
    let chars: Vec<char> = cells.iter().map(|&(c, _)| c).collect();
    let (prefix, pad) = split_cells(&chars, total);
    let mut out = cells[..prefix].to_vec();
    if pad && let Some(&(_, tone)) = cells.get(prefix) {
        out.push((' ', tone));
    }
    out
}

/// rich `chop_cells`: char ranges of at most `width` cells, never splitting a grapheme.
fn chop_cells(chars: &[char], width: usize) -> Vec<(usize, usize)> {
    let (spans, _) = split_graphemes(chars);
    let mut lines = Vec::new();
    let mut line_size = 0;
    let mut line_offset = 0;
    for span in spans {
        if line_size + span.width > width {
            lines.push((line_offset, span.start));
            line_offset = span.start;
            line_size = 0;
        }
        line_size += span.width;
    }
    if line_size > 0 {
        lines.push((line_offset, chars.len()));
    }
    lines
}

/// The caret column of `io::caret`: the cell width of the row prefix as rich lays the row
/// out (control codes stripped, tabs expanded to 8 columns).
pub(crate) fn caret_column(prefix: &str) -> usize {
    cells_len(&expand_tabs(&to_cells(prefix, Tone::Plain)))
}

/// rich `strip_control_codes` (every Text construction): BEL, BS, VT, FF and CR vanish.
fn is_stripped_control(c: char) -> bool {
    matches!(c, '\u{7}' | '\u{8}' | '\u{b}' | '\u{c}' | '\r')
}

/// `text` as rich's `Text(text)` holds it: control codes stripped.
fn to_cells(text: &str, tone: Tone) -> Cells {
    text.chars()
        .filter(|&c| !is_stripped_control(c))
        .map(|c| (c, tone))
        .collect()
}

fn line_cells(line: &Line) -> Cells {
    line.iter()
        .flat_map(|span| to_cells(&span.text, span.tone))
        .collect()
}

fn tone_style(tone: Tone, sgr: Sgr) -> Style {
    let style = match tone {
        Tone::Plain => Style::new(),
        Tone::Bold => Style::new().bold(),
        Tone::Dim => Style::new().dimmed(),
        Tone::Italic => Style::new().italic(),
        Tone::Error => Style::new().bold().fg_color(Some(AnsiColor::Red.into())),
        Tone::Danger => Style::new().fg_color(Some(AnsiColor::Red.into())),
        Tone::Success => Style::new().bold().fg_color(Some(AnsiColor::Green.into())),
    };
    match sgr {
        Sgr::Full => style,
        Sgr::NoColor => style.fg_color(None).bg_color(None),
        Sgr::Off => Style::new(),
    }
}

/// SGR-styled text of one line: each run of equal tone wrapped in its style + reset.
fn styled(cells: &[(char, Tone)], sgr: Sgr) -> String {
    let mut out = String::new();
    let mut index = 0;
    while index < cells.len() {
        let tone = cells[index].1;
        let run_end = cells[index..]
            .iter()
            .position(|&(_, t)| t != tone)
            .map_or(cells.len(), |offset| index + offset);
        let text: String = cells[index..run_end].iter().map(|&(c, _)| c).collect();
        let style = tone_style(tone, sgr);
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

/// rich `Text.expand_tabs(8)` for one line (no '\n' inside): every tab becomes a space plus
/// the spaces up to the next multiple of 8 cells (in the tab's tone), the position counted
/// with `cell_len` per tab-terminated part.
fn expand_tabs(line: &[(char, Tone)]) -> Cells {
    if !line.iter().any(|&(c, _)| c == '\t') {
        return line.to_vec();
    }
    let mut out = Cells::with_capacity(line.len());
    let mut position = 0;
    for part in line.split_inclusive(|&(c, _)| c == '\t') {
        match part.split_last() {
            Some((&('\t', tone), head)) => {
                out.extend_from_slice(head);
                out.push((' ', tone));
                position += cell_len(head.iter().map(|&(c, _)| c).chain([' ']));
                let remainder = position % 8;
                if remainder != 0 {
                    out.extend(std::iter::repeat_n((' ', tone), 8 - remainder));
                    position += 8 - remainder;
                }
            }
            _ => {
                out.extend_from_slice(part);
                position += cells_len(part);
            }
        }
    }
    out
}

/// rich `Text.truncate(width)` (overflow fold, no pad): crop only when too wide.
fn truncate(cells: Cells, width: usize) -> Cells {
    if cells_len(&cells) > width {
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

/// rich `_wrap.divide_line(text, width, fold=True)`: char offsets to break the line at.
fn divide_line(chars: &[char], width: usize) -> Vec<usize> {
    let width_of = |slice: &[char]| cell_len(slice.iter().copied());
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
            for (index, &(from, to)) in pieces.iter().enumerate() {
                if piece_start != 0 {
                    breaks.push(piece_start);
                }
                if index + 1 == pieces.len() {
                    cell_offset = width_of(&word[from..to]);
                } else {
                    piece_start += to - from;
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

/// rich `console.print(Text)`: every '\n'-separated line wrapped at the console width.
/// (A 0 width never reaches the renderer from a console — §4.9.2 maps it to 80 — and
/// leaves the lines unwrapped.)
fn render_text(lines: &[Cells], width: usize, sgr: Sgr) -> String {
    let laid_out: Vec<Cells> = if width == 0 {
        lines
            .iter()
            .flat_map(|line| line.split(|&(c, _)| c == '\n').map(expand_tabs))
            .collect()
    } else {
        wrap_lines(lines, width)
    };
    laid_out
        .iter()
        .map(|line| styled(line, sgr))
        .collect::<Vec<_>>()
        .join("\n")
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

/// rich `Panel._title` / `_subtitle` (`Text(title)`): control codes stripped; an empty
/// annotation is none (rich `if self.title:`); newlines → spaces, tabs expanded, one space
/// of padding on each side.
fn annotation(text: &str, tone: Tone) -> Option<Cells> {
    let cells = to_cells(text, tone);
    if cells.is_empty() {
        return None;
    }
    let cells: Cells = cells
        .into_iter()
        .map(|(c, tone)| (if c == '\n' { ' ' } else { c }, tone))
        .collect();
    let mut out = vec![(' ', tone)];
    out.extend(expand_tabs(&cells));
    out.push((' ', tone));
    Some(out)
}

/// rich Panel `align_text`: crop to `width`, then fill with `fill` (left: after, right:
/// before). (rich then renders it with `no_wrap`, which only truncates again: a no-op.)
fn align_annotation(text: Cells, width: usize, left: bool, fill: (char, Tone)) -> Cells {
    let text = truncate(text, width);
    let excess = width.saturating_sub(cells_len(&text));
    let padding = vec![fill; excess];
    if left {
        [text, padding].concat()
    } else {
        [padding, text].concat()
    }
}

/// rich 15 `Panel(Text, box=ROUNDED, padding=(0, 1), expand=False, title_align="left",
/// subtitle_align="right")` rendered at console width `width`.
fn render_panel(panel: &PanelData, width: usize, sgr: Sgr) -> String {
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
        .map(str_cell_len)
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
        .and_then(|title| annotation(title, border));
    let mut child_width = padded_max;
    if let Some(title) = &title {
        child_width = (cells_len(title) + 2).max(child_width).min(inner_max);
    }
    let panel_width = child_width + 2;

    // Content: Padding(expand=True) renders the text at child_width - 2, padded; at a text
    // width below 1 rich renders no content line at all.
    let text_width = child_width.saturating_sub(2);
    let mut rows: Vec<String> = Vec::new();
    let side = |c: char| styled(&[(c, border)], sgr);
    let top = match title {
        Some(title) if panel_width > 4 => {
            let aligned = align_annotation(title, panel_width - 4, true, ('─', border));
            format!(
                "{}{}{}",
                side_str("╭─", border, sgr),
                styled(&aligned, sgr),
                side_str("─╮", border, sgr)
            )
        }
        _ => side_str(
            &format!("╭{}╮", "─".repeat(panel_width.saturating_sub(2))),
            border,
            sgr,
        ),
    };
    rows.push(top);
    if text_width > 0 {
        for line in wrap_lines(&body, text_width) {
            let mut cells = vec![(' ', Tone::Plain)];
            let fill = text_width.saturating_sub(cells_len(&line));
            cells.extend(line);
            cells.extend(std::iter::repeat_n((' ', Tone::Plain), fill + 1));
            rows.push(format!("{}{}{}", side('│'), styled(&cells, sgr), side('│')));
        }
    }
    let subtitle = panel
        .subtitle
        .as_deref()
        .and_then(|text| annotation(text, border));
    let bottom = match subtitle {
        Some(subtitle) if panel_width > 4 => {
            let aligned = align_annotation(subtitle, panel_width - 4, false, ('─', border));
            format!(
                "{}{}{}",
                side_str("╰─", border, sgr),
                styled(&aligned, sgr),
                side_str("─╯", border, sgr)
            )
        }
        _ => side_str(
            &format!("╰{}╯", "─".repeat(panel_width.saturating_sub(2))),
            border,
            sgr,
        ),
    };
    rows.push(bottom);
    rows.join("\n")
}

fn side_str(text: &str, tone: Tone, sgr: Sgr) -> String {
    styled(&to_cells(text, tone), sgr)
}

// ---- tables -------------------------------------------------------------------------------

/// rich `box.SIMPLE_HEAD` look: only a header rule (fill and junction '─'); the junction
/// makes comfy-table separate columns by one blank vertical line, as rich does.
const SIMPLE_HEAD: TableStyle =
    TableStyle::new().header_separator(LineStyle::none().fill('─').junction('─'));

/// `text` as rich's `Text(str(cell))` lays it out: control codes stripped, then each
/// '\n'-separated line's tabs expanded to the next multiple of 8 cells (counted from the
/// start of the cell line), so no TAB reaches comfy-table.
fn table_cell_text(text: &str) -> String {
    text.split('\n')
        .map(|line| {
            expand_tabs(&to_cells(line, Tone::Plain))
                .into_iter()
                .map(|(c, _)| c)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The comfy-table body lines (`trim_fmt`), header cells bold when `bold_header` (then
/// SGR is enforced; otherwise comfy-table emits none).
fn comfy_lines(data: &TableData, cfg: &RenderConfig, bold_header: bool) -> Vec<String> {
    let mut table = ComfyTable::new();
    table
        .load_style(SIMPLE_HEAD)
        .force_no_tty()
        .set_width(u16::try_from(cfg.width).unwrap_or(u16::MAX))
        .set_content_arrangement(ContentArrangement::Dynamic);
    if bold_header {
        table.enforce_styling();
    }
    if !data.columns.is_empty() {
        table.set_header(
            data.columns
                .iter()
                .map(|column| {
                    let cell = Cell::new(table_cell_text(column));
                    if bold_header {
                        cell.add_attribute(Attribute::Bold)
                    } else {
                        cell
                    }
                })
                .collect::<Vec<_>>(),
        );
    }
    for row in &data.rows {
        table.add_row(
            row.iter()
                .map(|cell| Cell::new(table_cell_text(cell)))
                .collect::<Vec<_>>(),
        );
    }
    table.trim_fmt().lines().map(str::to_owned).collect()
}

fn render_table(data: &TableData, cfg: &RenderConfig, sgr: Sgr) -> String {
    // rich renders a table without columns as nothing at all, its title included.
    if data.columns.is_empty() && data.rows.is_empty() {
        return String::new();
    }
    // Layout and measurement happen on the unstyled rendering, where cell content (ESC and
    // all) is plain text. The styled rendering only replaces the header lines (the bold
    // header cells are the only SGR comfy-table emits); `trim_fmt()` cannot see the padding
    // inside a styled header cell, which ends with its SGR reset, so those lines get their
    // trailing blanks before such sequences trimmed too. Row lines (data) are never parsed
    // for escape sequences.
    let plain = comfy_lines(data, cfg, false);
    let body_lines: Vec<String> = if sgr == Sgr::Off || data.columns.is_empty() {
        plain.clone()
    } else {
        let styled_lines = comfy_lines(data, cfg, true);
        let header_count = plain
            .iter()
            .position(|line| !line.is_empty() && line.chars().all(|c| c == '─'))
            .unwrap_or(0);
        if styled_lines.len() == plain.len() {
            plain
                .iter()
                .zip(&styled_lines)
                .enumerate()
                .map(|(index, (plain_line, styled_line))| {
                    if index < header_count {
                        trim_styled_end(styled_line)
                    } else {
                        plain_line.clone()
                    }
                })
                .collect()
        } else {
            plain.clone()
        }
    };
    let body = body_lines.join("\n");
    // rich `if self.title:` — an empty title (after control-code stripping) is none.
    let Some(title) = data
        .title
        .as_deref()
        .map(|title| to_cells(title, Tone::Italic))
        .filter(|title| !title.is_empty())
    else {
        return body;
    };
    // The title: an italic line (rich wraps it at the table width), centered over the body.
    let table_width = plain
        .iter()
        .map(|line| str_cell_len(line))
        .max()
        .unwrap_or(0);
    let title_width = if table_width == 0 {
        cells_len(&title).max(1)
    } else {
        table_width
    };
    let mut lines: Vec<String> = wrap_lines(&[title], title_width)
        .into_iter()
        .map(|line| {
            let mut end = line.len();
            while end > 0 && is_py_space(line[end - 1].0) {
                end -= 1;
            }
            let line = &line[..end];
            let left = title_width.saturating_sub(cells_len(line)) / 2;
            format!("{}{}", " ".repeat(left), styled(line, sgr))
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

// BEGIN GENERATED rich cell tables (gen_cell_widths.py; rich 15.0.0, Unicode 17.0.0):
// do not edit by hand.
/// rich `CellTable.widths`: sorted, disjoint, inclusive code-point ranges of width 0 or 2;
/// every other code point is 1 cell wide (after the C0/C1 rule of `char_width`).
#[rustfmt::skip]
const CELL_WIDTHS: &[(u32, u32, u8)] = &[
    (0x0, 0x0, 0), (0x300, 0x36f, 0), (0x483, 0x489, 0), (0x591, 0x5bd, 0),
    (0x5bf, 0x5bf, 0), (0x5c1, 0x5c2, 0), (0x5c4, 0x5c5, 0), (0x5c7, 0x5c7, 0),
    (0x610, 0x61a, 0), (0x61c, 0x61c, 0), (0x64b, 0x65f, 0), (0x670, 0x670, 0),
    (0x6d6, 0x6dc, 0), (0x6df, 0x6e4, 0), (0x6e7, 0x6e8, 0), (0x6ea, 0x6ed, 0),
    (0x711, 0x711, 0), (0x730, 0x74a, 0), (0x7a6, 0x7b0, 0), (0x7eb, 0x7f3, 0),
    (0x7fd, 0x7fd, 0), (0x816, 0x819, 0), (0x81b, 0x823, 0), (0x825, 0x827, 0),
    (0x829, 0x82d, 0), (0x859, 0x85b, 0), (0x897, 0x89f, 0), (0x8ca, 0x8e1, 0),
    (0x8e3, 0x903, 0), (0x93a, 0x93c, 0), (0x93e, 0x94f, 0), (0x951, 0x957, 0),
    (0x962, 0x963, 0), (0x981, 0x983, 0), (0x9bc, 0x9bc, 0), (0x9be, 0x9c4, 0),
    (0x9c7, 0x9c8, 0), (0x9cb, 0x9cd, 0), (0x9d7, 0x9d7, 0), (0x9e2, 0x9e3, 0),
    (0x9fe, 0x9fe, 0), (0xa01, 0xa03, 0), (0xa3c, 0xa3c, 0), (0xa3e, 0xa42, 0),
    (0xa47, 0xa48, 0), (0xa4b, 0xa4d, 0), (0xa51, 0xa51, 0), (0xa70, 0xa71, 0),
    (0xa75, 0xa75, 0), (0xa81, 0xa83, 0), (0xabc, 0xabc, 0), (0xabe, 0xac5, 0),
    (0xac7, 0xac9, 0), (0xacb, 0xacd, 0), (0xae2, 0xae3, 0), (0xafa, 0xaff, 0),
    (0xb01, 0xb03, 0), (0xb3c, 0xb3c, 0), (0xb3e, 0xb44, 0), (0xb47, 0xb48, 0),
    (0xb4b, 0xb4d, 0), (0xb55, 0xb57, 0), (0xb62, 0xb63, 0), (0xb82, 0xb82, 0),
    (0xbbe, 0xbc2, 0), (0xbc6, 0xbc8, 0), (0xbca, 0xbcd, 0), (0xbd7, 0xbd7, 0),
    (0xc00, 0xc04, 0), (0xc3c, 0xc3c, 0), (0xc3e, 0xc44, 0), (0xc46, 0xc48, 0),
    (0xc4a, 0xc4d, 0), (0xc55, 0xc56, 0), (0xc62, 0xc63, 0), (0xc81, 0xc83, 0),
    (0xcbc, 0xcbc, 0), (0xcbe, 0xcc4, 0), (0xcc6, 0xcc8, 0), (0xcca, 0xccd, 0),
    (0xcd5, 0xcd6, 0), (0xce2, 0xce3, 0), (0xcf3, 0xcf3, 0), (0xd00, 0xd03, 0),
    (0xd3b, 0xd3c, 0), (0xd3e, 0xd44, 0), (0xd46, 0xd48, 0), (0xd4a, 0xd4d, 0),
    (0xd57, 0xd57, 0), (0xd62, 0xd63, 0), (0xd81, 0xd83, 0), (0xdca, 0xdca, 0),
    (0xdcf, 0xdd4, 0), (0xdd6, 0xdd6, 0), (0xdd8, 0xddf, 0), (0xdf2, 0xdf3, 0),
    (0xe31, 0xe31, 0), (0xe34, 0xe3a, 0), (0xe47, 0xe4e, 0), (0xeb1, 0xeb1, 0),
    (0xeb4, 0xebc, 0), (0xec8, 0xece, 0), (0xf18, 0xf19, 0), (0xf35, 0xf35, 0),
    (0xf37, 0xf37, 0), (0xf39, 0xf39, 0), (0xf3e, 0xf3f, 0), (0xf71, 0xf84, 0),
    (0xf86, 0xf87, 0), (0xf8d, 0xf97, 0), (0xf99, 0xfbc, 0), (0xfc6, 0xfc6, 0),
    (0x102b, 0x103e, 0), (0x1056, 0x1059, 0), (0x105e, 0x1060, 0), (0x1062, 0x1064, 0),
    (0x1067, 0x106d, 0), (0x1071, 0x1074, 0), (0x1082, 0x108d, 0), (0x108f, 0x108f, 0),
    (0x109a, 0x109d, 0), (0x1100, 0x115f, 2), (0x1160, 0x11ff, 0), (0x135d, 0x135f, 0),
    (0x1712, 0x1715, 0), (0x1732, 0x1734, 0), (0x1752, 0x1753, 0), (0x1772, 0x1773, 0),
    (0x17b4, 0x17d3, 0), (0x17dd, 0x17dd, 0), (0x180b, 0x180f, 0), (0x1885, 0x1886, 0),
    (0x18a9, 0x18a9, 0), (0x1920, 0x192b, 0), (0x1930, 0x193b, 0), (0x1a17, 0x1a1b, 0),
    (0x1a55, 0x1a5e, 0), (0x1a60, 0x1a7c, 0), (0x1a7f, 0x1a7f, 0), (0x1ab0, 0x1add, 0),
    (0x1ae0, 0x1aeb, 0), (0x1b00, 0x1b04, 0), (0x1b34, 0x1b44, 0), (0x1b6b, 0x1b73, 0),
    (0x1b80, 0x1b82, 0), (0x1ba1, 0x1bad, 0), (0x1be6, 0x1bf3, 0), (0x1c24, 0x1c37, 0),
    (0x1cd0, 0x1cd2, 0), (0x1cd4, 0x1ce8, 0), (0x1ced, 0x1ced, 0), (0x1cf4, 0x1cf4, 0),
    (0x1cf7, 0x1cf9, 0), (0x1dc0, 0x1dff, 0), (0x200b, 0x200f, 0), (0x2028, 0x202e, 0),
    (0x2060, 0x206f, 0), (0x20d0, 0x20f0, 0), (0x231a, 0x231b, 2), (0x2329, 0x232a, 2),
    (0x23e9, 0x23ec, 2), (0x23f0, 0x23f0, 2), (0x23f3, 0x23f3, 2), (0x25fd, 0x25fe, 2),
    (0x2614, 0x2615, 2), (0x2630, 0x2637, 2), (0x2648, 0x2653, 2), (0x267f, 0x267f, 2),
    (0x268a, 0x268f, 2), (0x2693, 0x2693, 2), (0x26a1, 0x26a1, 2), (0x26aa, 0x26ab, 2),
    (0x26bd, 0x26be, 2), (0x26c4, 0x26c5, 2), (0x26ce, 0x26ce, 2), (0x26d4, 0x26d4, 2),
    (0x26ea, 0x26ea, 2), (0x26f2, 0x26f3, 2), (0x26f5, 0x26f5, 2), (0x26fa, 0x26fa, 2),
    (0x26fd, 0x26fd, 2), (0x2705, 0x2705, 2), (0x270a, 0x270b, 2), (0x2728, 0x2728, 2),
    (0x274c, 0x274c, 2), (0x274e, 0x274e, 2), (0x2753, 0x2755, 2), (0x2757, 0x2757, 2),
    (0x2795, 0x2797, 2), (0x27b0, 0x27b0, 2), (0x27bf, 0x27bf, 2), (0x2b1b, 0x2b1c, 2),
    (0x2b50, 0x2b50, 2), (0x2b55, 0x2b55, 2), (0x2cef, 0x2cf1, 0), (0x2d7f, 0x2d7f, 0),
    (0x2de0, 0x2dff, 0), (0x2e80, 0x2e99, 2), (0x2e9b, 0x2ef3, 2), (0x2f00, 0x2fd5, 2),
    (0x2ff0, 0x3029, 2), (0x302a, 0x302f, 0), (0x3030, 0x303e, 2), (0x3041, 0x3096, 2),
    (0x3099, 0x309a, 0), (0x309b, 0x30ff, 2), (0x3105, 0x312f, 2), (0x3131, 0x3163, 2),
    (0x3164, 0x3164, 0), (0x3165, 0x318e, 2), (0x3190, 0x31e5, 2), (0x31ef, 0x321e, 2),
    (0x3220, 0x3247, 2), (0x3250, 0xa48c, 2), (0xa490, 0xa4c6, 2), (0xa66f, 0xa672, 0),
    (0xa674, 0xa67d, 0), (0xa69e, 0xa69f, 0), (0xa6f0, 0xa6f1, 0), (0xa802, 0xa802, 0),
    (0xa806, 0xa806, 0), (0xa80b, 0xa80b, 0), (0xa823, 0xa827, 0), (0xa82c, 0xa82c, 0),
    (0xa880, 0xa881, 0), (0xa8b4, 0xa8c5, 0), (0xa8e0, 0xa8f1, 0), (0xa8ff, 0xa8ff, 0),
    (0xa926, 0xa92d, 0), (0xa947, 0xa953, 0), (0xa960, 0xa97c, 2), (0xa980, 0xa983, 0),
    (0xa9b3, 0xa9c0, 0), (0xa9e5, 0xa9e5, 0), (0xaa29, 0xaa36, 0), (0xaa43, 0xaa43, 0),
    (0xaa4c, 0xaa4d, 0), (0xaa7b, 0xaa7d, 0), (0xaab0, 0xaab0, 0), (0xaab2, 0xaab4, 0),
    (0xaab7, 0xaab8, 0), (0xaabe, 0xaabf, 0), (0xaac1, 0xaac1, 0), (0xaaeb, 0xaaef, 0),
    (0xaaf5, 0xaaf6, 0), (0xabe3, 0xabea, 0), (0xabec, 0xabed, 0), (0xac00, 0xd7a3, 2),
    (0xd7b0, 0xd7ff, 0), (0xf900, 0xfaff, 2), (0xfb1e, 0xfb1e, 0), (0xfe00, 0xfe0f, 0),
    (0xfe10, 0xfe19, 2), (0xfe20, 0xfe2f, 0), (0xfe30, 0xfe52, 2), (0xfe54, 0xfe66, 2),
    (0xfe68, 0xfe6b, 2), (0xfeff, 0xfeff, 0), (0xff01, 0xff60, 2), (0xffa0, 0xffa0, 0),
    (0xffe0, 0xffe6, 2), (0xfff0, 0xfffb, 0), (0x101fd, 0x101fd, 0), (0x102e0, 0x102e0, 0),
    (0x10376, 0x1037a, 0), (0x10a01, 0x10a03, 0), (0x10a05, 0x10a06, 0), (0x10a0c, 0x10a0f, 0),
    (0x10a38, 0x10a3a, 0), (0x10a3f, 0x10a3f, 0), (0x10ae5, 0x10ae6, 0), (0x10d24, 0x10d27, 0),
    (0x10d69, 0x10d6d, 0), (0x10eab, 0x10eac, 0), (0x10efa, 0x10eff, 0), (0x10f46, 0x10f50, 0),
    (0x10f82, 0x10f85, 0), (0x11000, 0x11002, 0), (0x11038, 0x11046, 0), (0x11070, 0x11070, 0),
    (0x11073, 0x11074, 0), (0x1107f, 0x11082, 0), (0x110b0, 0x110ba, 0), (0x110c2, 0x110c2, 0),
    (0x11100, 0x11102, 0), (0x11127, 0x11134, 0), (0x11145, 0x11146, 0), (0x11173, 0x11173, 0),
    (0x11180, 0x11182, 0), (0x111b3, 0x111c0, 0), (0x111c9, 0x111cc, 0), (0x111ce, 0x111cf, 0),
    (0x1122c, 0x11237, 0), (0x1123e, 0x1123e, 0), (0x11241, 0x11241, 0), (0x112df, 0x112ea, 0),
    (0x11300, 0x11303, 0), (0x1133b, 0x1133c, 0), (0x1133e, 0x11344, 0), (0x11347, 0x11348, 0),
    (0x1134b, 0x1134d, 0), (0x11357, 0x11357, 0), (0x11362, 0x11363, 0), (0x11366, 0x1136c, 0),
    (0x11370, 0x11374, 0), (0x113b8, 0x113c0, 0), (0x113c2, 0x113c2, 0), (0x113c5, 0x113c5, 0),
    (0x113c7, 0x113ca, 0), (0x113cc, 0x113d0, 0), (0x113d2, 0x113d2, 0), (0x113e1, 0x113e2, 0),
    (0x11435, 0x11446, 0), (0x1145e, 0x1145e, 0), (0x114b0, 0x114c3, 0), (0x115af, 0x115b5, 0),
    (0x115b8, 0x115c0, 0), (0x115dc, 0x115dd, 0), (0x11630, 0x11640, 0), (0x116ab, 0x116b7, 0),
    (0x1171d, 0x1172b, 0), (0x1182c, 0x1183a, 0), (0x11930, 0x11935, 0), (0x11937, 0x11938, 0),
    (0x1193b, 0x1193e, 0), (0x11940, 0x11940, 0), (0x11942, 0x11943, 0), (0x119d1, 0x119d7, 0),
    (0x119da, 0x119e0, 0), (0x119e4, 0x119e4, 0), (0x11a01, 0x11a0a, 0), (0x11a33, 0x11a39, 0),
    (0x11a3b, 0x11a3e, 0), (0x11a47, 0x11a47, 0), (0x11a51, 0x11a5b, 0), (0x11a8a, 0x11a99, 0),
    (0x11b60, 0x11b67, 0), (0x11c2f, 0x11c36, 0), (0x11c38, 0x11c3f, 0), (0x11c92, 0x11ca7, 0),
    (0x11ca9, 0x11cb6, 0), (0x11d31, 0x11d36, 0), (0x11d3a, 0x11d3a, 0), (0x11d3c, 0x11d3d, 0),
    (0x11d3f, 0x11d45, 0), (0x11d47, 0x11d47, 0), (0x11d8a, 0x11d8e, 0), (0x11d90, 0x11d91, 0),
    (0x11d93, 0x11d97, 0), (0x11ef3, 0x11ef6, 0), (0x11f00, 0x11f01, 0), (0x11f03, 0x11f03, 0),
    (0x11f34, 0x11f3a, 0), (0x11f3e, 0x11f42, 0), (0x11f5a, 0x11f5a, 0), (0x13430, 0x13440, 0),
    (0x13447, 0x13455, 0), (0x1611e, 0x1612f, 0), (0x16af0, 0x16af4, 0), (0x16b30, 0x16b36, 0),
    (0x16f4f, 0x16f4f, 0), (0x16f51, 0x16f87, 0), (0x16f8f, 0x16f92, 0), (0x16fe0, 0x16fe3, 2),
    (0x16fe4, 0x16fe4, 0), (0x16ff0, 0x16ff1, 0), (0x16ff2, 0x16ff6, 2), (0x17000, 0x18cd5, 2),
    (0x18cff, 0x18d1e, 2), (0x18d80, 0x18df2, 2), (0x1aff0, 0x1aff3, 2), (0x1aff5, 0x1affb, 2),
    (0x1affd, 0x1affe, 2), (0x1b000, 0x1b122, 2), (0x1b132, 0x1b132, 2), (0x1b150, 0x1b152, 2),
    (0x1b155, 0x1b155, 2), (0x1b164, 0x1b167, 2), (0x1b170, 0x1b2fb, 2), (0x1bc9d, 0x1bc9e, 0),
    (0x1bca0, 0x1bca3, 0), (0x1cf00, 0x1cf2d, 0), (0x1cf30, 0x1cf46, 0), (0x1d165, 0x1d169, 0),
    (0x1d16d, 0x1d182, 0), (0x1d185, 0x1d18b, 0), (0x1d1aa, 0x1d1ad, 0), (0x1d242, 0x1d244, 0),
    (0x1d300, 0x1d356, 2), (0x1d360, 0x1d376, 2), (0x1da00, 0x1da36, 0), (0x1da3b, 0x1da6c, 0),
    (0x1da75, 0x1da75, 0), (0x1da84, 0x1da84, 0), (0x1da9b, 0x1da9f, 0), (0x1daa1, 0x1daaf, 0),
    (0x1e000, 0x1e006, 0), (0x1e008, 0x1e018, 0), (0x1e01b, 0x1e021, 0), (0x1e023, 0x1e024, 0),
    (0x1e026, 0x1e02a, 0), (0x1e08f, 0x1e08f, 0), (0x1e130, 0x1e136, 0), (0x1e2ae, 0x1e2ae, 0),
    (0x1e2ec, 0x1e2ef, 0), (0x1e4ec, 0x1e4ef, 0), (0x1e5ee, 0x1e5ef, 0), (0x1e6e3, 0x1e6e3, 0),
    (0x1e6e6, 0x1e6e6, 0), (0x1e6ee, 0x1e6ef, 0), (0x1e6f5, 0x1e6f5, 0), (0x1e8d0, 0x1e8d6, 0),
    (0x1e944, 0x1e94a, 0), (0x1f004, 0x1f004, 2), (0x1f0cf, 0x1f0cf, 2), (0x1f18e, 0x1f18e, 2),
    (0x1f191, 0x1f19a, 2), (0x1f200, 0x1f202, 2), (0x1f210, 0x1f23b, 2), (0x1f240, 0x1f248, 2),
    (0x1f250, 0x1f251, 2), (0x1f260, 0x1f265, 2), (0x1f300, 0x1f320, 2), (0x1f32d, 0x1f335, 2),
    (0x1f337, 0x1f37c, 2), (0x1f37e, 0x1f393, 2), (0x1f3a0, 0x1f3ca, 2), (0x1f3cf, 0x1f3d3, 2),
    (0x1f3e0, 0x1f3f0, 2), (0x1f3f4, 0x1f3f4, 2), (0x1f3f8, 0x1f3fa, 2), (0x1f3fb, 0x1f3ff, 0),
    (0x1f400, 0x1f43e, 2), (0x1f440, 0x1f440, 2), (0x1f442, 0x1f4fc, 2), (0x1f4ff, 0x1f53d, 2),
    (0x1f54b, 0x1f54e, 2), (0x1f550, 0x1f567, 2), (0x1f57a, 0x1f57a, 2), (0x1f595, 0x1f596, 2),
    (0x1f5a4, 0x1f5a4, 2), (0x1f5fb, 0x1f64f, 2), (0x1f680, 0x1f6c5, 2), (0x1f6cc, 0x1f6cc, 2),
    (0x1f6d0, 0x1f6d2, 2), (0x1f6d5, 0x1f6d8, 2), (0x1f6dc, 0x1f6df, 2), (0x1f6eb, 0x1f6ec, 2),
    (0x1f6f4, 0x1f6fc, 2), (0x1f7e0, 0x1f7eb, 2), (0x1f7f0, 0x1f7f0, 2), (0x1f90c, 0x1f93a, 2),
    (0x1f93c, 0x1f945, 2), (0x1f947, 0x1f9ff, 2), (0x1fa70, 0x1fa7c, 2), (0x1fa80, 0x1fa8a, 2),
    (0x1fa8e, 0x1fac6, 2), (0x1fac8, 0x1fac8, 2), (0x1facd, 0x1fadc, 2), (0x1fadf, 0x1faea, 2),
    (0x1faef, 0x1faf8, 2), (0x20000, 0x2fffd, 2), (0x30000, 0x3fffd, 2), (0xe0000, 0xe0fff, 0),
];
/// rich `CellTable.narrow_to_wide`: characters that a following U+FE0F (VS16) widens by
/// one cell (sorted, for binary search).
#[rustfmt::skip]
const NARROW_TO_WIDE: &[u32] = &[
    0x23, 0x2a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0xa9, 0xae, 0x203c, 0x2049, 0x2122, 0x2139, 0x2194, 0x2195,
    0x2196, 0x2197, 0x2198, 0x2199, 0x21a9, 0x21aa, 0x2328, 0x23cf, 0x23ed, 0x23ee,
    0x23ef, 0x23f1, 0x23f2, 0x23f8, 0x23f9, 0x23fa, 0x24c2, 0x25aa, 0x25ab, 0x25b6,
    0x25c0, 0x25fb, 0x25fc, 0x2600, 0x2601, 0x2602, 0x2603, 0x2604, 0x260e, 0x2611,
    0x2618, 0x261d, 0x2620, 0x2622, 0x2623, 0x2626, 0x262a, 0x262e, 0x262f, 0x2638,
    0x2639, 0x263a, 0x2640, 0x2642, 0x265f, 0x2660, 0x2663, 0x2665, 0x2666, 0x2668,
    0x267b, 0x267e, 0x2692, 0x2694, 0x2695, 0x2696, 0x2697, 0x2699, 0x269b, 0x269c,
    0x26a0, 0x26a7, 0x26b0, 0x26b1, 0x26c8, 0x26cf, 0x26d1, 0x26d3, 0x26e9, 0x26f0,
    0x26f1, 0x26f4, 0x26f7, 0x26f8, 0x26f9, 0x2702, 0x2708, 0x2709, 0x270c, 0x270d,
    0x270f, 0x2712, 0x2714, 0x2716, 0x271d, 0x2721, 0x2733, 0x2734, 0x2744, 0x2747,
    0x2763, 0x2764, 0x27a1, 0x2934, 0x2935, 0x2b05, 0x2b06, 0x2b07, 0x1f170, 0x1f171,
    0x1f17e, 0x1f17f, 0x1f321, 0x1f324, 0x1f325, 0x1f326, 0x1f327, 0x1f328, 0x1f329, 0x1f32a,
    0x1f32b, 0x1f32c, 0x1f336, 0x1f37d, 0x1f396, 0x1f397, 0x1f399, 0x1f39a, 0x1f39b, 0x1f39e,
    0x1f39f, 0x1f3cb, 0x1f3cc, 0x1f3cd, 0x1f3ce, 0x1f3d4, 0x1f3d5, 0x1f3d6, 0x1f3d7, 0x1f3d8,
    0x1f3d9, 0x1f3da, 0x1f3db, 0x1f3dc, 0x1f3dd, 0x1f3de, 0x1f3df, 0x1f3f3, 0x1f3f5, 0x1f3f7,
    0x1f43f, 0x1f441, 0x1f4fd, 0x1f549, 0x1f54a, 0x1f56f, 0x1f570, 0x1f573, 0x1f574, 0x1f575,
    0x1f576, 0x1f577, 0x1f578, 0x1f579, 0x1f587, 0x1f58a, 0x1f58b, 0x1f58c, 0x1f58d, 0x1f590,
    0x1f5a5, 0x1f5a8, 0x1f5b1, 0x1f5b2, 0x1f5bc, 0x1f5c2, 0x1f5c3, 0x1f5c4, 0x1f5d1, 0x1f5d2,
    0x1f5d3, 0x1f5dc, 0x1f5dd, 0x1f5de, 0x1f5e1, 0x1f5e3, 0x1f5e8, 0x1f5ef, 0x1f5f3, 0x1f5fa,
    0x1f6cb, 0x1f6cd, 0x1f6ce, 0x1f6cf, 0x1f6e0, 0x1f6e1, 0x1f6e2, 0x1f6e3, 0x1f6e4, 0x1f6e5,
    0x1f6e9, 0x1f6f0, 0x1f6f3,
];
// END GENERATED rich cell tables

#[cfg(test)]
mod tests {
    use super::*;

    /// `char_width`'s binary search needs sorted, disjoint ranges; `widens_with_vs16` a
    /// sorted list.
    #[test]
    fn cell_tables_are_sorted() {
        assert!(CELL_WIDTHS.iter().all(|&(start, end, _)| start <= end));
        assert!(CELL_WIDTHS.windows(2).all(|pair| pair[0].1 < pair[1].0));
        assert!(
            CELL_WIDTHS
                .iter()
                .all(|&(_, _, width)| width == 0 || width == 2)
        );
        assert!(NARROW_TO_WIDE.windows(2).all(|pair| pair[0] < pair[1]));
    }

    /// rich `cell_len` / `split_graphemes` / `set_cell_size` / `chop_cells` spot checks
    /// (values from rich 15).
    #[test]
    fn rich_cell_helpers() {
        assert_eq!(str_cell_len("\u{1f469}\u{200d}\u{1f4bb}"), 2);
        assert_eq!(str_cell_len("\u{2764}\u{fe0f}"), 2);
        assert_eq!(str_cell_len("\u{2764}"), 1);
        assert_eq!(str_cell_len("\u{93e}\u{ad}\u{1f3fb}"), 1);
        assert_eq!(str_cell_len("\u{200d}a"), 0);
        let chars: Vec<char> = "a\u{65e5}b".chars().collect();
        assert_eq!(split_cells(&chars, 2), (1, true));
        assert_eq!(split_cells(&chars, 3), (2, false));
        let cells = to_cells("a\u{65e5}b", Tone::Bold);
        assert_eq!(
            crop_cells(&cells, 2),
            vec![('a', Tone::Bold), (' ', Tone::Bold)]
        );
        let chars: Vec<char> = "\u{1f469}\u{200d}\u{1f4bb}x".chars().collect();
        assert_eq!(chop_cells(&chars, 2), vec![(0, 3), (3, 4)]);
        assert_eq!(caret_column("a\tb\r"), 9);
    }
}
