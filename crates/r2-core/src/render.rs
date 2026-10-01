// R0 skeleton — owner R1 (generated from spec §4)
// ---- spec §4.9.2 block 1
use crate::io::Renderable;

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
    let _ = (renderable, cfg);
    unimplemented!("R1")
}
/// `anstream::adapter::strip_str(&render(r, cfg))` — tests, ScriptedIo, snapshots.
pub fn render_plain(renderable: &Renderable, cfg: &RenderConfig) -> String {
    let _ = (renderable, cfg);
    unimplemented!("R1")
}
