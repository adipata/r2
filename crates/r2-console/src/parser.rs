// R0 skeleton — owner R7 (generated from spec §4)
// ---- spec §4.9.7 block 0
use indexmap::IndexMap;

/// One shell-style token. `pos`/`end` are byte offsets of the raw token in the line
/// (opening/closing quote included).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub quoted: bool,
    pub pos: usize,
    pub end: usize,
}

/// Split per the rules below. Unterminated quote → Parse "unterminated quote" (pos at the
/// opening quote; hint "close the quote, or keep typing — unterminated quotes continue on
/// the next line").
pub fn tokenize(line: &str) -> r2_core::Result<Vec<Token>> {
    let _ = line;
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
/// False while an unterminated quote keeps the buffer open.
pub fn line_is_complete(line: &str) -> bool {
    let _ = line;
    unimplemented!("R7")
}

/// Value of a `--option`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptValue {
    Value(String),
    Flag,
}

/// parser output (c2 BoundArgs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoundArgs {
    pub positionals: Vec<String>,
    /// Parallel to `positionals`: was the token quoted?
    pub positional_quoted: Vec<bool>,
    /// name=value tokens; insertion order; a repeated name keeps its first position and
    /// the last value (Python dict semantics).
    pub named: IndexMap<String, String>,
    /// --options (same repeat semantics).
    pub options: IndexMap<String, OptValue>,
}
impl BoundArgs {
    /// Value of a value-carrying option (c2 `_opt`); None when absent or a Flag.
    pub fn opt(&self, name: &str) -> Option<&str> {
        let _ = name;
        unimplemented!("R7")
    }
    /// True when the option is present as a Flag (c2 `options.get(name) is True`).
    pub fn flag(&self, name: &str) -> bool {
        let _ = name;
        unimplemented!("R7")
    }
    pub fn has_option(&self, name: &str) -> bool {
        let _ = name;
        unimplemented!("R7")
    }
}

/// Bind per the rules below; `flags` = the command's boolean options; `line` = the full
/// original input (carried into Parse errors).
pub fn bind_args(tokens: &[Token], flags: &[&str], line: &str) -> r2_core::Result<BoundArgs> {
    let _ = (tokens, flags, line);
    Err(r2_core::ConsoleError::not_implemented("R7"))
}
