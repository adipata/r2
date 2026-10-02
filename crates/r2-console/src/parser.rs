// Tokenizer + argument binder (spec §4.9.7; owner R7) — the port of c2 `console/parser.py`.
//
// Tokenizer: split on unquoted whitespace including newlines (Python `str.isspace`); `"…"` /
// `'…'` delimit one token preserving inner whitespace verbatim, but only at a token boundary
// (inside an unquoted token quote chars are literal); inside quotes a backslash escapes only
// the active quote char and backslash; a closing quote ends the token; an unterminated quote
// is a multiline continuation. Positions are BYTE offsets.
//
// Binding — applied to unquoted tokens only (a quoted token is never an option or a
// name=value): `--name` (flag, or consumes the next token), `name=value` (split at the first
// `=`), everything else positional.
use indexmap::IndexMap;
use r2_core::error::ConsoleError;
use r2_core::text::is_py_space;

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
    let mut tokens = Vec::new();
    let mut chars = line.char_indices().peekable();
    while let Some(&(start, ch)) = chars.peek() {
        if is_py_space(ch) {
            chars.next();
            continue;
        }
        if ch == '"' || ch == '\'' {
            chars.next();
            let quote = ch;
            let mut text = String::new();
            let mut end = None;
            while let Some((i, c)) = chars.next() {
                if c == '\\' {
                    if let Some(&(_, next)) = chars.peek()
                        && (next == quote || next == '\\')
                    {
                        text.push(next);
                        chars.next();
                        continue;
                    }
                    text.push(c);
                    continue;
                }
                if c == quote {
                    end = Some(i + c.len_utf8());
                    break;
                }
                text.push(c);
            }
            let Some(end) = end else {
                return Err(ConsoleError::parse("unterminated quote", line, start).with_hint(
                    "close the quote, or keep typing — unterminated quotes continue on the next line",
                ));
            };
            tokens.push(Token {
                text,
                quoted: true,
                pos: start,
                end,
            });
        } else {
            let mut end = line.len();
            while let Some(&(i, c)) = chars.peek() {
                if is_py_space(c) {
                    end = i;
                    break;
                }
                chars.next();
            }
            tokens.push(Token {
                text: line[start..end].to_owned(),
                quoted: false,
                pos: start,
                end,
            });
        }
    }
    Ok(tokens)
}
/// False while an unterminated quote keeps the buffer open.
pub fn line_is_complete(line: &str) -> bool {
    tokenize(line).is_ok()
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
        match self.options.get(name) {
            Some(OptValue::Value(value)) => Some(value),
            _ => None,
        }
    }
    /// True when the option is present as a Flag (c2 `options.get(name) is True`).
    pub fn flag(&self, name: &str) -> bool {
        matches!(self.options.get(name), Some(OptValue::Flag))
    }
    pub fn has_option(&self, name: &str) -> bool {
        self.options.contains_key(name)
    }
}

/// Bind per the rules below; `flags` = the command's boolean options; `line` = the full
/// original input (carried into Parse errors).
pub fn bind_args(tokens: &[Token], flags: &[&str], line: &str) -> r2_core::Result<BoundArgs> {
    let mut args = BoundArgs::default();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if !token.quoted
            && let Some(name) = token.text.strip_prefix("--")
        {
            if name.is_empty() {
                return Err(ConsoleError::parse("empty option name", line, token.pos)
                    .with_hint("options are written --name"));
            }
            if flags.contains(&name) {
                args.options.insert(name.to_owned(), OptValue::Flag);
            } else {
                let Some(value) = tokens.get(index + 1) else {
                    return Err(ConsoleError::parse(
                        format!("option --{name} expects a value"),
                        line,
                        token.pos,
                    )
                    .with_hint(format!("write: --{name} <value>")));
                };
                args.options
                    .insert(name.to_owned(), OptValue::Value(value.text.clone()));
                index += 1;
            }
        } else if !token.quoted
            && let Some((name, value)) = token.text.split_once('=')
        {
            if name.is_empty() {
                return Err(
                    ConsoleError::parse("empty parameter name before '='", line, token.pos)
                        .with_hint("parameters are written name=value"),
                );
            }
            args.named.insert(name.to_owned(), value.to_owned());
        } else {
            args.positionals.push(token.text.clone());
            args.positional_quoted.push(token.quoted);
        }
        index += 1;
    }
    Ok(args)
}
