// ParamResolver (spec §4.6.4; owner R7) — the port of c2 `ops/params.py`: ONE code path for
// inline and interactive parameters.
//
// Per ParamSpec in declared order: `given[name]` → parse + validate; else `default_from`
// (copy that param's already-resolved value) when set; else `default` when not required;
// else `io.prompt(param)` until the answer parses. Unknown names in `given` → ParamError
// listing the valid names. Ctrl-C / Ctrl-D inside the prompt arrive from the IO as UserAbort
// and propagate.
use std::collections::HashSet;

use indexmap::IndexMap;
use r2_core::codec::decode_data;
use r2_core::error::{ConsoleError, ErrorKind, Result};
use r2_core::io::ConsoleIo;
use r2_core::text::{py_repr, py_strip};
use r2_provider::ProviderRegistry;

use crate::model::{OperationSpec, ParamKind, ParamSpec, ParamValue, Params};

/// c2 `_BOOL_VALUES`.
const BOOL_VALUES: [(&str, bool); 8] = [
    ("true", true),
    ("yes", true),
    ("on", true),
    ("1", true),
    ("false", false),
    ("no", false),
    ("off", false),
    ("0", false),
];

pub struct ParamResolver<'a> {
    io: &'a dyn ConsoleIo,
    providers: &'a ProviderRegistry,
}
impl<'a> ParamResolver<'a> {
    pub fn new(io: &'a dyn ConsoleIo, providers: &'a ProviderRegistry) -> Self {
        Self { io, providers }
    }
    /// Algorithm below. `given` = BoundArgs.named (name=value tokens, line order).
    pub fn resolve(
        &self,
        spec: &OperationSpec,
        given: &IndexMap<String, String>,
    ) -> Result<Params> {
        for name in given.keys() {
            if spec.param(name).is_none() {
                let hint = if spec.params.is_empty() {
                    "this operation takes no parameters".to_owned()
                } else {
                    let names: Vec<&str> = spec.params.iter().map(|p| p.name.as_str()).collect();
                    format!("valid parameters: {}", names.join(", "))
                };
                return Err(ConsoleError::param(
                    format!("unknown parameter '{name}' for {}", spec.id),
                    name.clone(),
                )
                .with_hint(hint));
            }
        }
        let mut resolved = Params::new();
        // A resolved-but-absent param (c2 stored None) still counts as resolved.
        let mut seen: HashSet<&str> = HashSet::new();
        for param in &spec.params {
            if let Some(text) = given.get(&param.name) {
                let value = self.parse_value(param, text)?;
                resolved.insert(param.name.clone(), value);
            } else if let Some(other) = &param.default_from {
                if !seen.contains(other.as_str()) {
                    return Err(ConsoleError::param(
                        format!(
                            "parameter '{}' mirrors '{other}', which is not resolved yet",
                            param.name
                        ),
                        param.name.clone(),
                    )
                    .with_hint("default_from must reference an earlier parameter (§4.6)"));
                }
                if let Some(value) = resolved.get(other).cloned() {
                    resolved.insert(param.name.clone(), value);
                }
            } else if !param.required {
                if let Some(value) = &param.default {
                    resolved.insert(param.name.clone(), value.clone());
                }
            } else {
                let value = self.prompt(param)?;
                resolved.insert(param.name.clone(), value);
            }
            seen.insert(param.name.as_str());
        }
        Ok(resolved)
    }
    /// Parse + validate one textual value per its ParamSpec (rules below).
    pub fn parse_value(&self, param: &ParamSpec, text: &str) -> Result<ParamValue> {
        let value = self.parse_kind(param, text)?;
        if let Some(validator) = param.validate {
            (validator.0)(&value)?;
        }
        Ok(value)
    }

    /// Prompt until the answer parses; a ParamError is shown and the prompt repeats; any
    /// other error (the IO's UserAbort) propagates.
    fn prompt(&self, param: &ParamSpec) -> Result<ParamValue> {
        loop {
            let text = self.io.prompt(param)?;
            match self.parse_value(param, &text) {
                Ok(value) => return Ok(value),
                Err(err) if matches!(err.kind, ErrorKind::Param { .. }) => {
                    self.io.print_error(&err);
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn parse_kind(&self, param: &ParamSpec, text: &str) -> Result<ParamValue> {
        let name = param.name.as_str();
        match param.kind {
            ParamKind::Str => Ok(ParamValue::Str(text.to_owned())),
            ParamKind::Int => {
                let stripped = py_strip(text);
                let digits = stripped.strip_prefix('-').unwrap_or(stripped);
                let parsed = if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                    // Out of i64 range is rejected with the same message (§11 D18).
                    stripped.parse::<i64>().ok()
                } else {
                    None
                };
                match parsed {
                    Some(value) => Ok(ParamValue::Int(value)),
                    None => Err(ConsoleError::param(
                        format!("{name}: invalid integer {}", py_repr(text)),
                        name,
                    )
                    .with_hint("decimal digits with an optional leading '-' only (§4.6)")),
                }
            }
            ParamKind::Bool => {
                let answer = py_strip(text).to_lowercase();
                match BOOL_VALUES.iter().find(|(word, _)| *word == answer) {
                    Some((_, value)) => Ok(ParamValue::Bool(*value)),
                    None => Err(ConsoleError::param(
                        format!("{name}: invalid boolean {}", py_repr(text)),
                        name,
                    )
                    .with_hint("accepted: true/false, yes/no, on/off, 1/0")),
                }
            }
            ParamKind::Enum => {
                let choices = param.choices.as_deref().unwrap_or(&[]);
                let answer = py_strip(text);
                if choices.iter().any(|choice| choice == answer) {
                    Ok(ParamValue::Enum(answer.to_owned()))
                } else {
                    Err(ConsoleError::param(
                        format!("{name}: invalid choice {}", py_repr(text)),
                        name,
                    )
                    .with_hint(format!("choices: {}", choices.join(", "))))
                }
            }
            ParamKind::Bytes => self.parse_bytes(param, text),
            ParamKind::KeyRef => self.parse_keyref(param, text),
        }
    }

    fn parse_bytes(&self, param: &ParamSpec, text: &str) -> Result<ParamValue> {
        let name = param.name.as_str();
        let data = match decode_data(py_strip(text)) {
            Ok((data, _format)) => data,
            Err(err) if err.kind.is_user_abort() => return Err(err),
            Err(err) => {
                return Err(
                    ConsoleError::param(format!("{name}: {}", err.message), name)
                        .with_hint_opt(err.hint),
                );
            }
        };
        if let Some(length) = param.length
            && data.len() != length
        {
            return Err(ConsoleError::param(
                format!(
                    "{name}: expected exactly {length} bytes, got {}",
                    data.len()
                ),
                name,
            ));
        }
        Ok(ParamValue::Bytes(data.to_vec()))
    }

    fn parse_keyref(&self, param: &ParamSpec, text: &str) -> Result<ParamValue> {
        let name = param.name.as_str();
        match self.providers.resolve_ref(py_strip(text)) {
            Ok((_provider, info)) => Ok(ParamValue::KeyRef(Box::new(info))),
            // §4.2: a catch-all never swallows or rewraps UserAbort.
            Err(err) if err.kind.is_user_abort() => Err(err),
            Err(err) => Err(
                ConsoleError::param(format!("{name}: {}", err.message), name)
                    .with_hint_opt(err.hint),
            ),
        }
    }
}
