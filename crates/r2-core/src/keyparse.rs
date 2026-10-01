// R0 skeleton — owner R6 (generated from spec §4)
use crate::error::{ConsoleError, Result};
use crate::keys::KeyMaterial;
use secrecy::SecretString;
use std::str::FromStr;

/// Type hint of `parse_key_material` (c2's frozen hint set). Token: "auto" | "aes" | "rsa" |
/// "ec" | "cert".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyHint {
    #[default]
    Auto,
    Aes,
    Rsa,
    Ec,
    Cert,
}
impl KeyHint {
    pub fn as_str(self) -> &'static str {
        unimplemented!("R6")
    }
}
/// Exact tokens; else KeyParse "unknown key material hint {s!r}" (hint "valid hints: auto,
/// aes, rsa, ec, cert").
impl FromStr for KeyHint {
    type Err = ConsoleError;
    fn from_str(s: &str) -> Result<Self> {
        let _ = s;
        Err(crate::error::ConsoleError::not_implemented("R6"))
    }
}

/// Password source. Argument = prompt text ("Password for encrypted {PEM label}",
/// "Password for encrypted private key", "Password for PKCS#12"). It may fail (e.g.
/// UserAbort from a prompt); the error propagates unchanged.
pub type PasswordCallback<'a> = &'a mut dyn FnMut(&str) -> Result<SecretString>;

/// Sniff and parse key material. Errors → KeyParse (listing attempted formats).
pub fn parse_key_material(
    data: &[u8],
    hint: KeyHint,
    password: Option<PasswordCallback<'_>>,
) -> Result<Vec<KeyMaterial>> {
    let _ = (data, hint, password);
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
