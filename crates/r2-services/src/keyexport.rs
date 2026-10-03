// Key-export orchestration (spec §5.6, §4.9.10; owner R8) — c2 `services/keyexport.py`.
//
// Format resolution, the §5.6 sensitive-key refusal, public-part resolution and file
// writing. PKCS#12 assembly lives in `certops`. Re-serialization of the §4.3 canonical
// bytes goes through `r2_core::formats` (R6; pyca-identical writers).
use std::path::Path;

use r2_core::error::ConsoleError;
use r2_core::formats::{self, Encoding};
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo};
use r2_core::runtime::timed;
use r2_core::template::AttrValue;
use r2_core::text::{os_error_text, py_repr};
use r2_provider::Provider;
use secrecy::SecretString;
use zeroize::Zeroizing;

/// `export --format` values; "p12" is routed to certops.
pub const VALID_FORMATS: [&str; 5] = ["auto", "raw", "der", "pem", "p12"];

/// §5.6 defaults per object class when `--format auto`.
fn default_format(key_class: KeyClass) -> &'static str {
    match key_class {
        KeyClass::Secret | KeyClass::Data => "raw",
        KeyClass::Private | KeyClass::Public | KeyClass::Certificate => "pem",
    }
}

/// §5.6 pre-flight refusal (KeyNotExportable "Refusing to export: key '{ref}' is marked
/// sensitive/non-extractable." with the c2 hints).
pub fn refuse_non_exportable(key: &KeyInfo) -> r2_core::Result<()> {
    if !matches!(key.key_class, KeyClass::Secret | KeyClass::Private) || key.exportable {
        return Ok(());
    }
    let display = key.key_ref.display();
    let mut hints: Vec<String> = Vec::new();
    if key.key_class == KeyClass::Private {
        hints.push(format!(
            "public key available with `export {display} <path> --public`"
        ));
    }
    if key.attributes.get("CKA_EXTRACTABLE") != Some(&AttrValue::Bool(false)) {
        // §5.5: wrappable = CKA_EXTRACTABLE alone, so a merely SENSITIVE key can still
        // leave the token wrapped (§5.6 wrapped export).
        hints.push("an extractable key can leave wrapped: `export … --kek <kek>`".to_owned());
    }
    let hint = if hints.is_empty() {
        None
    } else {
        Some(hints.join("; "))
    };
    Err(ConsoleError::key_not_exportable(format!(
        "Refusing to export: key '{display}' is marked sensitive/non-extractable."
    ))
    .with_hint_opt(hint))
}

/// The PUBLIC (or, failing that, CERTIFICATE) object sharing CKA_ID/label.
pub fn find_public_part(
    provider: &dyn Provider,
    key: &KeyInfo,
) -> r2_core::Result<Option<KeyInfo>> {
    // buckets: public by id, public by label, certificate by id, certificate by label
    let mut buckets: [Option<KeyInfo>; 4] = [None, None, None, None];
    for info in provider.list_keys()? {
        let (id_bucket, label_bucket) = match info.key_class {
            KeyClass::Public => (0, 1),
            KeyClass::Certificate => (2, 3),
            _ => continue,
        };
        let bucket = if key.key_ref.key_id.is_some() && info.key_ref.key_id == key.key_ref.key_id {
            id_bucket
        } else if info.key_ref.label == key.key_ref.label {
            label_bucket
        } else {
            continue;
        };
        if buckets[bucket].is_none() {
            buckets[bucket] = Some(info);
        }
    }
    Ok(buckets.into_iter().flatten().next())
}

/// The DER SubjectPublicKeyInfo for any asymmetric object (§5.6/§5.7). PUBLIC → export
/// directly; CERTIFICATE → embedded SPKI; PRIVATE → the PUBLIC/CERTIFICATE object sharing
/// CKA_ID/label, else (exportable private) derived in software from its PKCS#8.
pub fn public_spki(provider: &dyn Provider, key: &KeyInfo) -> r2_core::Result<Vec<u8>> {
    match key.key_class {
        KeyClass::Public => return Ok(timed(|| provider.export_key(key))?.data.to_vec()),
        KeyClass::Certificate => {
            return formats::cert_spki(&timed(|| provider.export_key(key))?.data);
        }
        KeyClass::Private => {}
        other => {
            return Err(ConsoleError::unsupported(format!(
                "'{}' is a {} object and has no public part",
                key.key_ref.display(),
                other.as_str()
            )));
        }
    }
    if let Some(public) = find_public_part(provider, key)? {
        return public_spki(provider, &public);
    }
    if key.exportable {
        return formats::pkcs8_public_spki(&timed(|| provider.export_key(key))?.data);
    }
    Err(ConsoleError::key_not_found(format!(
        "no public part found for '{}'",
        key.key_ref.display()
    ))
    .with_hint(
        "the private key is not exportable and no public key or certificate shares its \
         label/CKA_ID",
    ))
}

/// §5.6 table → (payload, resolved format token).
pub fn export_bytes(
    provider: &dyn Provider,
    key: &KeyInfo,
    fmt: &str,
    public: bool,
    password: Option<&SecretString>,
) -> r2_core::Result<(Zeroizing<Vec<u8>>, &'static str)> {
    let Some(fmt) = VALID_FORMATS.iter().copied().find(|valid| *valid == fmt) else {
        return Err(ConsoleError::param(
            format!("unknown export format {}", py_repr(fmt)),
            "format",
        )
        .with_hint(format!("valid formats: {}", VALID_FORMATS.join(", "))));
    };
    if fmt == "p12" {
        return Err(ConsoleError::param(
            "PKCS#12 export is assembled by services/certops.py",
            "format",
        )
        .with_hint("the export command routes --format p12 through export_pkcs12()"));
    }
    // §5.6: only encrypted-PKCS#8 (private) and p12 outputs take a password — never
    // accept-and-ignore one on the public/secret/certificate paths.
    if password.is_some() && (public || key.key_class != KeyClass::Private) {
        return Err(ConsoleError::param(
            "--password applies only to private-key and p12 exports (§5.6)",
            "password",
        ));
    }
    if key.algorithm == KeyAlgorithm::Other {
        let key_type = key
            .attributes
            .get("CKA_KEY_TYPE")
            .map_or_else(|| "unknown".to_owned(), AttrValue::render_info);
        return Err(ConsoleError::unsupported(format!(
            "key type {key_type} of '{}' is not supported by r2 and cannot be exported",
            key.key_ref.display()
        ))
        .with_hint("objects of unsupported key types can be listed and deleted only"));
    }
    if public {
        return export_public(provider, key, fmt);
    }

    if matches!(key.key_class, KeyClass::Secret | KeyClass::Data) {
        if key.key_class == KeyClass::Secret {
            refuse_non_exportable(key)?;
        }
        if fmt != "auto" && fmt != "raw" {
            return Err(ConsoleError::param(
                format!(
                    "{} objects export as raw bytes, not {}",
                    key.key_class.as_str(),
                    py_repr(fmt)
                ),
                "format",
            )
            .with_hint("use --format raw (or omit --format)"));
        }
        return Ok((timed(|| provider.export_key(key))?.data, "raw"));
    }

    let resolved = if fmt == "auto" {
        default_format(key.key_class)
    } else {
        fmt
    };
    if resolved == "raw" {
        return Err(ConsoleError::param(
            format!(
                "{} objects export as pem or der, not raw",
                key.key_class.as_str()
            ),
            "format",
        ));
    }
    let encoding = if resolved == "pem" {
        Encoding::Pem
    } else {
        Encoding::Der
    };
    match key.key_class {
        KeyClass::Private => {
            refuse_non_exportable(key)?;
            let material = timed(|| provider.export_key(key))?;
            let payload = formats::private_key_bytes(&material.data, encoding, password)?;
            Ok((payload, resolved))
        }
        KeyClass::Public => {
            let material = timed(|| provider.export_key(key))?;
            let payload = formats::public_key_bytes(&material.data, encoding)?;
            Ok((Zeroizing::new(payload), resolved))
        }
        _ => {
            // CERTIFICATE: DER verbatim (c2 returned it unvalidated), PEM via pyca.
            let material = timed(|| provider.export_key(key))?;
            if encoding == Encoding::Der {
                return Ok((material.data, "der"));
            }
            let payload = formats::certificate_bytes(&material.data, Encoding::Pem)?;
            Ok((Zeroizing::new(payload), "pem"))
        }
    }
}

fn export_public(
    provider: &dyn Provider,
    key: &KeyInfo,
    fmt: &'static str,
) -> r2_core::Result<(Zeroizing<Vec<u8>>, &'static str)> {
    let spki = public_spki(provider, key)?;
    let resolved = if fmt == "auto" { "pem" } else { fmt };
    match resolved {
        "der" => Ok((Zeroizing::new(spki), "der")),
        "pem" => Ok((
            Zeroizing::new(formats::public_key_bytes(&spki, Encoding::Pem)?),
            "pem",
        )),
        _ => Err(ConsoleError::param("--public exports pem or der", "format")
            .with_hint("use --format pem or --format der with --public")),
    }
}

/// ★ (R14) Write a payload; DataIo "cannot write {path}: {err}".
pub fn write_output(path: &Path, data: &[u8]) -> r2_core::Result<()> {
    std::fs::write(path, data).map_err(|err| {
        ConsoleError::data_io(format!(
            "cannot write {}: {}",
            path.display(),
            os_error_text(&err)
        ))
    })
}
