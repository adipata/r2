// Key copy orchestration via wrap/unwrap (spec §5.5) — owner R10. Port of c2
// services/transfer.py.
//
// The method is chosen by `Provider::type_name()` per the §5.5 decision matrix:
//
//   memory → memory          plain export/import of canonical material
//   memory → pkcs11          export → template editor → import
//   pkcs11 → memory/pkcs11   transport-key protocol + fallback ladder (below)
//   cert/public/data (any)   plain export/import, no wrapping
//
// Probe order (binding): AuthState on both providers first (a logged-out PKCS#11 provider
// is AuthRequired — never a misleading "lacks mechanism" error from its empty
// `mechanisms()` set); then the whole ladder is evaluated via `mechanisms()` before
// anything touches a token, and only when no path exists at all is ONE clear error raised
// naming the best missing mechanisms.
//
// Ladder for pkcs11-type sources: AES-256 transport key via AES-KEY-WRAP-PAD (plain
// AES-KEY-WRAP only for 8-byte-aligned secrets) → ephemeral RSA-2048 session keypair on
// the destination + RSA-OAEP (secret targets; op defaults hash=sha256/mgf=sha256/label="")
// → RSA-AES-KEY-WRAP single shot when BOTH sides advertise it (any target class) → plain
// read (only for exportable keys, behind an explicit warning that key material transits
// process memory).
//
// Copyability: exportable = extractable ∧ ¬sensitive (plain-value read allowed);
// wrappable = CKA_EXTRACTABLE alone — sensitive-but-extractable keys are copied by
// wrapping, never plain-read.
//
// Ephemeral transport objects are destroyed on success AND failure (an explicit cleanup
// step whose UserAbort wins, as an interrupt in c2's `finally` did, plus a `Drop` guard
// as the backstop for early returns; while a panic unwinds the guard makes no provider
// call (spec §4 unwind-safety) and session objects die with the session), and the
// software transport key lives in a `Zeroizing`
// buffer (§11 D3). Ctrl-C is honored at the step boundaries (§11 D13). Services never
// print; confirmations go through `ConsoleIo`; key bytes are never logged.
use r2_core::crypto::random_bytes;
use r2_core::error::{ConsoleError, Result};
use r2_core::io::ConsoleIo;
use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial};
use r2_core::params::{ParamValue, Params};
use r2_core::runtime::{check_interrupt, timed};
use r2_core::template::{AttrKind, AttrValue, KeyTemplate, TemplateAttr};
use r2_provider::mechanism::{AES_KEY_WRAP, AES_KEY_WRAP_PAD, RSA_AES_KEY_WRAP, RSA_OAEP};
use r2_provider::{
    AuthState, GenerateRequest, MechanismInvocation, Provider, UnwrapRequest, WrapOptions,
};
use zeroize::Zeroizing;

use crate::templatefile::{EditorSeeding, build_seed};

pub const TRANSPORT_PREFIX: &str = "r2-transport-";

/// §5.5 decision matrix, ladder, refusal UX; transport keys are destroyed on success AND
/// failure (Drop guard) and their software bytes are `Zeroizing`.
///
/// `label` defaults to the source label. CKA_ID: an explicit `key_id` (`--id`) wins, then
/// an operator template row; with neither, a pkcs11→pkcs11 copy onto a DIFFERENT token
/// inherits the source object's CKA_ID, and otherwise PKCS#11 destinations generate a
/// fresh random 4-byte CKA_ID. `seeding.seeds` (§5.16 `--template` sections) seeds the
/// destination editor in place of the config defaults.
pub fn copy_key(
    source: &dyn Provider,
    key: &KeyInfo,
    dest: &dyn Provider,
    io: &dyn ConsoleIo,
    seeding: &EditorSeeding<'_>,
    label: Option<&str>,
    key_id: Option<&[u8]>,
) -> r2_core::Result<KeyInfo> {
    let dest_label = label.unwrap_or(&key.key_ref.label);
    require_auth(source)?;
    require_auth(dest)?;
    if key.algorithm == KeyAlgorithm::Other {
        let key_type = key
            .attributes
            .get("CKA_KEY_TYPE")
            .map_or_else(|| "unknown".to_owned(), AttrValue::render_info);
        return Err(ConsoleError::unsupported(format!(
            "key type {key_type} of '{}' is not supported by r2 and cannot be copied",
            key.key_ref.display()
        ))
        .with_hint("objects of unsupported key types can be listed and deleted only"));
    }
    let inherited = inherited_source_id(source, key, dest);
    let copy = CopyJob {
        source,
        dest,
        seeding,
        key_id,
    };
    if matches!(
        key.key_class,
        KeyClass::Public | KeyClass::Certificate | KeyClass::Data
    ) {
        // §5.5 matrix: certificates/public keys/data objects travel as plain material.
        return copy.plain(key, dest_label, inherited.as_deref());
    }
    if source.type_name() == "pkcs11" {
        return copy.pkcs11_source(key, io, label, inherited.as_deref());
    }
    // memory-type source (§5.5 matrix): plain export/import.
    if !key.exportable {
        return copy.refuse_or_offer_public(key, io, label);
    }
    copy.plain(key, dest_label, None)
}

// ---------------------------------------------------------------------------------------
// auth pre-probe & route selection
// ---------------------------------------------------------------------------------------

/// §5.5 probe order: auth first, so an empty logged-out `mechanisms()` never masquerades
/// as a capability problem.
fn require_auth(provider: &dyn Provider) -> Result<()> {
    if provider.status().auth == AuthState::LoggedOut {
        let name = provider.name();
        return Err(
            ConsoleError::auth_required(format!("provider '{name}' is not logged in"))
                .with_hint(format!("run `login {name}` first")),
        );
    }
    Ok(())
}

/// §5.5: a pkcs11→pkcs11 copy onto a DIFFERENT token inherits the copied object's CKA_ID;
/// same-token copies keep the fresh id so `label#id` stays unambiguous (§4.3).
fn inherited_source_id(
    source: &dyn Provider,
    key: &KeyInfo,
    dest: &dyn Provider,
) -> Option<Vec<u8>> {
    if source.type_name() != "pkcs11" || dest.type_name() != "pkcs11" {
        return None;
    }
    if key.key_class == KeyClass::Data {
        return None; // data objects carry no CKA_ID (§4.3)
    }
    if source.status().token == dest.status().token {
        return None;
    }
    key.key_ref.key_id.clone()
}

/// `--id` > template CKA_ID row > inherited source id > provider default (§4.7/§5.5).
/// Inheritance yields to an operator template row so it never turns the row into a bogus
/// `--id` conflict at the provider.
fn final_key_id(
    requested: Option<&[u8]>,
    inherited: Option<&[u8]>,
    template: Option<&KeyTemplate>,
) -> Option<Vec<u8>> {
    if let Some(requested) = requested {
        return Some(requested.to_vec());
    }
    let inherited = inherited?;
    if template
        .and_then(|template| template.get("CKA_ID"))
        .is_some_and(|row| row.enabled)
    {
        return None;
    }
    Some(inherited.to_vec())
}

/// Python truthiness of a CKA_* snapshot value (c2 `bool(...)`).
fn truthy(value: &AttrValue) -> bool {
    match value {
        AttrValue::Bool(value) => *value,
        AttrValue::Ulong(value) => *value != 0,
        AttrValue::Bytes(value) => !value.is_empty(),
        AttrValue::Str(value) | AttrValue::Symbol(value) => !value.is_empty(),
    }
}

/// Plain AES-KEY-WRAP (no pad) fits only 8-byte-aligned secrets >= 16 bytes.
fn kw_alignment_ok(key: &KeyInfo) -> bool {
    if key.key_class != KeyClass::Secret {
        return false;
    }
    let Some(bits) = key.size_bits else {
        return false;
    };
    let size = bits / 8;
    size >= 16 && size % 8 == 0
}

/// One clear error naming the best missing mechanisms per side (§5.5).
fn missing_mechanism_message(
    key: &KeyInfo,
    sides: [(&dyn Provider, &std::collections::BTreeSet<String>); 2],
) -> String {
    let mut needed = vec![AES_KEY_WRAP_PAD];
    if key.key_class == KeyClass::Secret {
        needed.push(RSA_OAEP);
    }
    needed.push(RSA_AES_KEY_WRAP);
    let parts: Vec<String> = sides
        .iter()
        .filter_map(|(provider, mechs)| {
            let missing: Vec<&str> = needed
                .iter()
                .copied()
                .filter(|name| !mechs.contains(*name))
                .collect();
            (!missing.is_empty())
                .then(|| format!("{} lacks {}", provider.name(), missing.join(" and ")))
        })
        .collect();
    let detail = if parts.is_empty() {
        "no common wrap mechanism".to_owned()
    } else {
        parts.join("; ")
    };
    format!("cannot copy: {detail}")
}

// ---------------------------------------------------------------------------------------
// the copy itself
// ---------------------------------------------------------------------------------------

/// The fixed context of one `copy_key` call.
struct CopyJob<'a> {
    source: &'a dyn Provider,
    dest: &'a dyn Provider,
    seeding: &'a EditorSeeding<'a>,
    /// The operator's `--id`.
    key_id: Option<&'a [u8]>,
}

impl<'a> CopyJob<'a> {
    /// pkcs11-type source: the §5.5 wrap ladder, then plain read, then refusal. `label` is
    /// the raw operator override (None = default): the refusal path distinguishes "no
    /// --label" (the PUBLIC part's own label) from an explicit override, and re-derives
    /// its inherited id from the public part itself.
    fn pkcs11_source(
        &self,
        key: &KeyInfo,
        io: &dyn ConsoleIo,
        label: Option<&str>,
        inherited: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        let wrappable = key
            .attributes
            .get("CKA_EXTRACTABLE")
            .map_or(key.exportable, truthy);
        if !wrappable {
            return self.refuse_or_offer_public(key, io, label);
        }
        let dest_label = label.unwrap_or(&key.key_ref.label);
        let src_mechs = self.source.mechanisms();
        let dst_mechs = self.dest.mechanisms();
        let common = |name: &str| src_mechs.contains(name) && dst_mechs.contains(name);

        let route = if common(AES_KEY_WRAP_PAD) {
            AES_KEY_WRAP_PAD
        } else if common(AES_KEY_WRAP) && kw_alignment_ok(key) {
            AES_KEY_WRAP
        } else if key.key_class == KeyClass::Secret && common(RSA_OAEP) {
            RSA_OAEP
        } else if common(RSA_AES_KEY_WRAP) {
            // §5.5 single-shot hybrid — gated on the mechanisms() probe of BOTH sides,
            // never on a version check; covers private-key targets too.
            RSA_AES_KEY_WRAP
        } else if key.exportable {
            // Plain read, last resort: exportable keys only, explicit warning.
            let warning = format!(
                "No wrap route is available — the key material of '{}' will transit process memory in plaintext. Continue?",
                key.key_ref.display()
            );
            if !io.confirm(&warning, false)? {
                return Err(ConsoleError::user_abort("copy aborted"));
            }
            tracing::info!(
                "copy {} -> {}: plain-read last resort (no wrap route)",
                key.key_ref.display(),
                self.dest.name()
            );
            return self.plain(key, dest_label, inherited);
        } else {
            return Err(ConsoleError::unsupported(missing_mechanism_message(
                key,
                [(self.source, &src_mechs), (self.dest, &dst_mechs)],
            ))
            .with_hint(
                "the source must wrap and the destination must unwrap with a common mechanism (§5.5)",
            ));
        };
        tracing::info!(
            "copy {} ({}/{}) -> {} via {}",
            key.key_ref.display(),
            key.key_class.as_str(),
            key.algorithm.as_str(),
            self.dest.name(),
            route
        );
        check_interrupt()?; // §11 D13: before the first token object is created
        let mut guard = EphemeralObjects::default();
        let result = if route == AES_KEY_WRAP_PAD || route == AES_KEY_WRAP {
            self.aes_transport(&mut guard, key, route, dest_label, inherited)
        } else {
            self.rsa_transport(&mut guard, key, route, dest_label, inherited)
        };
        // §5.5 step 4: success AND error paths — destroy on both sides. An abort raised
        // by the cleanup itself wins (c2: a KeyboardInterrupt inside `finally`).
        match guard.destroy_all() {
            Some(abort) => Err(abort),
            None => result,
        }
    }

    /// The plain route (memory sources, public/cert/data objects, last-resort read).
    fn plain(&self, key: &KeyInfo, label: &str, inherited: Option<&[u8]>) -> Result<KeyInfo> {
        let material = timed(|| self.source.export_key(key))?; // §11 D31: provider time
        check_interrupt()?; // §11 D13: between the export and the destination calls
        let extra_rows = if key.key_class == KeyClass::Data {
            data_attr_rows(key)
        } else {
            Vec::new()
        };
        let template = self.edited_template(key.key_class, key.algorithm, label, &extra_rows)?;
        let key_id = final_key_id(self.key_id, inherited, template.as_ref());
        let info = timed(|| {
            self.dest
                .import_key(&material, label, template.as_ref(), key_id.as_deref())
        })?;
        tracing::info!(
            "copied {} -> {} (plain material)",
            key.key_ref.display(),
            info.key_ref.display()
        );
        Ok(info)
    }

    /// §5.12: the editor runs before every copy targeting a PKCS#11 provider, seeded via
    /// `templatefile::build_seed` (§5.16 `--template` section when given, else
    /// `TemplatesSection::default_template` — same as load/generate). `extra_rows`
    /// (data-object extras) override/append seed rows by name.
    fn edited_template(
        &self,
        key_class: KeyClass,
        algorithm: KeyAlgorithm,
        label: &str,
        extra_rows: &[TemplateAttr],
    ) -> Result<Option<KeyTemplate>> {
        edited_template(
            self.dest,
            self.seeding,
            key_class,
            algorithm,
            label,
            extra_rows,
        )
    }

    /// Refusal UX (§5.5): offer the public part, then raise. `label` is the raw operator
    /// override: an explicit `--label` wins even for the offered public part; otherwise
    /// the public part keeps its own label. The inherited-id default likewise uses the
    /// public part's OWN CKA_ID.
    fn refuse_or_offer_public(
        &self,
        key: &KeyInfo,
        io: &dyn ConsoleIo,
        label: Option<&str>,
    ) -> Result<KeyInfo> {
        if let Some(public) = find_public_part(self.source, key)? {
            let question = format!(
                "key '{}' cannot be copied; copy its {} part '{}' instead?",
                key.key_ref.display(),
                public.key_class.as_str(),
                public.key_ref.display()
            );
            if io.confirm(&question, false)? {
                let inherited = inherited_source_id(self.source, &public, self.dest);
                let label = label.unwrap_or(&public.key_ref.label);
                return self.plain(&public, label, inherited.as_deref());
            }
        }
        Err(ConsoleError::key_not_exportable(format!(
            "key '{}' is non-extractable on this token and cannot be copied",
            key.key_ref.label
        ))
        .with_hint("only its public part (if any) can leave the token"))
    }

    /// Transport-key protocol (§5.5), ephemeral AES route: wrap under a software AES-256
    /// transport key created on BOTH tokens. Acceptable because the transport key is
    /// single-use; the target key never appears in plaintext (§5.5 step 1).
    fn aes_transport(
        &self,
        guard: &mut EphemeralObjects<'a>,
        key: &KeyInfo,
        mech_name: &str,
        label: &str,
        inherited: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        let transport_label = transport_label()?;
        let transport: Zeroizing<Vec<u8>> = random_bytes(32)?;
        let mut material = KeyMaterial::new(KeyAlgorithm::Aes, KeyClass::Secret, Vec::new());
        material.data = transport;
        material.size_bits = Some(256);
        let src_t = timed(|| {
            self.source.import_key(
                &material,
                &transport_label,
                Some(&transport_template(&["CKA_WRAP"])),
                None,
            )
        })?;
        guard.add(self.source, src_t.clone());
        let dst_t = timed(|| {
            self.dest.import_key(
                &material,
                &transport_label,
                Some(&transport_template(&["CKA_UNWRAP"])),
                None,
            )
        })?;
        guard.add(self.dest, dst_t.clone());
        drop(material); // the software transport key is wiped here (Zeroizing)
        let mech = MechanismInvocation::new(mech_name, Params::new());
        self.wrap_then_unwrap(key, &src_t, &dst_t, &mech, label, inherited)
    }

    /// Ephemeral-RSA routes (§5.5): OAEP fallback and RSA-AES-KEY-WRAP single shot. An
    /// ephemeral RSA-2048 session keypair on the DESTINATION; its public key is imported
    /// into the source as the wrapping key; the private half never leaves the destination.
    fn rsa_transport(
        &self,
        guard: &mut EphemeralObjects<'a>,
        key: &KeyInfo,
        mech_name: &str,
        label: &str,
        inherited: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        let transport_label = transport_label()?;
        // c2's cleanup order: source public, destination private, destination public.
        let src_slot = guard.reserve(self.source);
        let mut request = GenerateRequest::new(KeyAlgorithm::Rsa, transport_label.clone());
        request.size_bits = Some(2048);
        request.template = Some(transport_template(&["CKA_UNWRAP", "CKA_DECRYPT"]));
        request.public_template = Some(public_transport_template());
        let dst_priv = timed(|| self.dest.generate_key(&request))?;
        guard.add(self.dest, dst_priv.clone());
        // generate_key returns only the private KeyInfo (§4.5) — the public half is
        // retrieved via list_keys() filtered by label + PUBLIC (§5.5).
        let dst_pub = find_generated_public(self.dest, &transport_label)?;
        guard.add(self.dest, dst_pub.clone());
        let public_material = timed(|| self.dest.export_key(&dst_pub))?;
        let src_pub = timed(|| {
            self.source.import_key(
                &public_material,
                &transport_label,
                Some(&public_transport_template()),
                None,
            )
        })?;
        guard.fill(src_slot, src_pub.clone());
        let mech = MechanismInvocation::new(mech_name, oaep_defaults());
        self.wrap_then_unwrap(key, &src_pub, &dst_priv, &mech, label, inherited)
    }

    /// Steps 2–3 shared by every transport route: wrap on the source, editor, unwrap on
    /// the destination.
    fn wrap_then_unwrap(
        &self,
        key: &KeyInfo,
        wrapping_key: &KeyInfo,
        unwrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        label: &str,
        inherited: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        check_interrupt()?; // §11 D13
        let blob = timed(|| {
            self.source
                .wrap_key(wrapping_key, mech, key, &WrapOptions::default())
        })?;
        check_interrupt()?; // §11 D13
        let template = self.edited_template(key.key_class, key.algorithm, label, &[])?;
        let mut request = UnwrapRequest::new(key.algorithm, key.key_class, label);
        request.key_id = final_key_id(self.key_id, inherited, template.as_ref());
        request.template = template;
        let info = timed(|| self.dest.unwrap_key(unwrapping_key, mech, &blob, &request))?;
        tracing::info!(
            "copied {} -> {} ({}, {}-byte blob)",
            key.key_ref.display(),
            info.key_ref.display(),
            mech.mechanism,
            blob.len()
        );
        Ok(info)
    }
}

/// See `CopyJob::edited_template` (free function so the data-extras seeding is testable).
fn edited_template(
    dest: &dyn Provider,
    seeding: &EditorSeeding<'_>,
    key_class: KeyClass,
    algorithm: KeyAlgorithm,
    label: &str,
    extra_rows: &[TemplateAttr],
) -> Result<Option<KeyTemplate>> {
    if dest.type_name() != "pkcs11" {
        return Ok(None);
    }
    let mut seed = build_seed(seeding.templates, seeding.seeds, key_class, algorithm)?;
    for row in extra_rows {
        match seed.get_mut(&row.name) {
            Some(existing) => {
                existing.value = row.value.clone();
                existing.enabled = true;
            }
            None => seed.attrs.push(row.clone()),
        }
    }
    let what = if key_class == KeyClass::Data {
        key_class.as_str().to_owned()
    } else {
        format!("{} {}", key_class.as_str(), algorithm.as_str())
    };
    let title = format!("template for {}:{label} ({what})", dest.name());
    seeding.editor.edit(seed, &title).map(Some)
}

/// CKO_DATA extras travel with a copy: pre-seed CKA_APPLICATION / CKA_OBJECT_ID editor
/// rows from the source object's attribute snapshot (§5.5).
fn data_attr_rows(key: &KeyInfo) -> Vec<TemplateAttr> {
    let mut rows = Vec::new();
    if let Some(AttrValue::Str(application)) = key.attributes.get("CKA_APPLICATION")
        && !application.is_empty()
    {
        rows.push(TemplateAttr::new(
            "CKA_APPLICATION",
            AttrKind::Str,
            AttrValue::Str(application.clone()),
        ));
    }
    if let Some(AttrValue::Bytes(object_id)) = key.attributes.get("CKA_OBJECT_ID")
        && !object_id.is_empty()
    {
        rows.push(TemplateAttr::new(
            "CKA_OBJECT_ID",
            AttrKind::Bytes,
            AttrValue::Bytes(object_id.clone()),
        ));
    }
    rows
}

/// A PUBLIC (preferred) or CERTIFICATE object sharing the key's CKA_ID/label.
fn find_public_part(source: &dyn Provider, key: &KeyInfo) -> Result<Option<KeyInfo>> {
    let mut best: Option<(u8, KeyInfo)> = None;
    for info in source.list_keys()? {
        if !matches!(info.key_class, KeyClass::Public | KeyClass::Certificate) {
            continue;
        }
        let same_id = key.key_ref.key_id.is_some() && info.key_ref.key_id == key.key_ref.key_id;
        let same_label = info.key_ref.label == key.key_ref.label;
        if !(same_id || same_label) {
            continue;
        }
        let rank = if info.key_class == KeyClass::Public {
            0
        } else {
            2
        } + u8::from(!same_id);
        if best.as_ref().is_none_or(|(best_rank, _)| rank < *best_rank) {
            best = Some((rank, info));
        }
    }
    Ok(best.map(|(_, info)| info))
}

fn find_generated_public(dest: &dyn Provider, label: &str) -> Result<KeyInfo> {
    dest.list_keys()?
        .into_iter()
        .find(|info| info.key_ref.label == label && info.key_class == KeyClass::Public)
        .ok_or_else(|| {
            ConsoleError::key_not_found(format!(
                "ephemeral transport keypair '{label}' has no public half on {}",
                dest.name()
            ))
        })
}

// ---------------------------------------------------------------------------------------
// ephemeral-object templates & cleanup
// ---------------------------------------------------------------------------------------

/// "r2-transport-" + 8 random lower-case hex digits (c2 `secrets.token_hex(4)`, §11 D7).
fn transport_label() -> Result<String> {
    let suffix: String = random_bytes(4)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("{TRANSPORT_PREFIX}{suffix}"))
}

/// §5.5: transport wraps use the RSA-OAEP op defaults.
fn oaep_defaults() -> Params {
    let mut params = Params::new();
    params.insert("hash".into(), ParamValue::Enum("sha256".into()));
    params.insert("mgf_hash".into(), ParamValue::Enum("sha256".into()));
    params.insert("label".into(), ParamValue::Bytes(Vec::new()));
    params
}

fn bool_attr(name: &str, value: bool) -> TemplateAttr {
    TemplateAttr::new(name, AttrKind::Bool, AttrValue::Bool(value))
}

/// Session object (CKA_TOKEN=false), never readable, single-purpose.
fn transport_template(usages: &[&str]) -> KeyTemplate {
    let mut attrs = vec![
        bool_attr("CKA_TOKEN", false),
        bool_attr("CKA_PRIVATE", true),
        bool_attr("CKA_SENSITIVE", true),
        bool_attr("CKA_EXTRACTABLE", false),
    ];
    attrs.extend(usages.iter().map(|usage| bool_attr(usage, true)));
    KeyTemplate::new(attrs)
}

fn public_transport_template() -> KeyTemplate {
    KeyTemplate::new(vec![
        bool_attr("CKA_TOKEN", false),
        bool_attr("CKA_PRIVATE", false),
        bool_attr("CKA_WRAP", true),
        bool_attr("CKA_ENCRYPT", true),
    ])
}

/// The ephemeral objects of one transport route, destroyed in slot order. The normal path
/// calls `destroy_all` (success and failure alike); `Drop` is the backstop that still
/// destroys whatever is left when the flow unwinds.
#[derive(Default)]
struct EphemeralObjects<'a> {
    slots: Vec<(&'a dyn Provider, Option<KeyInfo>)>,
}

impl<'a> EphemeralObjects<'a> {
    fn add(&mut self, provider: &'a dyn Provider, info: KeyInfo) {
        self.slots.push((provider, Some(info)));
    }
    /// An empty slot destroyed in this position once filled.
    fn reserve(&mut self, provider: &'a dyn Provider) -> usize {
        self.slots.push((provider, None));
        self.slots.len() - 1
    }
    fn fill(&mut self, slot: usize, info: KeyInfo) {
        if let Some((_, entry)) = self.slots.get_mut(slot) {
            *entry = Some(info);
        }
    }
    /// Destroy every object; returns the first UserAbort a provider raised (never
    /// swallowed, §4.2) — every other failure is logged and ignored (c2 `_destroy_quietly`).
    fn destroy_all(&mut self) -> Option<ConsoleError> {
        let mut abort = None;
        for (provider, entry) in &mut self.slots {
            if let Some(info) = entry.take()
                && let Some(err) = destroy_quietly(*provider, &info)
                && abort.is_none()
            {
                abort = Some(err);
            }
        }
        abort
    }
}

impl Drop for EphemeralObjects<'_> {
    fn drop(&mut self) {
        // spec §4 unwind-safety: no provider calls while unwinding (a provider RefCell may
        // still be borrowed by a panicking frame); session objects die with the session.
        if std::thread::panicking() {
            return;
        }
        let _ = self.destroy_all();
    }
}

/// Best-effort destroy of an ephemeral object; session objects also die with the session
/// as a backstop (§5.5). Returns a UserAbort unchanged, logs anything else.
fn destroy_quietly(provider: &dyn Provider, info: &KeyInfo) -> Option<ConsoleError> {
    match provider.delete_key(info) {
        Ok(()) => None,
        Err(err) if err.kind.is_user_abort() => Some(err),
        Err(err) => {
            tracing::warn!(
                "could not destroy ephemeral object {}: {}",
                info.key_ref.display(),
                err.message
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    // Port of c2 tests/unit/services/test_objects_services.py
    // `test_copy_seeds_data_extras_into_the_editor` (private helpers: `_data_attr_rows`,
    // `_edited_template`).
    #![allow(clippy::unwrap_used)]
    use std::collections::BTreeMap;

    use r2_core::keys::{KeyAlgorithm, KeyClass, KeyInfo, KeyRef};
    use r2_core::template::{AttrKind, AttrValue};
    use r2_testkit::{FakeProvider, RecordingEditor};

    use super::{data_attr_rows, edited_template};
    use crate::templatefile::EditorSeeding;

    #[test]
    fn test_copy_seeds_data_extras_into_the_editor() {
        let hsm = FakeProvider::new("hsm").with_type_name("pkcs11");
        let mut attributes = BTreeMap::new();
        attributes.insert("CKA_APPLICATION".to_owned(), AttrValue::Str("acme".into()));
        attributes.insert(
            "CKA_OBJECT_ID".to_owned(),
            AttrValue::Bytes(vec![0x2a, 0x2b]),
        );
        let mut source = KeyInfo {
            key_ref: KeyRef::new("src", "blob", None),
            key_class: KeyClass::Data,
            algorithm: KeyAlgorithm::None,
            size_bits: Some(8),
            curve: None,
            exportable: true,
            attributes,
            handle: None,
        };
        let rows = data_attr_rows(&source);
        let summary: Vec<(&str, AttrKind, AttrValue)> = rows
            .iter()
            .map(|r| (r.name.as_str(), r.kind, r.value.clone()))
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "CKA_APPLICATION",
                    AttrKind::Str,
                    AttrValue::Str("acme".into())
                ),
                (
                    "CKA_OBJECT_ID",
                    AttrKind::Bytes,
                    AttrValue::Bytes(vec![0x2a, 0x2b])
                ),
            ]
        );
        let editor = RecordingEditor::new();
        let config = r2_config::loader::config_from_yaml(None).unwrap();
        let seeding = EditorSeeding {
            editor: &editor,
            templates: &config.templates,
            seeds: None,
        };
        let template = edited_template(
            &hsm,
            &seeding,
            KeyClass::Data,
            KeyAlgorithm::None,
            "blob",
            &rows,
        )
        .unwrap()
        .unwrap();
        let app = template.get("CKA_APPLICATION").unwrap();
        let oid = template.get("CKA_OBJECT_ID").unwrap();
        assert!(app.value == AttrValue::Str("acme".into()) && app.enabled);
        assert!(oid.value == AttrValue::Bytes(vec![0x2a, 0x2b]) && oid.enabled);
        assert!(template.get("CKA_KEY_TYPE").is_none()); // data objects have no key type
        assert_eq!(editor.titles(), ["template for hsm:blob (data)"]);
        source.attributes.clear();
        assert!(data_attr_rows(&source).is_empty());
        // empty values and other value types are not extras
        source
            .attributes
            .insert("CKA_APPLICATION".to_owned(), AttrValue::Str(String::new()));
        source
            .attributes
            .insert("CKA_OBJECT_ID".to_owned(), AttrValue::Str("2a".into()));
        assert!(data_attr_rows(&source).is_empty());
    }

    #[test]
    fn extras_override_an_existing_seed_row_and_reenable_it() {
        let hsm = FakeProvider::new("hsm").with_type_name("pkcs11");
        let config = r2_config::loader::config_from_yaml(Some(
            "templates:\n  pkcs11:\n    data:\n      CKA_APPLICATION: default-app\n",
        ))
        .unwrap();
        let editor = RecordingEditor::new();
        let seeding = EditorSeeding {
            editor: &editor,
            templates: &config.templates,
            seeds: None,
        };
        let rows = vec![r2_core::template::TemplateAttr::new(
            "CKA_APPLICATION",
            AttrKind::Str,
            AttrValue::Str("acme".into()),
        )];
        let template = edited_template(
            &hsm,
            &seeding,
            KeyClass::Data,
            KeyAlgorithm::None,
            "blob",
            &rows,
        )
        .unwrap()
        .unwrap();
        let apps: Vec<_> = template
            .attrs
            .iter()
            .filter(|a| a.name == "CKA_APPLICATION")
            .collect();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].value, AttrValue::Str("acme".into()));
        // a memory destination never opens the editor
        let mem = FakeProvider::new("mem");
        assert!(
            edited_template(
                &mem,
                &seeding,
                KeyClass::Data,
                KeyAlgorithm::None,
                "b",
                &rows
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(editor.titles().len(), 1);
    }
}
