//! MemoryProvider — the in-process software provider over OpenSSL (spec §4.5.5, loop R4;
//! port of c2 `providers/memory.py`).
//!
//! Implements every §5.8–§5.10 mechanism (incl. the hand-rolled RSA-RAW modexp and the
//! GMAC-as-GCM construction), key generation, certificate objects with
//! cert-as-public-key resolution (§4.3/§5.11), generic secrets and data objects, the §4.7
//! twin guard, and wrap/unwrap for the copy flow and `--kek` (§5.4/§5.5): AES-KW(-PAD)
//! with the dual-dialect PAD unwrap, AES-CBC/AES-GCM, RSA-OAEP/PKCS1, and the
//! `RSA-AES-KEY-WRAP` single-shot hybrid in c2's blob format
//! (`OAEP(ephemeral AES-256) ‖ KWP(ephemeral, payload)`).
//!
//! Byte formats at the provider boundary are the §4.3 canonical table. ECDSA signatures
//! cross the boundary as fixed-width `r‖s` (§4.5.4); GCM ciphertexts are `ct‖tag` (§5.8).
//! RSA-RAW is a diagnostic feature and NOT constant-time (§5.8). Secret key bytes live in
//! `Zeroizing` buffers; private keys in OpenSSL `PKey`s (freed with the BN_clear_free of
//! OpenSSL's key types).
#![forbid(unsafe_code)]

mod engine;
mod material;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::rc::Rc;

use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use r2_core::crypto::{ct_eq, random_bytes};
use r2_core::der::{ecdsa_der_to_rs, ecdsa_rs_to_der};
use r2_core::error::{ConsoleError, Result};
use r2_core::keys::{Curve, KeyAlgorithm, KeyClass, KeyInfo, KeyMaterial, KeyRef};
use r2_core::params::{Params, param_choice, param_int};
use r2_core::template::{AttrValue, KeyTemplate};
use r2_core::text::py_repr;
use r2_core::x509info;
use r2_provider::lookup::{duplicate_identity, matches_selector, select_match};
use r2_provider::mechanism::CANONICAL_MECHANISMS;
use r2_provider::rsa_raw::rsa_raw_modexp;
use r2_provider::{
    AttrEditOutcome, AuthState, DeriveResult, GenerateRequest, KeyEditResult, KeySelector,
    MechanismInvocation, Provider, ProviderStatus, UnwrapRequest, WrapOptions,
};
use zeroize::Zeroizing;

use crate::engine::Oaep;
use crate::material::{Parsed, Payload};

const AES_CIPHER_MECHS: [&str; 4] = ["AES-ECB", "AES-CBC", "AES-CTR", "AES-GCM"];
const RSA_CIPHER_MECHS: [&str; 3] = ["RSA-OAEP", "RSA-PKCS1", "RSA-RAW"];
const MAC_MECHS: [&str; 3] = ["AES-CMAC", "AES-GMAC", "HMAC"];
const RSA_SIGN_MECHS: [&str; 3] = ["RSA-PKCS1", "RSA-PSS", "RSA-RAW"];
const WRAP_MECHS: [&str; 7] = [
    "AES-KEY-WRAP",
    "AES-KEY-WRAP-PAD",
    "AES-CBC",
    "AES-GCM",
    "RSA-OAEP",
    "RSA-PKCS1",
    "RSA-AES-KEY-WRAP",
];
const AES_KEY_BITS: [u32; 3] = [128, 192, 256];
/// Generic secret sizes accepted by `generate_key` (bits; whole bytes, 1..=1024 B).
const GENERIC_MIN_BITS: u32 = 8;
const GENERIC_MAX_BITS: u32 = 8192;

const CERT_VERB_HINT: &str = "certificates stand in for PUBLIC keys only (encrypt/verify/wrap)";
const KW_WRAP_HINT: &str =
    "AES-KEY-WRAP needs an 8-byte-aligned payload of >= 16 bytes; use AES-KEY-WRAP-PAD otherwise";
const KW_PAD_HINT: &str =
    "CKM_AES_KEY_WRAP_PAD has two wire dialects (RFC 5649 vs RFC 3394+PKCS#7) — both were tried";
const EXPORT_HINT: &str = "CKA_SENSITIVE/CKA_EXTRACTABLE forbid a plain-value read (§5.5)";
const EC_PEER_TEXT: &str = "peer is not SPKI DER or an uncompressed EC point (0x04‖X‖Y)";

/// The detail appended to a c2 prefix where c2 appended a pyca exception text (§11 D11):
/// the reason of the first OpenSSL error, never `ErrorStack`'s build-specific `Display`.
pub(crate) fn ossl_reason(err: &ErrorStack) -> String {
    err.errors()
        .first()
        .and_then(|e| e.reason())
        .map_or_else(|| "unknown error".to_owned(), str::to_owned)
}

/// One in-memory object (c2 `_StoredKey`).
#[derive(Clone)]
struct Stored {
    info: KeyInfo,
    payload: Payload,
}

/// Software key store + crypto backend over OpenSSL (spec §4.5.5).
pub struct MemoryProvider {
    name: String,
    /// Insertion order = `list_keys` / `find_key` provider order. Never borrowed across a
    /// call out of this provider (it makes none).
    keys: RefCell<Vec<Stored>>,
    /// Providers are `!Send`/`!Sync` (spec §6).
    _single_thread: PhantomData<Rc<()>>,
}

impl MemoryProvider {
    /// type_name "memory"; AuthState::NotRequired; advertises every canonical mechanism
    /// incl. RSA-AES-KEY-WRAP (OAEP(eph-AES-256)‖KWP blob, c2 format) and the wrap-capable
    /// AES-CBC/AES-GCM/RSA-PKCS1 rows of §5.4. Certificates are classified with
    /// `x509info::cert_facts(.., Classifier::KeyParse)` and carry
    /// `x509info::memory_cert_attributes` (§4.4.5).
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            keys: RefCell::new(Vec::new()),
            _single_thread: PhantomData,
        }
    }

    // -- store ------------------------------------------------------------------------

    /// The record of exactly `key` (same ref AND class, c2 `_record`), cloned out of the
    /// store (OpenSSL keys are reference-counted, secrets re-copied into Zeroizing).
    fn record(&self, key: &KeyInfo) -> Result<Stored> {
        self.keys
            .borrow()
            .iter()
            .find(|rec| rec.info.key_ref == key.key_ref && rec.info.key_class == key.key_class)
            .cloned()
            .ok_or_else(|| self.no_record(key))
    }

    fn no_record(&self, key: &KeyInfo) -> ConsoleError {
        ConsoleError::key_not_found(format!(
            "no key '{}' on provider {}",
            key.key_ref.display(),
            self.name
        ))
    }

    /// Refuse creating an exact (class, label, key id) twin (§4.7 guard, c2
    /// `_ensure_identity_free`). CERTIFICATE is exempt (PKCS#12 chains share one identity);
    /// two None ids count as the same identity; distinct ids stay allowed.
    fn ensure_identity_free(
        &self,
        label: &str,
        key_id: Option<&[u8]>,
        key_classes: &[KeyClass],
    ) -> Result<()> {
        let keys = self.keys.borrow();
        for &key_class in key_classes {
            if key_class == KeyClass::Certificate {
                continue;
            }
            let taken = keys.iter().any(|rec| {
                rec.info.key_ref.label == label
                    && rec.info.key_ref.key_id.as_deref() == key_id
                    && rec.info.key_class == key_class
            });
            if taken {
                return Err(duplicate_identity(
                    &self.name, key_class, label, key_id, false,
                ));
            }
        }
        Ok(())
    }

    /// Store a parsed object (c2 `_store`): §5.5 policy attributes, or the certificate's
    /// `memory_cert_attributes`.
    fn store(
        &self,
        parsed: Parsed,
        label: &str,
        key_id: Option<&[u8]>,
        template: Option<&KeyTemplate>,
    ) -> Result<KeyInfo> {
        let (exportable, mut attributes) = material::policy(template, parsed.key_class);
        if let Payload::Certificate { der, .. } = &parsed.payload {
            attributes = x509info::memory_cert_attributes(der)?;
        }
        let info = KeyInfo {
            key_ref: KeyRef::new(self.name.clone(), label, key_id.map(<[u8]>::to_vec)),
            key_class: parsed.key_class,
            algorithm: parsed.algorithm,
            size_bits: parsed.size_bits,
            curve: parsed.curve,
            exportable,
            attributes,
            handle: None,
        };
        self.keys.borrow_mut().push(Stored {
            info: info.clone(),
            payload: parsed.payload,
        });
        Ok(info)
    }

    // -- capability / key-kind checks ---------------------------------------------------

    fn check_mechanism(&self, mech: &MechanismInvocation) -> Result<()> {
        if CANONICAL_MECHANISMS.contains(&mech.mechanism.as_str()) {
            return Ok(());
        }
        Err(ConsoleError::unsupported(format!(
            "{} does not support mechanism {}",
            self.name, mech.mechanism
        )))
    }

    /// The raw bytes of a SECRET key of exactly `algorithm` (c2 `_secret_of`): DATA objects
    /// and other classes/algorithms are refused — their bytes are never key material.
    fn secret_of(
        &self,
        key: &KeyInfo,
        verb: &str,
        algorithm: KeyAlgorithm,
        what: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let rec = self.record(key)?;
        match rec.payload {
            Payload::Secret(bytes)
                if rec.info.key_class == KeyClass::Secret && rec.info.algorithm == algorithm =>
            {
                Ok(bytes)
            }
            _ => {
                let wanted = if algorithm == KeyAlgorithm::Aes {
                    "secret AES key"
                } else {
                    "generic secret key"
                };
                Err(ConsoleError::unsupported(format!(
                    "{verb} with {what} requires a {wanted} (got {} {})",
                    rec.info.algorithm.as_str(),
                    rec.info.key_class.as_str()
                )))
            }
        }
    }

    fn aes_secret(&self, key: &KeyInfo, verb: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.secret_of(key, verb, KeyAlgorithm::Aes, "an AES mechanism")
    }

    /// MAC key bytes: HMAC ↔ generic secret, AES-CMAC/GMAC ↔ AES (§5.9).
    fn mac_secret(&self, key: &KeyInfo, verb: &str, mechanism: &str) -> Result<Zeroizing<Vec<u8>>> {
        if mechanism == "HMAC" {
            return self.secret_of(key, verb, KeyAlgorithm::Generic, "HMAC");
        }
        self.secret_of(key, verb, KeyAlgorithm::Aes, mechanism)
    }

    /// §4.3 resolution: CERTIFICATE → its embedded public key; PUBLIC → itself.
    fn public_object(&self, key: &KeyInfo, verb: &str) -> Result<PKey<Public>> {
        match self.record(key)?.payload {
            Payload::Certificate { public, .. } | Payload::Public(public) => Ok(public),
            _ => Err(ConsoleError::unsupported(format!(
                "{verb} requires a public key or certificate"
            ))),
        }
    }

    fn rsa_public_for(&self, key: &KeyInfo, verb: &str) -> Result<PKey<Public>> {
        let public = self.public_object(key, verb)?;
        if public.id() != Id::RSA {
            return Err(ConsoleError::unsupported(format!(
                "{verb} requires an RSA public key or certificate"
            )));
        }
        Ok(public)
    }

    fn ec_public_for(&self, key: &KeyInfo, verb: &str) -> Result<PKey<Public>> {
        let public = self.public_object(key, verb)?;
        if public.id() != Id::EC {
            return Err(ConsoleError::unsupported(format!(
                "{verb} requires an EC public key or certificate"
            )));
        }
        Ok(public)
    }

    fn ed_public_for(&self, key: &KeyInfo, verb: &str) -> Result<PKey<Public>> {
        let public = self.public_object(key, verb)?;
        if !matches!(public.id(), Id::ED25519 | Id::ED448) {
            return Err(ConsoleError::unsupported(format!(
                "{verb} requires an Ed25519/Ed448 public key or certificate"
            )));
        }
        Ok(public)
    }

    fn raise_for_certificate(key: &KeyInfo, verb: &str) -> Result<()> {
        if key.key_class == KeyClass::Certificate {
            return Err(ConsoleError::unsupported(format!(
                "certificates cannot be used for {verb} (§4.3)"
            ))
            .with_hint(CERT_VERB_HINT));
        }
        Ok(())
    }

    /// The private key of `key` when its OpenSSL type is one of `ids` (c2 `_rsa_private`,
    /// `_ec_private`, `_ed_private`).
    fn private_of(
        &self,
        key: &KeyInfo,
        verb: &str,
        ids: &[Id],
        what: &str,
    ) -> Result<PKey<Private>> {
        Self::raise_for_certificate(key, verb)?;
        match self.record(key)?.payload {
            Payload::Private(private) if ids.contains(&private.id()) => Ok(private),
            _ => Err(ConsoleError::unsupported(format!(
                "{verb} requires {what} private key"
            ))),
        }
    }

    fn rsa_private(&self, key: &KeyInfo, verb: &str) -> Result<PKey<Private>> {
        self.private_of(key, verb, &[Id::RSA], "an RSA")
    }

    // -- wrap/unwrap helpers -----------------------------------------------------------

    fn unwrap_payload(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let name = mech.mechanism.as_str();
        match name {
            "AES-KEY-WRAP" | "AES-KEY-WRAP-PAD" => {
                let kek = self.aes_secret(wrapping_key, "unwrap_key")?;
                let result = if name == "AES-KEY-WRAP" {
                    engine::kw_unwrap(&kek, wrapped)
                } else {
                    engine::kw_pad_unwrap(&kek, wrapped)
                };
                result.map_err(|err| {
                    let error =
                        ConsoleError::crypto(format!("AES key unwrap failed: {}", err.text()));
                    if name == "AES-KEY-WRAP-PAD" {
                        error.with_hint(KW_PAD_HINT)
                    } else {
                        error
                    }
                })
            }
            "AES-CBC" | "AES-GCM" => {
                let kek = self.aes_secret(wrapping_key, "unwrap_key")?;
                engine::aes_cipher(&kek, name, &mech.params, wrapped, false)
            }
            "RSA-OAEP" => {
                let private = self.rsa_private(wrapping_key, "unwrap_key")?;
                let oaep = engine::oaep_params(&mech.params)?;
                engine::oaep_decrypt(&private, &oaep, wrapped)
                    .ok_or_else(|| ConsoleError::crypto("RSA-OAEP unwrap failed"))
            }
            "RSA-PKCS1" => {
                let private = self.rsa_private(wrapping_key, "unwrap_key")?;
                // detail-free on purpose: PKCS#1 v1.5 decrypt failures are padding-oracle-
                // shaped (mirrors the OAEP branch above)
                engine::pkcs1_decrypt(&private, wrapped)
                    .ok_or_else(|| ConsoleError::crypto("RSA-PKCS1 unwrap failed"))
            }
            _ => {
                // RSA-AES-KEY-WRAP
                let private = self.rsa_private(wrapping_key, "unwrap_key")?;
                let k = private
                    .rsa()
                    .ok()
                    .and_then(|rsa| usize::try_from(rsa.n().num_bits()).ok())
                    .map_or(0, |bits| bits.div_ceil(8));
                if wrapped.len() <= k {
                    return Err(ConsoleError::crypto(format!(
                        "RSA-AES-KEY-WRAP blob too short: {} bytes (needs > {k}-byte OAEP part plus the wrapped payload)",
                        wrapped.len()
                    )));
                }
                let oaep = engine::oaep_params(&mech.params)?;
                let failed = || ConsoleError::crypto("RSA-AES-KEY-WRAP unwrap failed");
                let ephemeral =
                    engine::oaep_decrypt(&private, &oaep, &wrapped[..k]).ok_or_else(failed)?;
                engine::kwp_unwrap(&ephemeral, &wrapped[k..]).map_err(|_| failed())
            }
        }
    }

    fn wrap_payload(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let name = mech.mechanism.as_str();
        match name {
            "AES-KEY-WRAP" | "AES-KEY-WRAP-PAD" => {
                let kek = self.aes_secret(wrapping_key, "wrap_key")?;
                let result = if name == "AES-KEY-WRAP" {
                    engine::kw_wrap(&kek, payload)
                } else {
                    engine::kwp_wrap(&kek, payload)
                };
                result.map_err(|err| {
                    ConsoleError::crypto(format!("AES key wrap failed: {}", err.text()))
                        .with_hint(KW_WRAP_HINT)
                })
            }
            "AES-CBC" | "AES-GCM" => {
                let kek = self.aes_secret(wrapping_key, "wrap_key")?;
                engine::aes_cipher(&kek, name, &mech.params, payload, true).map(|out| out.to_vec())
            }
            _ => {
                let public = self.rsa_public_for(wrapping_key, "wrap_key")?;
                match name {
                    "RSA-OAEP" => {
                        let oaep = engine::oaep_params(&mech.params)?;
                        engine::oaep_encrypt(&public, &oaep, payload).map_err(|detail| {
                            ConsoleError::crypto(format!("RSA-OAEP wrap failed: {detail}")).with_hint(
                                "the payload may exceed the OAEP limit (k - 2*hLen - 2); use RSA-AES-KEY-WRAP for large keys",
                            )
                        })
                    }
                    "RSA-PKCS1" => engine::pkcs1_encrypt(&public, payload).map_err(|detail| {
                        ConsoleError::crypto(format!("RSA-PKCS1 wrap failed: {detail}")).with_hint(
                            "PKCS#1 v1.5 fits at most k-11 payload bytes (245 at RSA-2048); use an AES KEK for private keys",
                        )
                    }),
                    _ => {
                        // RSA-AES-KEY-WRAP: OAEP-wrapped ephemeral AES-256 ‖ AES-KW-PAD payload.
                        let oaep: Oaep = engine::oaep_params(&mech.params)?;
                        let ephemeral = random_bytes(32)?;
                        let mut blob = engine::oaep_encrypt(&public, &oaep, &ephemeral)
                            .map_err(|detail| {
                                ConsoleError::crypto(format!(
                                    "RSA-AES-KEY-WRAP failed wrapping the transport key: {detail}"
                                ))
                            })?;
                        let wrapped = engine::kwp_wrap(&ephemeral, payload).map_err(|err| {
                            ConsoleError::crypto(format!("AES key wrap failed: {}", err.text()))
                        })?;
                        blob.extend_from_slice(&wrapped);
                        Ok(blob)
                    }
                }
            }
        }
    }

    // -- derive helpers ----------------------------------------------------------------

    /// Peer for ECDH on a Weierstrass key: SPKI DER (leading 0x30) or an X9.62-encoded
    /// point on the key's curve, as pyca's `from_encoded_point` accepts it (c2 `_peer_ec`).
    fn peer_ec(private: &PKey<Private>, peer: &[u8]) -> Result<PKey<Public>> {
        let param = |message: String| ConsoleError::param(message, "peer");
        if peer.first() == Some(&0x30) {
            let loaded = material::load_public(peer).map_err(|detail| {
                param(format!("peer is not a valid SPKI public key: {detail}"))
            })?;
            if loaded.id() != Id::EC {
                return Err(param("peer public key is not an EC key".to_owned()));
            }
            let (peer_curve, key_curve) = (
                material::pyca_curve_name(&loaded),
                material::pyca_curve_name(private),
            );
            if peer_curve != key_curve {
                return Err(param(format!(
                    "peer curve {peer_curve} does not match key curve {key_curve}"
                )));
            }
            return Ok(loaded);
        }
        // pyca pre-validation: OpenSSL also accepts the hybrid forms 0x06/0x07 (§5.8).
        if !matches!(peer.first(), Some(0x02..=0x04)) {
            return Err(param(format!(
                "{EC_PEER_TEXT}: Unsupported elliptic curve point type"
            )));
        }
        let decode = || -> std::result::Result<PKey<Public>, ErrorStack> {
            let ec = private.ec_key()?;
            let group: &openssl::ec::EcGroupRef = ec.group();
            let mut ctx = BigNumContext::new()?;
            let point = EcPoint::from_bytes(group, peer, &mut ctx)?;
            let key = EcKey::from_public_key(group, &point)?;
            key.check_key()?;
            PKey::from_ec_key(key)
        };
        decode().map_err(|err| param(format!("{EC_PEER_TEXT}: {}", ossl_reason(&err))))
    }

    /// Peer for X25519/X448: the raw u-coordinate (exactly `raw_len` bytes — length-gated,
    /// never by sniffing the DER tag) or SPKI DER (c2 `_peer_x25519` / `_peer_x448`).
    fn peer_montgomery(peer: &[u8], id: Id, raw_len: usize, curve: &str) -> Result<PKey<Public>> {
        if peer.len() == raw_len {
            return PKey::public_key_from_raw_bytes(peer, id).map_err(|err| {
                ConsoleError::crypto(format!("ECDH key exchange failed: {}", ossl_reason(&err)))
            });
        }
        let loaded = material::load_public(peer).map_err(|detail| {
            ConsoleError::param(
                format!("peer is not a valid SPKI public key: {detail}"),
                "peer",
            )
        })?;
        if loaded.id() != id {
            return Err(ConsoleError::param(
                format!("peer public key does not match the {curve} private key"),
                "peer",
            ));
        }
        Ok(loaded)
    }

    fn exchange(private: &PKey<Private>, peer: &PKey<Public>) -> Result<Zeroizing<Vec<u8>>> {
        let run = || -> std::result::Result<Zeroizing<Vec<u8>>, ErrorStack> {
            let mut deriver = Deriver::new(private)?;
            deriver.set_peer(peer)?;
            let mut z = Zeroizing::new(vec![0u8; deriver.len()?]);
            let n = deriver.derive(&mut z)?;
            z.truncate(n);
            Ok(z)
        };
        run().map_err(|err| {
            ConsoleError::crypto(format!("ECDH key exchange failed: {}", ossl_reason(&err)))
        })
    }

    // -- generation helpers --------------------------------------------------------------

    /// c2 `_generate_private`'s parameter checks, then the key.
    fn keypair_spec(request: &GenerateRequest) -> Result<KeypairSpec> {
        let algorithm = request.algorithm;
        if algorithm == KeyAlgorithm::Rsa {
            let Some(bits) = request.size_bits else {
                return Err(ConsoleError::param(
                    "size_bits is required for RSA",
                    "size_bits",
                ));
            };
            // pyca refuses keys below 1024 bits; OpenSSL would generate them (§5.8).
            if bits < 1024 {
                return Err(ConsoleError::param(
                    format!("invalid RSA key size {bits}: key_size must be at least 1024-bits."),
                    "size_bits",
                ));
            }
            return Ok(KeypairSpec::Rsa(bits));
        }
        let Some(curve) = &request.curve else {
            return Err(ConsoleError::param(
                format!("curve is required for {}", algorithm.as_str()),
                "curve",
            ));
        };
        let unknown = |family: &str, hint: &str| {
            ConsoleError::param(
                format!("unknown {family} curve {}", py_repr(curve.as_str())),
                "curve",
            )
            .with_hint(hint)
        };
        match algorithm {
            KeyAlgorithm::Ec => match curve {
                Curve::P256 => Ok(KeypairSpec::Ec(Nid::X9_62_PRIME256V1)),
                Curve::P384 => Ok(KeypairSpec::Ec(Nid::SECP384R1)),
                Curve::P521 => Ok(KeypairSpec::Ec(Nid::SECP521R1)),
                _ => Err(unknown("EC", "EC (Weierstrass) curves: p256, p384, p521")),
            },
            KeyAlgorithm::EcEdwards => match curve {
                Curve::Ed25519 => Ok(KeypairSpec::Raw(Id::ED25519)),
                Curve::Ed448 => Ok(KeypairSpec::Raw(Id::ED448)),
                _ => Err(unknown("Edwards", "ec-edwards curves: ed25519, ed448")),
            },
            _ => match curve {
                Curve::X25519 => Ok(KeypairSpec::Raw(Id::X25519)),
                Curve::X448 => Ok(KeypairSpec::Raw(Id::X448)),
                _ => Err(unknown("Montgomery", "ec-montgomery curves: x25519, x448")),
            },
        }
    }
}

/// A validated keypair generation request.
enum KeypairSpec {
    Rsa(u32),
    Ec(Nid),
    Raw(Id),
}

impl KeypairSpec {
    fn generate(&self) -> Result<PKey<Private>> {
        let failed = |err: ErrorStack| {
            ConsoleError::crypto(format!("key generation failed: {}", ossl_reason(&err)))
        };
        match self {
            KeypairSpec::Rsa(bits) => {
                Rsa::generate(*bits)
                    .and_then(PKey::from_rsa)
                    .map_err(|err| {
                        ConsoleError::param(
                            format!("invalid RSA key size {bits}: {}", ossl_reason(&err)),
                            "size_bits",
                        )
                    })
            }
            KeypairSpec::Ec(nid) => EcGroup::from_curve_name(*nid)
                .and_then(|group| EcKey::generate(&group))
                .and_then(PKey::from_ec_key)
                .map_err(failed),
            KeypairSpec::Raw(id) => match *id {
                Id::ED25519 => PKey::generate_ed25519(),
                Id::ED448 => PKey::generate_ed448(),
                Id::X25519 => PKey::generate_x25519(),
                _ => PKey::generate_x448(),
            }
            .map_err(failed),
        }
    }
}

/// §4.3 invariant: an empty key id is no key id.
fn normalize_id(key_id: Option<&[u8]>) -> Option<&[u8]> {
    key_id.filter(|id| !id.is_empty())
}

/// §4.3: DATA objects are identified by label alone — no CKA_ID, ever (c2 `_reject_data_id`).
fn reject_data_id(key_class: KeyClass, key_id: Option<&[u8]>) -> Result<()> {
    if key_class == KeyClass::Data && key_id.is_some() {
        return Err(
            ConsoleError::param("data objects carry no CKA_ID (§4.3)", "key_id")
                .with_hint("drop --id; data objects are identified by label alone"),
        );
    }
    Ok(())
}

fn rsa_modulus_bits(pkey: &openssl::pkey::PKeyRef<impl openssl::pkey::HasPublic>) -> u32 {
    pkey.rsa()
        .ok()
        .and_then(|rsa| u32::try_from(rsa.n().num_bits()).ok())
        .unwrap_or(0)
}

/// (modulus, public exponent) of an RSA key, big-endian magnitudes.
fn rsa_public_numbers(
    pkey: &openssl::pkey::PKeyRef<impl openssl::pkey::HasPublic>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let rsa = pkey
        .rsa()
        .map_err(|err| ConsoleError::crypto(format!("RSA-RAW failed: {}", ossl_reason(&err))))?;
    Ok((rsa.n().to_vec(), rsa.e().to_vec()))
}

/// (modulus, private exponent d) of an RSA private key.
fn rsa_private_numbers(pkey: &PKey<Private>) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let rsa = pkey
        .rsa()
        .map_err(|err| ConsoleError::crypto(format!("RSA-RAW failed: {}", ossl_reason(&err))))?;
    Ok((rsa.n().to_vec(), Zeroizing::new(rsa.d().to_vec())))
}

/// ceil(curve bits / 8) — the fixed r‖s half width of an EC key (c2
/// `(curve.key_size + 7) // 8`, §4.5.4).
fn ec_width(pkey: &openssl::pkey::PKeyRef<impl openssl::pkey::HasPublic>) -> usize {
    pkey.ec_key()
        .ok()
        .and_then(|ec| usize::try_from(ec.group().degree()).ok())
        .map_or(0, |bits| bits.div_ceil(8))
}

/// The resolved PSS salt length as OpenSSL's `custom(n)` (memory always passes an explicit
/// length so verify is exact, §5.9). Lengths beyond i32 fit no RSA key: OpenSSL refuses them.
fn pss_saltlen(pss: &engine::Pss) -> RsaPssSaltlen {
    RsaPssSaltlen::custom(i32::try_from(pss.salt_len).unwrap_or(i32::MAX))
}

impl Provider for MemoryProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn type_name(&self) -> &str {
        "memory"
    }

    /// No-op for memory (idempotent, §4.5).
    fn initialize(&self) -> Result<()> {
        Ok(())
    }

    /// Drop all session-resident keys; safe when never initialized.
    fn shutdown(&self) -> Result<()> {
        self.keys.borrow_mut().clear();
        Ok(())
    }

    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            auth: AuthState::NotRequired,
            token: None,
        }
    }

    fn mechanisms(&self) -> BTreeSet<String> {
        CANONICAL_MECHANISMS
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    }

    fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        Ok(self
            .keys
            .borrow()
            .iter()
            .map(|rec| rec.info.clone())
            .collect())
    }

    fn find_key(&self, selector: &KeySelector) -> Result<KeyInfo> {
        let matches: Vec<KeyInfo> = self
            .keys
            .borrow()
            .iter()
            .filter(|rec| matches_selector(&rec.info, selector))
            .map(|rec| rec.info.clone())
            .collect();
        select_match(&self.name, selector, matches)
    }

    fn import_key(
        &self,
        material: &KeyMaterial,
        label: &str,
        template: Option<&KeyTemplate>,
        key_id: Option<&[u8]>,
    ) -> Result<KeyInfo> {
        let key_id = normalize_id(key_id);
        let parsed = material::parse_material(material)?;
        reject_data_id(parsed.key_class, key_id)?;
        self.ensure_identity_free(label, key_id, &[parsed.key_class])?;
        self.store(parsed, label, key_id, template)
    }

    fn generate_key(&self, request: &GenerateRequest) -> Result<KeyInfo> {
        let key_id = normalize_id(request.key_id.as_deref());
        let label = request.label.as_str();
        let algorithm = request.algorithm;
        match algorithm {
            KeyAlgorithm::Aes | KeyAlgorithm::Generic => {
                let Some(size_bits) = request.size_bits else {
                    return Err(ConsoleError::param(
                        format!("size_bits is required for {}", algorithm.as_str()),
                        "size_bits",
                    ));
                };
                if algorithm == KeyAlgorithm::Aes && !AES_KEY_BITS.contains(&size_bits) {
                    return Err(ConsoleError::param(
                        format!("invalid AES key size {size_bits}; expected 128, 192 or 256"),
                        "size_bits",
                    ));
                }
                if algorithm == KeyAlgorithm::Generic
                    && (!size_bits.is_multiple_of(8)
                        || !(GENERIC_MIN_BITS..=GENERIC_MAX_BITS).contains(&size_bits))
                {
                    return Err(ConsoleError::param(
                        format!(
                            "invalid generic secret size {size_bits}; expected a multiple of 8 between {GENERIC_MIN_BITS} and {GENERIC_MAX_BITS} bits"
                        ),
                        "size_bits",
                    ));
                }
                let len = usize::try_from(size_bits / 8).unwrap_or(0);
                let secret = random_bytes(len)?;
                self.ensure_identity_free(label, key_id, &[KeyClass::Secret])?;
                let parsed = Parsed {
                    algorithm,
                    key_class: KeyClass::Secret,
                    curve: None,
                    size_bits: Some(size_bits),
                    payload: Payload::Secret(secret),
                };
                self.store(parsed, label, key_id, request.template.as_ref())
            }
            KeyAlgorithm::None | KeyAlgorithm::Other => Err(ConsoleError::param(
                format!("cannot generate {} keys", algorithm.as_str()),
                "algorithm",
            )),
            _ => {
                let spec = Self::keypair_spec(request)?;
                let private = spec.generate()?;
                let (algorithm, curve, size_bits) = material::classify(&private, true)?;
                let public_der = private.public_key_to_der().map_err(|err| {
                    ConsoleError::crypto(format!("key generation failed: {}", ossl_reason(&err)))
                })?;
                let public = PKey::public_key_from_der(&public_der).map_err(|err| {
                    ConsoleError::crypto(format!("key generation failed: {}", ossl_reason(&err)))
                })?;
                // Both halves share label and key_id (§4.5); both checked up front — a
                // collision never leaves a half-created pair.
                self.ensure_identity_free(label, key_id, &[KeyClass::Private, KeyClass::Public])?;
                let private_info = self.store(
                    Parsed {
                        algorithm,
                        key_class: KeyClass::Private,
                        curve: curve.clone(),
                        size_bits,
                        payload: Payload::Private(private),
                    },
                    label,
                    key_id,
                    request.template.as_ref(),
                )?;
                self.store(
                    Parsed {
                        algorithm,
                        key_class: KeyClass::Public,
                        curve,
                        size_bits,
                        payload: Payload::Public(public),
                    },
                    label,
                    key_id,
                    request.public_template.as_ref(),
                )?;
                Ok(private_info)
            }
        }
    }

    fn delete_key(&self, key: &KeyInfo) -> Result<()> {
        let mut keys = self.keys.borrow_mut();
        let position = keys
            .iter()
            .position(|rec| rec.info.key_ref == key.key_ref && rec.info.key_class == key.key_class);
        match position {
            Some(index) => {
                keys.remove(index);
                Ok(())
            }
            None => {
                drop(keys);
                Err(self.no_record(key))
            }
        }
    }

    fn export_key(&self, key: &KeyInfo) -> Result<KeyMaterial> {
        let rec = self.record(key)?;
        if !rec.info.exportable {
            return Err(ConsoleError::key_not_exportable(format!(
                "key '{}' is not exportable",
                key.key_ref.display()
            ))
            .with_hint(EXPORT_HINT));
        }
        Ok(KeyMaterial {
            algorithm: rec.info.algorithm,
            key_class: rec.info.key_class,
            data: material::canonical_bytes(&rec.payload)?,
            curve: rec.info.curve.clone(),
            size_bits: rec.info.size_bits,
            label_hint: Some(rec.info.key_ref.label.clone()),
        })
    }

    // -- crypto verbs -------------------------------------------------------------------

    fn encrypt(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        self.check_mechanism(mech)?;
        let name = mech.mechanism.as_str();
        if AES_CIPHER_MECHS.contains(&name) {
            let secret = self.aes_secret(key, "encrypt")?;
            return engine::aes_cipher(&secret, name, &mech.params, data, true)
                .map(|out| out.to_vec());
        }
        if RSA_CIPHER_MECHS.contains(&name) {
            let public = self.rsa_public_for(key, "encrypt")?;
            return match name {
                "RSA-OAEP" => {
                    let oaep = engine::oaep_params(&mech.params)?;
                    engine::oaep_encrypt(&public, &oaep, data).map_err(|detail| {
                        ConsoleError::crypto(format!("RSA-OAEP encryption failed: {detail}"))
                    })
                }
                "RSA-PKCS1" => engine::pkcs1_encrypt(&public, data).map_err(|detail| {
                    ConsoleError::crypto(format!("RSA-PKCS1 encryption failed: {detail}"))
                }),
                _ => {
                    let (n, e) = rsa_public_numbers(&public)?;
                    rsa_raw_modexp(&n, &e, data).map(|out| out.to_vec())
                }
            };
        }
        Err(ConsoleError::unsupported(format!(
            "mechanism {name} does not support encrypt"
        )))
    }

    fn decrypt(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.check_mechanism(mech)?;
        let name = mech.mechanism.as_str();
        if AES_CIPHER_MECHS.contains(&name) {
            let secret = self.aes_secret(key, "decrypt")?;
            return engine::aes_cipher(&secret, name, &mech.params, data, false);
        }
        if RSA_CIPHER_MECHS.contains(&name) {
            if name == "RSA-RAW" && key.key_class == KeyClass::Public {
                // §5.8: public-exponent modexp — signature recovery (`decrypt …:pub raw`)
                let public = self.rsa_public_for(key, "decrypt")?;
                let (n, e) = rsa_public_numbers(&public)?;
                return rsa_raw_modexp(&n, &e, data);
            }
            let private = self.rsa_private(key, "decrypt")?;
            return match name {
                "RSA-OAEP" => {
                    let oaep = engine::oaep_params(&mech.params)?;
                    engine::oaep_decrypt(&private, &oaep, data)
                        .ok_or_else(|| ConsoleError::crypto("RSA-OAEP decryption failed"))
                }
                "RSA-PKCS1" => engine::pkcs1_decrypt(&private, data)
                    .ok_or_else(|| ConsoleError::crypto("RSA-PKCS1 decryption failed")),
                _ => {
                    let (n, d) = rsa_private_numbers(&private)?;
                    rsa_raw_modexp(&n, &d, data)
                }
            };
        }
        Err(ConsoleError::unsupported(format!(
            "mechanism {name} does not support decrypt"
        )))
    }

    fn sign(&self, key: &KeyInfo, mech: &MechanismInvocation, data: &[u8]) -> Result<Vec<u8>> {
        self.check_mechanism(mech)?;
        let name = mech.mechanism.as_str();
        let params: &Params = &mech.params;
        if MAC_MECHS.contains(&name) {
            let secret = self.mac_secret(key, "sign", name)?;
            return engine::mac(&secret, name, params, data);
        }
        if RSA_SIGN_MECHS.contains(&name) {
            let private = self.rsa_private(key, "sign")?;
            return match name {
                "RSA-PKCS1" => {
                    let (md, _) = engine::digest(&engine::hash_param(params)?);
                    let run = || -> std::result::Result<Vec<u8>, ErrorStack> {
                        let mut signer = Signer::new(md, &private)?;
                        signer.update(data)?;
                        signer.sign_to_vec()
                    };
                    run().map_err(|err| {
                        ConsoleError::crypto(format!(
                            "RSA-PKCS1 signing failed: {}",
                            ossl_reason(&err)
                        ))
                    })
                }
                "RSA-PSS" => {
                    let pss = engine::pss_params(params, rsa_modulus_bits(&private))?;
                    if pss.salt_len < 0 {
                        // pyca PSS(salt_length=<0) ValueError (the -1 sentinel on a tiny key)
                        return Err(ConsoleError::crypto(
                            "RSA-PSS signing failed: salt_length must be zero or greater.",
                        ));
                    }
                    let run = || -> std::result::Result<Vec<u8>, ErrorStack> {
                        let mut signer = Signer::new(pss.hash, &private)?;
                        signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?;
                        signer.set_rsa_mgf1_md(pss.mgf)?;
                        signer.set_rsa_pss_saltlen(pss_saltlen(&pss))?;
                        signer.update(data)?;
                        signer.sign_to_vec()
                    };
                    run().map_err(|err| {
                        ConsoleError::crypto(format!(
                            "RSA-PSS signing failed: {}",
                            ossl_reason(&err)
                        ))
                    })
                }
                _ => {
                    let (n, d) = rsa_private_numbers(&private)?;
                    rsa_raw_modexp(&n, &d, data).map(|out| out.to_vec())
                }
            };
        }
        if name == "ECDSA" {
            let private = self.private_of(key, "sign", &[Id::EC], "an EC")?;
            let (md, _) = engine::digest(&engine::hash_param(params)?);
            let run = || -> std::result::Result<Vec<u8>, ErrorStack> {
                let mut signer = Signer::new(md, &private)?;
                signer.update(data)?;
                signer.sign_to_vec()
            };
            let der = run().map_err(|err| {
                ConsoleError::crypto(format!("ECDSA signing failed: {}", ossl_reason(&err)))
            })?;
            return ecdsa_der_to_rs(&der, ec_width(&private));
        }
        if name == "EDDSA" {
            let private =
                self.private_of(key, "sign", &[Id::ED25519, Id::ED448], "an Ed25519/Ed448")?;
            let run = || -> std::result::Result<Vec<u8>, ErrorStack> {
                Signer::new_without_digest(&private)?.sign_oneshot_to_vec(data)
            };
            return run().map_err(|err| {
                ConsoleError::crypto(format!("EdDSA signing failed: {}", ossl_reason(&err)))
            });
        }
        Err(ConsoleError::unsupported(format!(
            "mechanism {name} does not support sign"
        )))
    }

    fn verify(
        &self,
        key: &KeyInfo,
        mech: &MechanismInvocation,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        self.check_mechanism(mech)?;
        let name = mech.mechanism.as_str();
        let params: &Params = &mech.params;
        if MAC_MECHS.contains(&name) {
            let secret = self.mac_secret(key, "verify", name)?;
            return engine::mac_verify(&secret, name, params, data, signature);
        }
        match name {
            "RSA-PKCS1" => {
                let public = self.rsa_public_for(key, "verify")?;
                let (md, _) = engine::digest(&engine::hash_param(params)?);
                let run = || -> std::result::Result<bool, ErrorStack> {
                    let mut verifier = Verifier::new(md, &public)?;
                    verifier.update(data)?;
                    verifier.verify(signature)
                };
                // pyca reports every backend verify failure as InvalidSignature.
                Ok(run().unwrap_or(false))
            }
            "RSA-PSS" => {
                let public = self.rsa_public_for(key, "verify")?;
                let pss = engine::pss_params(params, rsa_modulus_bits(&public))?;
                if pss.salt_len < 0 {
                    return Err(ConsoleError::crypto(
                        "RSA-PSS verification failed: salt_length must be zero or greater.",
                    ));
                }
                let mut verifier = Verifier::new(pss.hash, &public)
                    .and_then(|mut verifier| {
                        verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?;
                        verifier.set_rsa_mgf1_md(pss.mgf)?;
                        verifier.set_rsa_pss_saltlen(pss_saltlen(&pss))?;
                        Ok(verifier)
                    })
                    .map_err(|err| {
                        ConsoleError::crypto(format!(
                            "RSA-PSS verification failed: {}",
                            ossl_reason(&err)
                        ))
                    })?;
                let valid = verifier
                    .update(data)
                    .and_then(|()| verifier.verify(signature));
                Ok(valid.unwrap_or(false))
            }
            "RSA-RAW" => {
                let public = self.rsa_public_for(key, "verify")?;
                let (n, e) = rsa_public_numbers(&public)?;
                let k = usize::try_from(rsa_modulus_bits(&public))
                    .unwrap_or(0)
                    .div_ceil(8);
                if signature.len() != k || data.len() > k {
                    return Ok(false);
                }
                // a signature not numerically below n is refused by rsa_raw_modexp
                let Ok(recovered) = rsa_raw_modexp(&n, &e, signature) else {
                    return Ok(false);
                };
                let mut expected = vec![0u8; k - data.len()];
                expected.extend_from_slice(data);
                Ok(ct_eq(&recovered, &expected))
            }
            "ECDSA" => {
                let public = self.ec_public_for(key, "verify")?;
                let width = ec_width(&public);
                if signature.len() != 2 * width {
                    return Ok(false);
                }
                let (md, _) = engine::digest(&engine::hash_param(params)?);
                let Ok(der) = ecdsa_rs_to_der(signature) else {
                    return Ok(false);
                };
                let run = || -> std::result::Result<bool, ErrorStack> {
                    let mut verifier = Verifier::new(md, &public)?;
                    verifier.update(data)?;
                    verifier.verify(&der)
                };
                Ok(run().unwrap_or(false))
            }
            "EDDSA" => {
                let public = self.ed_public_for(key, "verify")?;
                let run = || -> std::result::Result<bool, ErrorStack> {
                    Verifier::new_without_digest(&public)?.verify_oneshot(signature, data)
                };
                Ok(run().unwrap_or(false))
            }
            _ => Err(ConsoleError::unsupported(format!(
                "mechanism {name} does not support verify"
            ))),
        }
    }

    fn derive(&self, key: &KeyInfo, mech: &MechanismInvocation) -> Result<DeriveResult> {
        self.check_mechanism(mech)?;
        if mech.mechanism != "ECDH" {
            return Err(ConsoleError::unsupported(format!(
                "mechanism {} does not support derive",
                mech.mechanism
            )));
        }
        let rec = self.record(key)?;
        if rec.info.key_class == KeyClass::Certificate {
            return Err(
                ConsoleError::unsupported("certificates cannot be used for derive (§4.3)")
                    .with_hint(CERT_VERB_HINT),
            );
        }
        let private = match rec.payload {
            Payload::Private(private) if rec.info.key_class == KeyClass::Private => private,
            _ => return Err(ConsoleError::unsupported("ECDH requires a private key")),
        };
        let params: &Params = &mech.params;
        let peer = engine::param_bytes(params, "peer", None)?;
        if peer.is_empty() {
            return Err(ConsoleError::param(
                "peer public key must not be empty",
                "peer",
            ));
        }
        let peer_key = match private.id() {
            Id::EC => Self::peer_ec(&private, peer)?,
            Id::X25519 => Self::peer_montgomery(peer, Id::X25519, 32, "x25519")?,
            Id::X448 => Self::peer_montgomery(peer, Id::X448, 56, "x448")?,
            _ => {
                return Err(ConsoleError::unsupported(
                    "ECDH requires an EC (Weierstrass) or X25519/X448 private key",
                )
                .with_hint("Ed25519/Ed448 keys sign; they do not derive"));
            }
        };
        let z = Self::exchange(&private, &peer_key)?;

        let kdf = param_choice(params, "kdf", &engine::KDF_NAMES, "null")?;
        let shared_data = engine::param_bytes(params, "shared_data", Some(b""))?;
        let out_len = param_int(params, "out_len", 0)?;
        if out_len < 0 {
            return Err(ConsoleError::param(
                "out_len must be >= 0 (0 = curve size)",
                "out_len",
            ));
        }
        let out_len = usize::try_from(out_len).unwrap_or(usize::MAX);
        let raw = if kdf == "null" {
            if !shared_data.is_empty() {
                return Err(ConsoleError::param(
                    "shared_data requires a KDF (set kdf to a hash)",
                    "shared_data",
                ));
            }
            if out_len == 0 || out_len == z.len() {
                z
            } else if out_len < z.len() {
                Zeroizing::new(z[..out_len].to_vec())
            } else {
                return Err(ConsoleError::param(
                    format!(
                        "out_len {out_len} exceeds the shared-secret length {} for kdf=null",
                        z.len()
                    ),
                    "out_len",
                ));
            }
        } else {
            let length = if out_len == 0 { z.len() } else { out_len };
            engine::x963_kdf(&z, shared_data, &kdf, length)?
        };
        Ok(DeriveResult {
            key: None,
            raw: Some(raw),
        })
    }

    // -- wrap/unwrap (§5.5) ------------------------------------------------------------

    fn wrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        target: &KeyInfo,
        options: &WrapOptions,
    ) -> Result<Vec<u8>> {
        let _ = options;
        self.check_mechanism(mech)?;
        let name = mech.mechanism.as_str();
        if !WRAP_MECHS.contains(&name) {
            return Err(ConsoleError::unsupported(format!(
                "mechanism {name} does not support key wrapping"
            )));
        }
        let target_rec = self.record(target)?;
        if !matches!(
            target_rec.info.key_class,
            KeyClass::Secret | KeyClass::Private
        ) {
            return Err(
                ConsoleError::unsupported("only secret and private keys are wrapped").with_hint(
                    "copy public keys, certificates and data objects as plain material (§5.5)",
                ),
            );
        }
        // §5.5: wrappable = CKA_EXTRACTABLE alone (sensitive-but-extractable OK).
        if target_rec.info.attributes.get("CKA_EXTRACTABLE") == Some(&AttrValue::Bool(false)) {
            return Err(ConsoleError::key_not_exportable(format!(
                "key '{}' is not extractable and cannot be wrapped",
                target.key_ref.display()
            )));
        }
        let payload = material::canonical_bytes(&target_rec.payload)?;
        self.wrap_payload(wrapping_key, mech, &payload)
    }

    fn unwrap_key(
        &self,
        wrapping_key: &KeyInfo,
        mech: &MechanismInvocation,
        wrapped: &[u8],
        request: &UnwrapRequest,
    ) -> Result<KeyInfo> {
        self.check_mechanism(mech)?;
        let name = mech.mechanism.as_str();
        if !WRAP_MECHS.contains(&name) {
            return Err(ConsoleError::unsupported(format!(
                "mechanism {name} does not support key unwrapping"
            )));
        }
        if !matches!(request.result_class, KeyClass::Secret | KeyClass::Private) {
            return Err(
                ConsoleError::unsupported("unwrap produces secret or private keys only").with_hint(
                    "import public keys, certificates and data objects as plain material (§5.5)",
                ),
            );
        }
        let key_id = normalize_id(request.key_id.as_deref());
        let label = request.label.as_str();
        self.ensure_identity_free(label, key_id, &[request.result_class])?;
        let payload = self.unwrap_payload(wrapping_key, mech, wrapped)?;
        let material = KeyMaterial {
            algorithm: request.result_algorithm,
            key_class: request.result_class,
            data: payload,
            curve: None,
            size_bits: None,
            label_hint: Some(label.to_owned()),
        };
        let parsed = material::parse_material(&material)?;
        self.store(parsed, label, key_id, request.template.as_ref())
    }

    // -- key editing (§5.15) --------------------------------------------------------------

    /// Editor-seedable snapshot: memory objects carry identity only (§5.15). DATA objects
    /// have no CKA_ID (§4.3) — their snapshot is the label alone.
    fn read_key_template(&self, key: &KeyInfo) -> Result<KeyTemplate> {
        let rec = self.record(key)?;
        let key_ref = &rec.info.key_ref;
        let mut attrs = vec![r2_core::template::TemplateAttr::new(
            "CKA_LABEL",
            r2_core::template::AttrKind::Str,
            AttrValue::Str(key_ref.label.clone()),
        )];
        if rec.info.key_class != KeyClass::Data {
            let mut id_row = r2_core::template::TemplateAttr::new(
                "CKA_ID",
                r2_core::template::AttrKind::Bytes,
                AttrValue::Bytes(key_ref.key_id.clone().unwrap_or_default()),
            );
            id_row.enabled = key_ref.key_id.is_some();
            attrs.push(id_row);
        }
        Ok(KeyTemplate::new(attrs))
    }

    /// Rename this object (CKA_LABEL/CKA_ID); other attrs are not editable (§5.15).
    fn update_key(&self, key: &KeyInfo, changes: &KeyTemplate) -> Result<KeyEditResult> {
        let rec = self.record(key)?;
        let mut outcomes = Vec::new();
        let mut new_label = rec.info.key_ref.label.clone();
        let mut new_id = rec.info.key_ref.key_id.clone();
        for attr in changes.enabled_attrs() {
            match attr.name.as_str() {
                "CKA_CLASS" | "CKA_KEY_TYPE" => {
                    return Err(ConsoleError::param(
                        format!("{} cannot be edited after creation", attr.name),
                        attr.name.clone(),
                    ));
                }
                "CKA_LABEL" => {
                    let label = match &attr.value {
                        AttrValue::Str(text) | AttrValue::Symbol(text) if !text.is_empty() => {
                            text.clone()
                        }
                        _ => {
                            return Err(ConsoleError::param(
                                "CKA_LABEL expects a non-empty string",
                                "CKA_LABEL",
                            ));
                        }
                    };
                    new_label = label;
                    outcomes.push(AttrEditOutcome {
                        name: "CKA_LABEL".to_owned(),
                        applied: true,
                        detail: None,
                    });
                }
                "CKA_ID" => {
                    if rec.info.key_class == KeyClass::Data {
                        return Err(ConsoleError::param(
                            "data objects carry no CKA_ID (§4.3)",
                            "CKA_ID",
                        )
                        .with_hint("data objects are identified by label alone"));
                    }
                    let id = match &attr.value {
                        AttrValue::Bytes(bytes) if !bytes.is_empty() => bytes.clone(),
                        _ => {
                            return Err(ConsoleError::param(
                                "CKA_ID expects non-empty bytes",
                                "CKA_ID",
                            )
                            .with_hint("use a 0x… hex value"));
                        }
                    };
                    new_id = Some(id);
                    outcomes.push(AttrEditOutcome {
                        name: "CKA_ID".to_owned(),
                        applied: true,
                        detail: None,
                    });
                }
                other => outcomes.push(AttrEditOutcome {
                    name: other.to_owned(),
                    applied: false,
                    detail: Some("not editable on the memory provider".to_owned()),
                }),
            }
        }
        let current = (&rec.info.key_ref.label, &rec.info.key_ref.key_id);
        if (&new_label, &new_id) == current {
            return Ok(KeyEditResult {
                key: rec.info,
                outcomes,
            });
        }
        let mut keys = self.keys.borrow_mut();
        let Some(index) = keys.iter().position(|other| {
            other.info.key_ref == rec.info.key_ref && other.info.key_class == rec.info.key_class
        }) else {
            drop(keys);
            return Err(self.no_record(key));
        };
        // §4.7 duplicate-identity guard for renames — excludes the renamed record;
        // certificates are exempt.
        if rec.info.key_class != KeyClass::Certificate {
            let taken = keys.iter().enumerate().any(|(i, other)| {
                i != index
                    && other.info.key_ref.label == new_label
                    && other.info.key_ref.key_id == new_id
                    && other.info.key_class == rec.info.key_class
            });
            if taken {
                return Err(duplicate_identity(
                    &self.name,
                    rec.info.key_class,
                    &new_label,
                    new_id.as_deref(),
                    true,
                ));
            }
        }
        keys[index].info.key_ref = KeyRef::new(self.name.clone(), new_label, new_id);
        Ok(KeyEditResult {
            key: keys[index].info.clone(),
            outcomes,
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::engine::{KwError, kw_pad_unwrap, kwp_unwrap};

    #[test]
    fn kwp_unwrap_of_short_and_unaligned_blobs_is_pycas() {
        let kek = [0u8; 16];
        assert!(
            matches!(kwp_unwrap(&kek, &[0u8; 10]), Err(KwError::Invalid(t)) if t == "Must be at least 16 bytes")
        );
        assert!(matches!(
            kwp_unwrap(&kek, &[0u8; 20]),
            Err(KwError::Value(t)) if t == "The length of the provided data is not a multiple of the block length."
        ));
        assert!(
            matches!(kw_pad_unwrap(&kek, &[0u8; 16]), Err(KwError::Invalid(t)) if t.starts_with("blob matches neither"))
        );
    }
}
