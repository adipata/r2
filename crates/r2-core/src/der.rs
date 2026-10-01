// R0 skeleton — owner R6 (generated from spec §4)
use crate::error::Result;
use crate::keys::Curve;

/// Named-curve OID DER (CKA_EC_PARAMS): p256 06082a8648ce3d030107, p384 06052b81040022,
/// p521 06052b81040023, ed25519 06032b6570, ed448 06032b6571, x25519 06032b656e,
/// x448 06032b656f. None for Curve::Other. (R0 mandated working body: this table.)
pub fn curve_oid_der(curve: &Curve) -> Option<&'static [u8]> {
    match curve {
        Curve::P256 => Some(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        Curve::P384 => Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
        Curve::P521 => Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]),
        Curve::Ed25519 => Some(&[0x06, 0x03, 0x2b, 0x65, 0x70]),
        Curve::Ed448 => Some(&[0x06, 0x03, 0x2b, 0x65, 0x71]),
        Curve::X25519 => Some(&[0x06, 0x03, 0x2b, 0x65, 0x6e]),
        Curve::X448 => Some(&[0x06, 0x03, 0x2b, 0x65, 0x6f]),
        Curve::Other(_) => None,
    }
}
/// Inverse of curve_oid_der over the seven known curves. (R0 mandated working body.)
pub fn curve_from_oid_der(der: &[u8]) -> Option<Curve> {
    Curve::KNOWN
        .into_iter()
        .find(|curve| curve_oid_der(curve) == Some(der))
}
/// DER OCTET STRING around a raw EC point (CKA_EC_POINT — the classic gotcha): tag 0x04,
/// DER definite length (short form < 128, else 0x81/0x82/… long form), the bytes.
/// (R0 mandated working body.)
pub fn wrap_octet_string(raw: &[u8]) -> Vec<u8> {
    let len = raw.len();
    let mut out = vec![0x04];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(raw);
    out
}
/// Strip a DER OCTET STRING header; input that is not exactly one well-formed OCTET STRING
/// TLV is returned unchanged (raw points pass through) — c2 `_unwrap_octet_string`.
pub fn unwrap_octet_string(der: &[u8]) -> Vec<u8> {
    let _ = der;
    unimplemented!("R6")
}
/// Canonical fixed-width r‖s → DER ECDSA-Sig-Value SEQUENCE (minimal INTEGERs), via
/// `#[derive(der::Sequence)] struct { r: UintRef, s: UintRef }`. Empty or odd length →
/// Crypto "ECDSA signature of {n} bytes is not fixed-width r‖s" (hint "providers emit r‖s
/// with each half ceil(curve_bits/8) bytes (§4.6)").
pub fn ecdsa_rs_to_der(signature: &[u8]) -> Result<Vec<u8>> {
    let _ = signature;
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
/// DER ECDSA-Sig-Value → r‖s, each half left-padded to `half_len` bytes. Malformed or
/// oversized → Crypto "malformed ECDSA DER signature".
pub fn ecdsa_der_to_rs(der: &[u8], half_len: usize) -> Result<Vec<u8>> {
    let _ = (der, half_len);
    Err(crate::error::ConsoleError::not_implemented("R6"))
}
