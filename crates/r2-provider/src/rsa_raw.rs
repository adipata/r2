// R0 skeleton — owner R3 (generated from spec §4)
// ---- spec §4.5.3 block 2
use r2_core::error::Result;
use zeroize::Zeroizing;

/// RSA-RAW (CKM_RSA_X_509 equivalent): textbook modexp with fixed-width I2OSP, shared by
/// MemoryProvider and Pkcs11Provider's software public-exponent decrypt. Inputs are
/// big-endian magnitudes. `data` is left-padded to k = modulus byte length. NOT
/// constant-time (diagnostic feature, §5.8). Implemented with openssl BigNum `mod_exp` +
/// `to_vec_padded(k)` — never `Padding::NONE` (it requires len == k). Errors → Crypto
/// "RSA-RAW input is longer than the modulus ({len} > {k} bytes)" /
/// "RSA-RAW input is not numerically smaller than the modulus". The output may be a
/// private-exponent result (decrypt/sign), so it is zeroizing (D3).
pub fn rsa_raw_modexp(modulus: &[u8], exponent: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let _ = (modulus, exponent, data);
    Err(r2_core::ConsoleError::not_implemented("R3"))
}
