// RSA-RAW modexp shared by MemoryProvider and Pkcs11Provider (spec §4.5.3, c2
// providers/base.py `rsa_raw_modexp`).
use openssl::bn::{BigNum, BigNumContext};
use r2_core::error::{ConsoleError, Result};
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
    let n = bignum(modulus)?;
    // c2: k = (n.bit_length() + 7) // 8 — leading zero bytes of the magnitude do not count.
    let k = usize::try_from(n.num_bits())
        .map_err(|_| crypto_failure())?
        .div_ceil(8);
    if data.len() > k {
        return Err(ConsoleError::crypto(format!(
            "RSA-RAW input is longer than the modulus ({} > {k} bytes)",
            data.len()
        )));
    }
    // `m` may be ciphertext and `exponent` the private exponent d (decrypt/sign), and
    // openssl's BigNum Drop is BN_free (no wipe): every BigNum holding them, and the
    // result, is cleared on every path by `Cleared`.
    let m = Cleared(bignum(data)?);
    if m.0 >= n {
        return Err(ConsoleError::crypto(
            "RSA-RAW input is not numerically smaller than the modulus",
        ));
    }
    let e = Cleared(bignum(exponent)?);
    let mut out = Cleared(BigNum::new().map_err(|_| crypto_failure())?);
    let mut ctx = BigNumContext::new().map_err(|_| crypto_failure())?;
    out.0
        .mod_exp(&m.0, &e.0, &n, &mut ctx)
        .map_err(|_| crypto_failure())?;
    let width = i32::try_from(k).map_err(|_| crypto_failure())?;
    let bytes = out.0.to_vec_padded(width).map_err(|_| crypto_failure())?;
    Ok(Zeroizing::new(bytes))
}

/// Clears (BN_clear) the wrapped BigNum on drop; `clear` never fails or panics.
struct Cleared(BigNum);

impl Drop for Cleared {
    fn drop(&mut self) {
        self.0.clear();
    }
}

fn bignum(bytes: &[u8]) -> Result<BigNum> {
    BigNum::from_slice(bytes).map_err(|_| crypto_failure())
}

fn crypto_failure() -> ConsoleError {
    ConsoleError::crypto("RSA-RAW modular exponentiation failed")
}
