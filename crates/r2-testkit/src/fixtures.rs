// R0 skeleton — owner R3 (generated from spec §4)
// ---- spec §4.10.3 block 1
pub fn rsa2048_pkcs8() -> Vec<u8> {
    unimplemented!("R3")
} // unencrypted PKCS#8 DER
pub fn ec_p256_pkcs8() -> Vec<u8> {
    unimplemented!("R3")
}
pub fn ed25519_pkcs8() -> Vec<u8> {
    unimplemented!("R3")
}
/// Self-signed cert (CN = cn, SHA-256 / Ed: no digest, BasicConstraints CA:FALSE, notBefore
/// = now − 1 day, 3650 days) for the given PKCS#8 key; DER.
pub fn self_signed_cert(pkcs8: &[u8], cn: &str) -> Vec<u8> {
    let _ = (pkcs8, cn);
    unimplemented!("R3")
}
/// (PKCS#8, cert) of the contract suite's RSA key, CN "r2-contract".
pub fn rsa_pkcs8_and_cert() -> (Vec<u8>, Vec<u8>) {
    unimplemented!("R3")
}
