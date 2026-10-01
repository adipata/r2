// R0 skeleton — owner R3 (generated from spec §4)
// ---- spec §4.5.3 block 3
pub const AES_ECB: &str = "AES-ECB";
pub const AES_CBC: &str = "AES-CBC";
pub const AES_CTR: &str = "AES-CTR";
pub const AES_GCM: &str = "AES-GCM";
pub const AES_CMAC: &str = "AES-CMAC";
pub const AES_GMAC: &str = "AES-GMAC";
pub const HMAC: &str = "HMAC";
pub const RSA_OAEP: &str = "RSA-OAEP";
pub const RSA_PKCS1: &str = "RSA-PKCS1";
pub const RSA_PSS: &str = "RSA-PSS";
pub const RSA_RAW: &str = "RSA-RAW";
pub const ECDSA: &str = "ECDSA";
pub const EDDSA: &str = "EDDSA";
pub const ECDH: &str = "ECDH";
pub const AES_KEY_WRAP: &str = "AES-KEY-WRAP";
pub const AES_KEY_WRAP_PAD: &str = "AES-KEY-WRAP-PAD";
pub const RSA_AES_KEY_WRAP: &str = "RSA-AES-KEY-WRAP";
pub const CANONICAL_MECHANISMS: [&str; 17] = [
    AES_ECB,
    AES_CBC,
    AES_CTR,
    AES_GCM,
    AES_CMAC,
    AES_GMAC,
    HMAC,
    RSA_OAEP,
    RSA_PKCS1,
    RSA_PSS,
    RSA_RAW,
    ECDSA,
    EDDSA,
    ECDH,
    AES_KEY_WRAP,
    AES_KEY_WRAP_PAD,
    RSA_AES_KEY_WRAP,
];
