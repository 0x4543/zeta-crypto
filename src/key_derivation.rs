use hmac::Hmac;
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use hex;

type HmacSha256 = Hmac<Sha256>;

/// Derive a key of `output_len` bytes from given `seed` and `salt` using PBKDF2.
pub fn derive_key_pbkdf2(seed: &[u8], salt: &[u8], iterations: u32, output_len: usize) -> String {
    let mut out = vec![0u8; output_len];
    pbkdf2_hmac::<HmacSha256>(seed, salt, iterations, &mut out);
    hex::encode(out)
}

/// Derive a key of `output_len` bytes from given `seed` and `salt` using HKDF-SHA256.
pub fn derive_key_hkdf(seed: &[u8], salt: &[u8], output_len: usize) -> String {
    use sha2::Sha256 as H;
    use hkdf::Hkdf;

    let hk = Hkdf::<H>::new(Some(salt), seed);
    let mut okm = vec![0u8; output_len];
    hk.expand(&[], &mut okm).expect("HKDF expand failed");
    hex::encode(okm)
}