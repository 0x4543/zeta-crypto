use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Sha256, Sha512};
use hkdf::Hkdf;

pub fn derive_key_pbkdf2(pass: &str, salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    pbkdf2::<Hmac<Sha256>>(pass.as_bytes(), salt, iterations, &mut out);
    out
}

pub fn derive_key_hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}