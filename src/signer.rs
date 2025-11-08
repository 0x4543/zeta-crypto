use anyhow::Result;
use k256::ecdsa::{
    signature::{DigestSigner, DigestVerifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

pub struct Signer;

impl Signer {
    pub fn sign(sk: &SigningKey, msg: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let sig: Signature = sk.sign_digest(hasher);
        hex::encode(sig.to_der().as_bytes())
    }

    pub fn verify(vk: &VerifyingKey, msg: &[u8], sig_hex: &str) -> Result<bool> {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let bytes = hex::decode(sig_hex)?;
        let sig = Signature::from_der(&bytes)?;
        Ok(vk.verify_digest(hasher, &sig).is_ok())
    }
}
