use k256::ecdsa::{SigningKey, Signature, signature::{Signer as _, Verifier as _}};
use hex;

pub struct Signer;

impl Signer {
    pub fn sign(signing_key: &SigningKey, msg: &[u8]) -> String {
        let sig: Signature = signing_key.sign(msg);
        hex::encode(sig.as_ref())
    }

    pub fn verify(verifying_key: &k256::ecdsa::VerifyingKey, msg: &[u8], sig_hex: &str) -> anyhow::Result<bool> {
        let sig_bytes = hex::decode(sig_hex)?;
        let sig = Signature::from_der(&sig_bytes)?;
        Ok(verifying_key.verify(msg, &sig).is_ok())
    }
}
