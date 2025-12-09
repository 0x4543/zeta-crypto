use crate::mnemonic;
use crate::signer;
use anyhow::Result;
use bip39::Mnemonic;
use hmac::Hmac;
use k256::ecdsa::{SigningKey, VerifyingKey};
use pbkdf2::pbkdf2;
use sha2::Sha256;

pub struct Wallet {
    sk: SigningKey,
    pk: VerifyingKey,
}

impl Wallet {
    pub fn from_phrase(phrase: &str, passphrase: &str) -> Result<Self> {
        let mn = mnemonic::from_phrase(phrase)?;
        Self::from_mnemonic(&mn, passphrase)
    }

    pub fn from_mnemonic(mn: &Mnemonic, passphrase: &str) -> Result<Self> {
        let seed = mnemonic::to_seed(mn, passphrase);
        let salt = b"zeta-crypto-wallet";
        let mut key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(&seed, salt, 100_000, &mut key).expect("pbkdf2");

        let sk = SigningKey::from_slice(&key)
            .map_err(|_| anyhow::anyhow!("Failed to derive valid signing key"))?;
        let pk = VerifyingKey::from(&sk);
        Ok(Wallet { sk, pk })
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.sk
    }

    pub fn address_hex(&self) -> String {
        let encoded = self.pk.to_encoded_point(false);
        hex::encode(encoded.as_bytes())
    }

    pub fn sign_message(&self, msg: &[u8]) -> String {
        signer::sign(&self.sk, msg)
    }
}