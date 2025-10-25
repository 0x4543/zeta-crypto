use crate::mnemonic::MnemonicHelper;
use bip39::Mnemonic;
use pbkdf2::pbkdf2_hmac;
use hmac::Hmac;
use sha2::Sha256;
use k256::{ecdsa::{SigningKey, VerifyingKey}, SecretKey};
use hex;

pub struct Wallet {
    pub secret: SecretKey,
}

impl Wallet {
    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> Self {
        let seed = MnemonicHelper::to_seed(mnemonic, passphrase);
        type HmacSha256 = Hmac<Sha256>;
        let mut out = [0u8; 32];
        let salt = b"zeta-wallet-v0";
        pbkdf2_hmac::<HmacSha256>(seed.as_bytes(), salt, 2048, &mut out);
        let secret = SecretKey::from_be_bytes(&out).expect("derived bytes within curve order (demo)");
        Self { secret }
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from(self.secret.clone())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from(&self.signing_key())
    }

    pub fn address_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        let pubkey = self.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let hash = Sha256::digest(&pubkey);
        hex::encode(&hash[..20])
    }
}
impl Wallet {
    /// Generate a random 32-byte hex key (for demo/testing purposes)
    pub fn generate_random_hex() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        hex::encode(bytes)
    }
}