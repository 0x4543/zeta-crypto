use bip39::{Mnemonic, Language, Seed};
use rand::RngCore;

pub struct MnemonicHelper;

impl MnemonicHelper {
    pub fn generate() -> Mnemonic {
        let mut entropy = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut entropy);
        Mnemonic::from_entropy(&entropy, Language::English).expect("entropy length ok")
    }

    pub fn from_phrase(phrase: &str) -> anyhow::Result<Mnemonic> {
        Ok(Mnemonic::from_phrase(phrase, Language::English)?)
    }

    pub fn to_seed(mn: &Mnemonic, passphrase: &str) -> Seed {
        Seed::new(mn, passphrase)
    }
}
