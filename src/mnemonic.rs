use bip39::{Language, Mnemonic};
use rand::RngCore;

pub struct MnemonicHelper;

impl MnemonicHelper {
    pub fn generate() -> Mnemonic {
        let mut entropy = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut entropy);
        Mnemonic::from_entropy(&entropy).expect("entropy length ok")
    }

    pub fn from_phrase(phrase: &str) -> anyhow::Result<Mnemonic> {
        Ok(Mnemonic::parse_in_normalized(Language::English, phrase)?)
    }

    pub fn to_seed(mnemonic: &Mnemonic, passphrase: &str) -> Vec<u8> {
        let seed = mnemonic.to_seed_normalized(passphrase);
        seed.to_vec()
    }
}
