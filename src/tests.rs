#[cfg(test)]
mod tests {
    use crate::{MnemonicHelper, Wallet, Signer};

    #[test]
    fn test_wallet_address_length() {
        let mn = MnemonicHelper::generate();
        let wallet = Wallet::from_mnemonic(&mn, "");
        let address = wallet.address_hex();
        assert_eq!(address.len(), 40); // 20 bytes hex
    }

    #[test]
    fn test_sign_verify() {
        let mn = MnemonicHelper::generate();
        let wallet = Wallet::from_mnemonic(&mn, "");
        let sk = wallet.signing_key();
        let vk = wallet.verifying_key();
        let msg = b"test message";

        let sig = Signer::sign(&sk, msg);
        let verified = Signer::verify(&vk, msg, &sig).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_generate_random_hex() {
        let hex1 = Wallet::generate_random_hex();
        let hex2 = Wallet::generate_random_hex();
        assert_eq!(hex1.len(), 64);
        assert_eq!(hex2.len(), 64);
        assert_ne!(hex1, hex2); // should generate different values
    }
}