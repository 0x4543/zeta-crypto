#[cfg(test)]
mod tests {
    use crate::{mnemonic, signer, Wallet};
    use k256::ecdsa::VerifyingKey;

    #[test]
    fn test_wallet_pubkey_length() {
        let mn = mnemonic::generate();
        let wallet = Wallet::from_mnemonic(&mn, "").expect("failed to create wallet");
        let address = wallet.address_hex();
        assert_eq!(address.len(), 130);
    }

    #[test]
    fn test_sign_verify() {
        let mn = mnemonic::generate();
        let wallet = Wallet::from_mnemonic(&mn, "").expect("failed to create wallet");
        let msg = b"test message";

        let sig = wallet.sign_message(msg);

        let sk = wallet.signing_key();
        let vk = VerifyingKey::from(sk);

        let verified = signer::verify(&vk, msg, &sig).expect("verification failed");
        assert!(verified);
    }
}