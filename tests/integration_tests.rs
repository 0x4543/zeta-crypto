use k256::ecdsa::VerifyingKey;
use zeta_crypto::{derive_key_hkdf, derive_key_pbkdf2, mnemonic, signer, Wallet};

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

#[test]
fn test_pbkdf2_derivation() {
    let password = "password";
    let salt = b"salt";
    let key = derive_key_pbkdf2(password, salt, 1000, 32);
    assert_eq!(key.len(), 32);
    let key2 = derive_key_pbkdf2(password, salt, 1000, 32);
    assert_eq!(key, key2);
}

#[test]
fn test_hkdf_derivation() {
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"info";
    let key = derive_key_hkdf(ikm, salt, info, 32).expect("hkdf failed");
    assert_eq!(key.len(), 32);
}