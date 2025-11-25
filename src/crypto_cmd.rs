use anyhow::Result;
use crate::{MnemonicHelper, Signer, Wallet};

pub fn handle_gen_mnemonic() -> Result<()> {
    let mn = MnemonicHelper::generate();
    println!("{}", mn);
    Ok(())
}

pub fn handle_derive_wallet(phrase: &str, pass: Option<&str>) -> Result<()> {
    let mn = MnemonicHelper::from_phrase(phrase)?;
    let w = Wallet::from_mnemonic(&mn, pass.unwrap_or(""));
    println!("{}", w.address_hex());
    Ok(())
}

pub fn handle_sign(phrase: &str, pass: Option<&str>, msg: &str) -> Result<()> {
    let mn = MnemonicHelper::from_phrase(phrase)?;
    let w = Wallet::from_mnemonic(&mn, pass.unwrap_or(""));
    let sk = w.signing_key();
    let sig = Signer::sign(sk, msg.as_bytes());
    println!("{}", sig);
    Ok(())
}

pub fn handle_verify(pubhex: &str, msg: &str, sig: &str) -> Result<()> {
    let bytes = hex::decode(pubhex)?;
    let ep = k256::EncodedPoint::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("Invalid public key bytes: {:?}", e))?;
    let vk = k256::ecdsa::VerifyingKey::from_encoded_point(&ep)?;
    let ok = Signer::verify(&vk, msg.as_bytes(), sig)?;
    println!("{}", ok);
    Ok(())
}

pub fn handle_print_address(phrase: &str, pass: Option<&str>) -> Result<()> {
    let mn = MnemonicHelper::from_phrase(phrase)?;
    let w = Wallet::from_mnemonic(&mn, pass.unwrap_or(""));
    println!("{}", w.address_hex());
    Ok(())
}