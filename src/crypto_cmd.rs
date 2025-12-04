use crate::{MnemonicHelper, Signer, Wallet};
use anyhow::Result;

pub fn handle_gen_mnemonic() -> Result<()> {
    let mn = MnemonicHelper::generate();
    println!("{}", mn);
    Ok(())
}

pub fn handle_derive_wallet(phrase: &str, pass: Option<&str>) -> Result<()> {
    let w = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    println!("{}", w.address_hex());
    Ok(())
}

pub fn handle_sign(phrase: &str, pass: Option<&str>, msg: &str) -> Result<()> {
    let w = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    let sig = w.sign_message(msg.as_bytes());
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
    let w = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    println!("{}", w.address_hex());
    Ok(())
}