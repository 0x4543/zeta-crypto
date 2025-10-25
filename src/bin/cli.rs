use clap::{Parser, Subcommand};
use anyhow::Result;
use zeta_crypto::{MnemonicHelper, Wallet, Signer};

#[derive(Parser)]
#[command(author, version, about = "zeta-cli: tiny crypto playground")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenMnemonic,
    Derive { phrase: String, pass: Option<String> },
    Sign { phrase: String, pass: Option<String>, msg: String },
    Verify { pubhex: String, msg: String, sig: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::GenMnemonic => {
            let mn = MnemonicHelper::generate();
            println!("mnemonic: {}", mn.phrase());
        }
        Commands::Derive { phrase, pass } => {
            let mn = MnemonicHelper::from_phrase(&phrase)?;
            let w = Wallet::from_mnemonic(&mn, pass.as_deref().unwrap_or("") );
            println!("address: {}", w.address_hex());
        }
        Commands::Sign { phrase, pass, msg } => {
            let mn = MnemonicHelper::from_phrase(&phrase)?;
            let w = Wallet::from_mnemonic(&mn, pass.as_deref().unwrap_or("") );
            let sk = w.signing_key();
            let sig = Signer::sign(&sk, msg.as_bytes());
            println!("sig: {}", sig);
        }
        Commands::Verify { pubhex: _pubhex, msg, sig } => {
            use k256::EncodedPoint;
            let bytes = hex::decode(_pubhex)?;
            let ep = EncodedPoint::from_bytes(&bytes)?;
            let vk = k256::ecdsa::VerifyingKey::from_encoded_point(&ep)?;
            let ok = Signer::verify(&vk, msg.as_bytes(), &sig)?;
            println!("verified: {}", ok);
        }
    }
    Ok(())
}
