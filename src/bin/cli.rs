use clap::{Parser, Subcommand};
use zeta_crypto::{MnemonicHelper, Wallet, Signer, WalletConnectSession, ZetaConfig};
use anyhow::Result;
use hex;
use std::env;
use std::process::Command;

#[derive(Parser)]
#[command(name = "zeta-cli", version, about = "zeta-cli: tiny crypto playground")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    VersionInfo,
    GenMnemonic,
    DeriveWallet { phrase: String, pass: Option<String> },
    Sign { phrase: String, pass: Option<String>, msg: String },
    Verify { pubhex: String, msg: String, sig: String },
    WalletConnect { peer: String, action: String },
    WalletConnectStatus { peer: String },
    WalletConnectInfo { peer: String },
    WalletConnectRestore,
    WalletConnectDefault { action: String },
    ConfigShow,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::GenMnemonic => {
            let mn = MnemonicHelper::generate();
            println!("{}", mn.phrase());
        }
        Commands::DeriveWallet { phrase, pass } => {
            let mn = MnemonicHelper::from_phrase(&phrase)?;
            let w = Wallet::from_mnemonic(&mn, pass.as_deref().unwrap_or(""));
            println!("{}", w.address_hex());
        }
        Commands::Sign { phrase, pass, msg } => {
            let mn = MnemonicHelper::from_phrase(&phrase)?;
            let w = Wallet::from_mnemonic(&mn, pass.as_deref().unwrap_or(""));
            let sk = w.signing_key();
            let sig = Signer::sign(&sk, msg.as_bytes());
            println!("{}", sig);
        }
        Commands::Verify { pubhex, msg, sig } => {
            let bytes = hex::decode(pubhex)?;
            let ep = k256::EncodedPoint::from_bytes(&bytes)?;
            let vk = k256::ecdsa::VerifyingKey::from_encoded_point(&ep)?;
            let ok = Signer::verify(&vk, msg.as_bytes(), &sig)?;
            println!("{}", ok);
        }
        Commands::WalletConnect { peer, action } => {
            let mut session = WalletConnectSession::new(&peer);
            match action.as_str() {
                "connect" => session.connect(),
                "disconnect" => session.disconnect(),
                _ => println!("Unknown action: {}", action),
            }
            println!("{}", session.status());
        }
        Commands::WalletConnectStatus { peer } => {
            let session = WalletConnectSession::new(&peer);
            let connected = session.status().contains("connected");
            if connected {
                println!("✅ WalletConnect peer is active and reachable");
            } else {
                println!("⚠️ Unable to reach peer or session inactive");
            }
        }
        Commands::WalletConnectInfo { peer } => {
            let session = WalletConnectSession::new(&peer);
            println!("Peer: {}", peer);
            println!("Status: {}", session.status());
        }
        Commands::WalletConnectRestore => {
            match WalletConnectSession::from_file() {
                Some(s) => {
                    println!("Restored session:");
                    println!("Peer: {}", s.peer());
                    println!("Status: {}", s.status());
                }
                None => println!("No saved WalletConnect session found"),
            }
        }
        Commands::WalletConnectDefault { action } => {
            let cfg = ZetaConfig::load();
            match cfg.default_peer {
                Some(peer) => {
                    let mut session = WalletConnectSession::new(&peer);
                    match action.as_str() {
                        "connect" => session.connect(),
                        "disconnect" => session.disconnect(),
                        _ => {
                            println!("Unknown action: {}", action);
                            return Ok(());
                        }
                    }
                    println!("{}", session.status());
                }
                None => {
                    println!("No default_peer found in config. Create ~/.zeta_crypto/config.toml with e.g.:\n\ndefault_peer = \"wc:example@2?relay-protocol=irn&symKey=...\"\nauto_connect = true");
                }
            }
        }
        Commands::ConfigShow => {
            let cfg = ZetaConfig::load();
            println!("{:?}", cfg);
        }
        Commands::VersionInfo => {
            let rustc = Command::new("rustc").arg("--version").output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|_| "unknown".into());
            println!("Zeta Crypto CLI {}", env!("CARGO_PKG_VERSION"));
            println!("Rust compiler: {}", rustc.trim());
            println!("Platform: {} {}", env::consts::OS, env::consts::ARCH);
        }
    }

    Ok(())
}