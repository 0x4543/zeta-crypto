use anyhow::Result;
use clap::{Parser, Subcommand};
use sha2::Digest;
use std::env;
use std::process::Command;
use zeta_crypto::cli_utils;
use zeta_crypto::{MnemonicHelper, Signer, Wallet, WalletConnectSession, ZetaConfig};

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
    HealthCheck,
    Cleanup,
    DeriveWallet {
        phrase: String,
        pass: Option<String>,
    },
    Sign {
        phrase: String,
        pass: Option<String>,
        msg: String,
    },
    Verify {
        pubhex: String,
        msg: String,
        sig: String,
    },
    WalletConnect {
        peer: String,
        action: String,
    },
    WalletConnectStatus {
        peer: String,
    },
    WalletConnectInfo {
        peer: String,
    },
    WalletConnectRestore,
    WalletConnectDefault {
        action: String,
    },
    WalletConnectLast,
    WalletConnectLastUpdated {
        peer: String,
    },
    WalletConnectSave {
        peer: String,
    },
    WalletConnectIsDefault {
        peer: String,
    },
    WalletConnectShortStatus {
        peer: String,
    },
    WalletConnectAlive,
    WalletConnectPeerHash,
    ConfigShow,
    Env,
    HelpAll,
    ClearLogs,
    LogPath,
    ConfigPath,
    SessionPath,
    LogSize,
    CachePath,
    DataDir,
    ListFiles,
    CpuCores,
    Timestamp,
    ConfigExists,
    SessionExists,
    LogsExist,
    ConfigDir,
    WalletConnectOpenLog,
    WalletConnectActive,
    ShowPeer,
    PrintAddress {
        phrase: String,
        pass: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::GenMnemonic => {
            let mn = MnemonicHelper::generate();
            println!("{}", mn);
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
            let sig = Signer::sign(sk, msg.as_bytes());
            println!("{}", sig);
        }
        Commands::Verify { pubhex, msg, sig } => {
            let bytes = hex::decode(pubhex)?;
            let ep = k256::EncodedPoint::from_bytes(&bytes)
                .map_err(|e| anyhow::anyhow!("Invalid public key bytes: {:?}", e))?;
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
                println!("WalletConnect peer is active and reachable");
            } else {
                println!("Unable to reach peer or session inactive");
            }
        }
        Commands::WalletConnectInfo { peer } => {
            let session = WalletConnectSession::new(&peer);
            println!("Peer: {}", peer);
            println!("Status: {}", session.status());
        }
        Commands::WalletConnectRestore => match WalletConnectSession::from_file() {
            Some(s) => {
                println!("Restored session:");
                println!("Peer: {}", s.peer());
                println!("Status: {}", s.status());
            }
            None => println!("No saved WalletConnect session found"),
        },
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
                None => println!("No default_peer found in config."),
            }
        }
        Commands::WalletConnectLast => match WalletConnectSession::from_file() {
            Some(s) => println!("{}", s.last_updated()),
            None => println!("0"),
        },
        Commands::WalletConnectLastUpdated { peer } => {
            let session = WalletConnectSession::new(&peer);
            println!("{}", session.status());
        }
        Commands::WalletConnectSave { peer } => {
            println!("Not implemented.");
            println!("Requested peer: {}", peer);
        }
        Commands::WalletConnectIsDefault { peer } => {
            let cfg = ZetaConfig::load();
            match cfg.default_peer {
                Some(p) if p == peer => println!("true"),
                _ => println!("false"),
            }
        }
        Commands::WalletConnectAlive => match WalletConnectSession::from_file() {
            Some(s) if s.status().contains("connected") => {
                println!("true");
            }
            _ => println!("false"),
        },
        Commands::ConfigShow => {
            let cfg = ZetaConfig::load();
            println!("{:?}", cfg);
        }
        Commands::VersionInfo => {
            let rustc = Command::new("rustc")
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|_| "unknown".into());
            println!("Zeta Crypto CLI {}", env!("CARGO_PKG_VERSION"));
            println!("Rust compiler: {}", rustc.trim());
            println!(
                "Platform: {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
        }
        Commands::HealthCheck => {
            use std::path::PathBuf;
            let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            dir.push(".zeta_crypto");

            let cfg = dir.join("config.toml");
            let session = dir.join("session.json");
            let log = dir.join("logs.txt");

            println!("Health Check:");
            println!("config.toml:     {}", cfg.exists());
            println!("session.json:    {}", session.exists());
            println!("logs.txt:        {}", log.exists());
        }
        Commands::Cleanup => {
            use std::io::{self, Write};
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto");

            println!(
                "This will remove all logs and saved sessions from {}",
                dir.display()
            );
            print!("Type 'yes' to confirm: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            if input.trim().to_lowercase() == "yes" {
                let _ = std::fs::remove_file(dir.join("logs.txt"));
                let _ = std::fs::remove_file(dir.join("session.json"));
                cli_utils::success("Cleanup completed.");
            } else {
                cli_utils::fail("Aborted.");
            }
        }
        Commands::LogSize => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");
            if path.exists() {
                let metadata = std::fs::metadata(&path)?;
                let size = metadata.len();
                if size < 1024 {
                    println!("{} bytes", size);
                } else {
                    println!("{:.2} KB", size as f64 / 1024.0);
                }
            } else {
                println!("Log file not found");
            }
        }
        Commands::Env => {
            let rustc = Command::new("rustc")
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_else(|_| "unknown".into());
            println!("Zeta CLI version: {}", env!("CARGO_PKG_VERSION"));
            println!("Rust compiler: {}", rustc.trim());
            println!(
                "Platform: {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
        }
        Commands::HelpAll => {
            println!("Commands:");
            println!("gen-mnemonic");
            println!("derive-wallet");
            println!("sign");
            println!("verify");
            println!("walletconnect");
            println!("walletconnect-status");
            println!("walletconnect-info");
            println!("walletconnect-restore");
            println!("walletconnect-default");
            println!("config-show");
            println!("version-info");
            println!("healthcheck");
            println!("cleanup");
            println!("help-all");
        }
        Commands::ClearLogs => {
            use std::io::{self, Write};
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");
            if path.exists() {
                print!("This will clear logs. Type 'yes' to confirm: ");
                io::stdout().flush().unwrap();
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                if input.trim().eq_ignore_ascii_case("yes") {
                    std::fs::write(&path, "")?;
                    println!("Logs cleared.");
                } else {
                    println!("Aborted.");
                }
            } else {
                println!("No logs found.");
            }
        }
        Commands::LogPath => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");
            println!("{}", path.display());
        }
        Commands::ConfigPath => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/config.toml");
            println!("{}", path.display());
        }
        Commands::SessionPath => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/session.json");
            println!("{}", path.display());
        }
        Commands::CachePath => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/cache");
            println!("{}", path.display());
        }
        Commands::DataDir => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto");
            println!("{}", path.display());
        }
        Commands::ListFiles => {
            use std::fs;

            let mut dir = dirs::home_dir().unwrap_or_default();
            dir.push(".zeta_crypto");

            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => {
                    println!("Directory not found");
                    return Ok(());
                }
            };

            let mut files: Vec<String> = entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();

            files.sort();

            for f in files {
                println!("{}", f);
            }
        }
        Commands::CpuCores => {
            let cores = num_cpus::get();
            println!("{}", cores);
        }
        Commands::Timestamp => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            println!("{}", now);
        }
        Commands::ConfigExists => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/config.toml");
            println!("{}", path.exists());
        }
        Commands::SessionExists => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/session.json");
            println!("{}", path.exists());
        }
        Commands::LogsExist => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");
            println!("{}", path.exists());
        }
        Commands::ConfigDir => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto");
            println!("{}", path.display());
        }
        Commands::WalletConnectOpenLog => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");

            if !path.exists() {
                println!("Log file not found");
                return Ok(());
            }

            let cmd = {
                #[cfg(target_os = "macos")]
                {
                    "open"
                }
                #[cfg(target_os = "linux")]
                {
                    "xdg-open"
                }
                #[cfg(target_os = "windows")]
                {
                    "start"
                }
            };

            let _ = std::process::Command::new(cmd)
                .arg(path.to_string_lossy().to_string())
                .spawn();

            println!("Opening log file...");
        }
        Commands::ShowPeer => {
            let cfg = ZetaConfig::load();
            match cfg.default_peer {
                Some(p) => println!("{}", p),
                None => println!("No default peer set"),
            }
        }
        Commands::PrintAddress { phrase, pass } => {
            let mn = MnemonicHelper::from_phrase(&phrase)?;
            let w = Wallet::from_mnemonic(&mn, pass.as_deref().unwrap_or(""));
            println!("{}", w.address_hex());
        }
        Commands::WalletConnectPeerHash => match WalletConnectSession::from_file() {
            Some(s) => {
                let hash = hex::encode(sha2::Sha256::digest(s.peer().as_bytes()));
                println!("{}", &hash[0..16]);
            }
            None => println!("No saved session"),
        },
        Commands::WalletConnectActive => match WalletConnectSession::from_file() {
            Some(s) => {
                if s.status().contains("connected") {
                    println!("true");
                } else {
                    println!("false");
                }
            }
            None => println!("false"),
        },
        Commands::WalletConnectShortStatus { peer } => {
            let session = WalletConnectSession::new(&peer);
            let s = session.status();
            if s.contains("connected") {
                println!("connected");
            } else {
                println!("disconnected");
            }
        }
    }

    Ok(())
}
