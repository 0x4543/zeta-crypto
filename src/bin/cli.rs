use anyhow::Result;
use clap::{Parser, Subcommand};
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
    WalletConnectLastUpdated {
        peer: String,
    },
    WalletConnectSave {
        peer: String,
    },
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
                None => {
                    println!("No default_peer found in config. Create ~/.zeta_crypto/config.toml with e.g.:\n\ndefault_peer = \"wc:example@2?relay-protocol=irn&symKey=...\"\nauto_connect = true");
                }
            }
        }
        Commands::WalletConnectLastUpdated { peer } => {
            let session = WalletConnectSession::new(&peer);
            println!("{}", session.last_updated());
        }
        Commands::WalletConnectSave { peer } => {
            let session = WalletConnectSession::new(&peer);
            if let Err(e) = session.save_to_file() {
                println!("Failed to save session: {}", e);
            } else {
                println!("Session saved.");
            }
        }
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
            println!("Platform: {} {}", env::consts::OS, env::consts::ARCH);
        }
        Commands::HealthCheck => {
            use std::path::PathBuf;
            let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            dir.push(".zeta_crypto");

            let cfg = dir.join("config.toml");
            let session = dir.join("session.json");
            let log = dir.join("logs.txt");

            println!("Health Check:");
            println!("- Config exists: {}", cfg.exists());
            println!("- Session file exists: {}", session.exists());
            println!("- Log file exists: {}", log.exists());
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
            use std::path::PathBuf;
            let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push(".zeta_crypto/logs.txt");
            if path.exists() {
                let metadata = std::fs::metadata(&path)?;
                let size = metadata.len();
                if size < 1024 {
                    println!("Log file size: {} bytes", size);
                } else {
                    println!("Log file size: {:.2} KB", size as f64 / 1024.0);
                }
            } else {
                println!("Log file not found at {}", path.display());
            }
        }
        Commands::Env => {
            let rustc = std::process::Command::new("rustc")
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
            println!("Zeta Crypto CLI — command overview:\n");
            println!("  gen-mnemonic              → Generate new BIP39 mnemonic");
            println!("  derive-wallet             → Derive wallet from mnemonic");
            println!("  sign                      → Sign a message");
            println!("  verify                    → Verify a signature");
            println!("  walletconnect             → Connect or disconnect a WalletConnect peer");
            println!("  walletconnect-status       → Check WalletConnect session status");
            println!("  walletconnect-info         → Show peer info");
            println!("  walletconnect-restore      → Restore last saved session");
            println!("  walletconnect-default      → Use default peer from config");
            println!("  config-show               → Display configuration");
            println!("  version-info              → Show version and environment info");
            println!("  healthcheck               → Check local setup");
            println!("  cleanup                   → Remove logs and sessions");
            println!("  help-all                  → Show this command overview\n");
            println!("Examples:");
            println!("  zeta-cli gen-mnemonic");
            println!("  zeta-cli derive-wallet --phrase \"<mnemonic>\"");
            println!("  zeta-cli walletconnect --peer <peer> --action connect");
        }
        Commands::ClearLogs => {
            use std::io::{self, Write};
            use std::path::PathBuf;

            let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            dir.push(".zeta_crypto");
            let log_path = dir.join("logs.txt");

            if log_path.exists() {
                print!(
                    "This will clear {}. Type 'yes' to confirm: ",
                    log_path.display()
                );
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();

                if input.trim().eq_ignore_ascii_case("yes") {
                    std::fs::write(&log_path, "").expect("Failed to clear log file");
                    println!("Logs cleared successfully.");
                } else {
                    println!("Aborted.");
                }
            } else {
                println!("No logs found at {}", log_path.display());
            }
        }
        Commands::LogPath => {
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto/logs.txt");
            println!("{}", dir.display());
        }
        Commands::ConfigPath => {
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto/config.toml");
            println!("{}", dir.display());
        }
        Commands::SessionPath => {
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto/session.json");
            println!("{}", dir.display());
        }
        Commands::CachePath => {
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto/cache");
            println!("{}", dir.display());
        }
        Commands::DataDir => {
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto");
            println!("{}", dir.display());
        }
        Commands::ListFiles => {
            use std::fs;

            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto");

            match fs::read_dir(&dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        println!("{}", entry.path().display());
                    }
                }
                Err(_) => println!("Directory not found: {}", dir.display()),
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
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto/config.toml");
            println!("{}", dir.exists());
        }
        Commands::SessionExists => {
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto/session.json");
            println!("{}", dir.exists());
        }
        Commands::LogsExist => {
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto/logs.txt");
            println!("{}", dir.exists());
        }
        Commands::ConfigDir => {
            let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
            dir.push(".zeta_crypto");
            println!("{}", dir.display());
        }
        Commands::WalletConnectOpenLog => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");

            if !path.exists() {
                println!("Log file not found.");
                return Ok(());
            }

            #[cfg(target_os = "macos")]
            let cmd = "open";
            #[cfg(target_os = "linux")]
            let cmd = "xdg-open";
            #[cfg(target_os = "windows")]
            let cmd = "start";

            let _ = std::process::Command::new(cmd)
                .arg(path.to_string_lossy().to_string())
                .spawn();

            println!("Opening log file...");
        }
    }

    Ok(())
}
