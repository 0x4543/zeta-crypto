use anyhow::Result;
use clap::{Parser, Subcommand};
use sha2::Digest;
use std::env;
use std::process::Command;
use zeta_crypto::cli_utils;
use zeta_crypto::{WalletConnectSession, ZetaConfig};

use zeta_crypto::crypto_cmd;
use zeta_crypto::version::print_version_info;
use zeta_crypto::walletconnect_cmd;

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
    WalletConnectPeerUpper {
        peer: String,
    },
    WalletConnectPeerLen {
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
    WalletConnectActive,
    ShowPeer,
    PrintAddress {
        phrase: String,
        pass: Option<String>,
    },
    LogCount,
    SessionSize,
    Cwd,
    ConfigSize,
    SessionModified,
    DataFileCount,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::GenMnemonic => {
            crypto_cmd::handle_gen_mnemonic()?;
        }
        Commands::DeriveWallet { phrase, pass } => {
            crypto_cmd::handle_derive_wallet(&phrase, pass.as_deref())?;
        }
        Commands::Sign { phrase, pass, msg } => {
            crypto_cmd::handle_sign(&phrase, pass.as_deref(), &msg)?;
        }
        Commands::Verify { pubhex, msg, sig } => {
            crypto_cmd::handle_verify(&pubhex, &msg, &sig)?;
        }
        Commands::PrintAddress { phrase, pass } => {
            crypto_cmd::handle_print_address(&phrase, pass.as_deref())?;
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
            walletconnect_cmd::handle_status(peer)?;
        }
        Commands::WalletConnectInfo { peer } => {
            walletconnect_cmd::handle_info(peer)?;
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
            walletconnect_cmd::handle_default(&action);
        }
        Commands::WalletConnectLast => {
            walletconnect_cmd::handle_last()?;
        }
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
        Commands::WalletConnectAlive => {
            walletconnect_cmd::handle_alive();
        }
        Commands::ConfigShow => {
            let cfg = ZetaConfig::load();
            println!("{:?}", cfg);
        }
        Commands::VersionInfo => {
            print_version_info();
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
        Commands::WalletConnectPeerHash => {
            walletconnect_cmd::handle_peer_hash();
        }
        Commands::WalletConnectActive => match WalletConnectSession::from_file() {
            Some(s) => {
                if s.is_connected() {
                    println!("true");
                } else {
                    println!("false");
                }
            }
            None => println!("false"),
        },
        Commands::WalletConnectShortStatus { peer } => {
            walletconnect_cmd::handle_short_status(peer)?;
        }
        Commands::WalletConnectPeerLen { peer } => {
            walletconnect_cmd::handle_peer_len(&peer);
        }
        Commands::LogCount => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");
            if !path.exists() {
                println!("0");
                return Ok(());
            }
            let content = std::fs::read_to_string(&path)?;
            let count = content.lines().count();
            println!("{}", count);
        }
        Commands::WalletConnectPeerUpper { peer } => {
            walletconnect_cmd::handle_peer_upper(&peer);
        }
        Commands::SessionSize => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/session.json");
            if let Ok(meta) = std::fs::metadata(&path) {
                println!("{}", meta.len());
            } else {
                println!("0");
            }
        }
        Commands::Cwd => {
            if let Ok(path) = std::env::current_dir() {
                println!("{}", path.display());
            }
        }
        Commands::ConfigSize => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/config.toml");
            if let Ok(meta) = std::fs::metadata(&path) {
                println!("{}", meta.len());
            } else {
                println!("0");
            }
        }
        Commands::SessionModified => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/session.json");
            if let Ok(meta) = std::fs::metadata(&path) {
                if let Ok(time) = meta.modified() {
                    if let Ok(secs) = time.duration_since(std::time::UNIX_EPOCH) {
                        println!("{}", secs.as_secs());
                    }
                }
            }
        }
        Commands::DataFileCount => {
            let mut dir = dirs::home_dir().unwrap_or_default();
            dir.push(".zeta_crypto");
            if let Ok(read) = std::fs::read_dir(&dir) {
                let count = read.count();
                println!("{}", count);
            } else {
                println!("0");
            }
        }
    }

    Ok(())
}
