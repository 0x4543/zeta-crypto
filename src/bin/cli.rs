use anyhow::Result;
use clap::{Parser, Subcommand};
use sha2::Digest;
use std::env;
use std::process::Command;
use zeta_crypto::cli_utils;
use zeta_crypto::{WalletConnectSession, ZetaConfig};

use zeta_crypto::crypto_cmd;
use zeta_crypto::fs_cmd;
use zeta_crypto::fs_manage_cmd;
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
            fs_manage_cmd::health_report(cfg, session, log);
        }

        Commands::Cleanup => {
            use std::path::PathBuf;
            let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            dir.push(".zeta_crypto");
            if fs_manage_cmd::confirm("Type yes to confirm: ") {
                fs_manage_cmd::cleanup(dir);
                cli_utils::success("Cleanup completed.");
            } else {
                cli_utils::fail("Aborted.");
            }
        }

        Commands::ClearLogs => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");
            fs_manage_cmd::clear_logs(path);
            println!("Logs cleared.");
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

        Commands::LogSize => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");
            println!("{}", fs_cmd::file_size(path));
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
            use std::path::PathBuf;
            let mut dir = dirs::home_dir().unwrap_or_default();
            dir.push(".zeta_crypto");
            for f in fs_cmd::list_files(dir) {
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
            println!("{}", fs_cmd::health_exists(path));
        }
        Commands::SessionExists => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/session.json");
            println!("{}", fs_cmd::health_exists(path));
        }
        Commands::LogsExist => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");
            println!("{}", fs_cmd::health_exists(path));
        }

        Commands::ConfigDir => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto");
            println!("{}", path.display());
        }

        Commands::WalletConnectOpenLog => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");
            fs_manage_cmd::open_log(path);
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
            println!("{}", fs_cmd::log_count(path));
        }

        Commands::WalletConnectPeerUpper { peer } => {
            walletconnect_cmd::handle_peer_upper(&peer);
        }

        Commands::SessionSize => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/session.json");
            println!("{}", fs_cmd::file_size(path));
        }

        Commands::Cwd => {
            println!("{}", fs_cmd::cwd());
        }

        Commands::ConfigSize => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/config.toml");
            println!("{}", fs_cmd::file_size(path));
        }

        Commands::SessionModified => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/session.json");
            if let Ok(meta) = std::fs::metadata(path) {
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
            println!("{}", fs_cmd::file_count(dir));
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
    }

    Ok(())
}
