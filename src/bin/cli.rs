use anyhow::Result;
use clap::{Parser, Subcommand};
use sha2::Digest;
use std::process::Command;
use zeta_crypto::sysinfo_cmd;
use zeta_crypto::crypto_cmd;
use zeta_crypto::walletconnect_cmd;
use zeta_crypto::{WalletConnectSession, ZetaConfig};

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
        Commands::VersionInfo => sysinfo_cmd::handle_version()?,
        Commands::HealthCheck => sysinfo_cmd::handle_health_check()?,
        Commands::Cleanup => sysinfo_cmd::handle_cleanup()?,
        Commands::LogSize => sysinfo_cmd::handle_log_size()?,
        Commands::Env => sysinfo_cmd::handle_env()?,
        Commands::ClearLogs => sysinfo_cmd::handle_clear_logs()?,
        Commands::LogPath => sysinfo_cmd::handle_log_path()?,
        Commands::ConfigPath => sysinfo_cmd::handle_config_path()?,
        Commands::SessionPath => sysinfo_cmd::handle_session_path()?,
        Commands::CachePath => sysinfo_cmd::handle_cache_path()?,
        Commands::DataDir => sysinfo_cmd::handle_data_dir()?,
        Commands::ListFiles => sysinfo_cmd::handle_list_files()?,
        Commands::CpuCores => sysinfo_cmd::handle_cpu_cores()?,
        Commands::Timestamp => sysinfo_cmd::handle_timestamp()?,
        Commands::ConfigExists => sysinfo_cmd::handle_config_exists()?,
        Commands::SessionExists => sysinfo_cmd::handle_session_exists()?,
        Commands::LogsExist => sysinfo_cmd::handle_logs_exist()?,
        Commands::ConfigDir => sysinfo_cmd::handle_config_dir()?,
        Commands::LogCount => sysinfo_cmd::handle_log_count()?,
        Commands::SessionSize => sysinfo_cmd::handle_session_size()?,
        Commands::Cwd => sysinfo_cmd::handle_cwd()?,
        Commands::ConfigSize => sysinfo_cmd::handle_config_size()?,
        Commands::SessionModified => sysinfo_cmd::handle_session_modified()?,
        Commands::DataFileCount => sysinfo_cmd::handle_data_file_count()?,
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
        Commands::WalletConnectOpenLog => {
            let mut path = dirs::home_dir().unwrap_or_default();
            path.push(".zeta_crypto/logs.txt");

            if !path.exists() {
                println!("Log file not found");
                return Ok(());
            }

            let cmd = {
                #[cfg(target_os = "macos")] { "open" }
                #[cfg(target_os = "linux")] { "xdg-open" }
                #[cfg(target_os = "windows")] { "start" }
            };

            let _ = Command::new(cmd)
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
        Commands::WalletConnectPeerHash => match WalletConnectSession::from_file() {
            Some(s) => {
                let hash = hex::encode(sha2::Sha256::digest(s.peer().as_bytes()));
                println!("{}", &hash[0..16]);
            }
            None => println!("No saved session"),
        },
        Commands::WalletConnectActive => match WalletConnectSession::from_file() {
            Some(s) => {
                if s.is_connected() { println!("true"); } else { println!("false"); }
            }
            None => println!("false"),
        },
        Commands::WalletConnectShortStatus { peer } => {
            let session = WalletConnectSession::new(&peer);
            if session.is_connected() { println!("connected"); } else { println!("disconnected"); }
        }
        Commands::WalletConnectPeerLen { peer } => {
            println!("{}", peer.len());
        }
        Commands::WalletConnectPeerUpper { peer } => {
            println!("{}", peer.to_uppercase());
        }
    }

    Ok(())
}