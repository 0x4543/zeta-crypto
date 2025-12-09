use anyhow::Result;
use clap::{Parser, Subcommand};
use zeta_crypto::base_cmd;
use zeta_crypto::crypto_cmd;
use zeta_crypto::sysinfo_cmd;
use zeta_crypto::walletconnect_cmd::{self, WcAction};

const BASE_RPC_URL: &str = "https://mainnet.base.org";

#[derive(Parser)]
#[command(name = "zeta-cli", version, about = "zeta-cli: tiny crypto playground")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Base {
        #[command(subcommand)]
        cmd: BaseCommands,
    },
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
        action: WcAction,
    },
    WalletConnectStatus {
        peer: String,
    },
    WalletConnectInfo {
        peer: String,
    },
    WalletConnectRestore,
    WalletConnectDefault {
        action: WcAction,
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

#[derive(Subcommand)]
enum BaseCommands {
    Balance { address: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Base { cmd } => match cmd {
            BaseCommands::Balance { address } => {
                base_cmd::handle_balance(BASE_RPC_URL, &address).await?;
            }
        },
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
            walletconnect_cmd::handle_action(peer, action)?;
        }
        Commands::WalletConnectStatus { peer } => {
            walletconnect_cmd::handle_status(peer)?;
        }
        Commands::WalletConnectInfo { peer } => {
            walletconnect_cmd::handle_info(peer)?;
        }
        Commands::WalletConnectRestore => {
            walletconnect_cmd::handle_restore()?;
        }
        Commands::WalletConnectDefault { action } => {
            walletconnect_cmd::handle_default(action);
        }
        Commands::WalletConnectLast => {
            walletconnect_cmd::handle_last()?;
        }
        Commands::WalletConnectLastUpdated { peer } => {
            walletconnect_cmd::handle_last_updated(&peer)?;
        }
        Commands::WalletConnectSave { peer } => {
            walletconnect_cmd::handle_save(peer);
        }
        Commands::WalletConnectIsDefault { peer } => {
            walletconnect_cmd::handle_is_default(&peer);
        }
        Commands::WalletConnectAlive => {
            walletconnect_cmd::handle_alive();
        }
        Commands::ConfigShow => {
            sysinfo_cmd::handle_config_show()?;
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
        Commands::WalletConnectOpenLog => {
            walletconnect_cmd::handle_open_log()?;
        }
        Commands::ShowPeer => {
            walletconnect_cmd::handle_show_default_peer();
        }
        Commands::WalletConnectPeerHash => {
            walletconnect_cmd::handle_peer_hash();
        }
        Commands::WalletConnectActive => {
            walletconnect_cmd::handle_active();
        }
        Commands::WalletConnectShortStatus { peer } => {
            walletconnect_cmd::handle_short_status(peer)?;
        }
        Commands::WalletConnectPeerLen { peer } => {
            walletconnect_cmd::handle_peer_len(&peer);
        }
        Commands::WalletConnectPeerUpper { peer } => {
            walletconnect_cmd::handle_peer_upper(&peer);
        }
        Commands::HelpAll => {
            sysinfo_cmd::handle_help_all()?;
        }
    }

    Ok(())
}