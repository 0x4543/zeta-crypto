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
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
    },
    Sign {
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
        #[arg(long)]
        msg: String,
    },
    Verify {
        #[arg(long)]
        pubhex: String,
        #[arg(long)]
        msg: String,
        #[arg(long)]
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
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
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
    Balance {
        address: String,
    },
    BalanceUsdc {
        address: String,
    },
    Send {
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
    },
    SendUsdc {
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
    },
    Resolve {
        name: String,
    },
    Deploy {
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
    },
    DisperseEth {
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
        #[arg(long)]
        contract: String,
        #[arg(long, num_args = 1.., value_delimiter = ' ')]
        pairs: Vec<String>,
    },
    Approve {
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
        #[arg(long)]
        token: String,
        #[arg(long)]
        spender: String,
        #[arg(long)]
        amount: String,
        #[arg(long, default_value_t = 18)]
        decimals: u8,
    },
    DisperseToken {
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
        #[arg(long)]
        contract: String,
        #[arg(long)]
        token: String,
        #[arg(long, num_args = 1.., value_delimiter = ' ')]
        pairs: Vec<String>,
        #[arg(long, default_value_t = 18)]
        decimals: u8,
    },
    Gas,
    Allowance {
        #[arg(long)]
        token: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        spender: String,
        #[arg(long, default_value_t = 18)]
        decimals: u8,
    },
    Wrap {
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
        #[arg(long)]
        amount: String,
    },
    Unwrap {
        #[arg(long, env = "ZETA_PHRASE")]
        phrase: String,
        #[arg(long, env = "ZETA_PASS")]
        pass: Option<String>,
        #[arg(long)]
        amount: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc_url = std::env::var("ZETA_RPC_URL").unwrap_or_else(|_| BASE_RPC_URL.to_string());

    match cli.cmd {
        Commands::Base { cmd } => match cmd {
            BaseCommands::Balance { address } => {
                base_cmd::handle_balance(&rpc_url, &address).await?;
            }
            BaseCommands::BalanceUsdc { address } => {
                base_cmd::handle_balance_usdc(&rpc_url, &address).await?;
            }
            BaseCommands::Send {
                phrase,
                pass,
                to,
                amount,
            } => {
                base_cmd::handle_send(&rpc_url, &phrase, pass.as_deref(), &to, &amount).await?;
            }
            BaseCommands::SendUsdc {
                phrase,
                pass,
                to,
                amount,
            } => {
                base_cmd::handle_send_usdc(&rpc_url, &phrase, pass.as_deref(), &to, &amount)
                    .await?;
            }
            BaseCommands::Resolve { name } => {
                base_cmd::handle_resolve(&rpc_url, &name).await?;
            }
            BaseCommands::Deploy { phrase, pass } => {
                base_cmd::handle_deploy(&rpc_url, &phrase, pass.as_deref()).await?;
            }
            BaseCommands::DisperseEth {
                phrase,
                pass,
                contract,
                pairs,
            } => {
                base_cmd::handle_disperse_eth(&rpc_url, &phrase, pass.as_deref(), &contract, pairs)
                    .await?;
            }
            BaseCommands::Approve {
                phrase,
                pass,
                token,
                spender,
                amount,
                decimals,
            } => {
                base_cmd::handle_approve(
                    &rpc_url,
                    &phrase,
                    pass.as_deref(),
                    &token,
                    &spender,
                    &amount,
                    decimals,
                )
                .await?;
            }
            BaseCommands::DisperseToken {
                phrase,
                pass,
                contract,
                token,
                pairs,
                decimals,
            } => {
                base_cmd::handle_disperse_token(
                    &rpc_url,
                    &phrase,
                    pass.as_deref(),
                    &contract,
                    &token,
                    pairs,
                    decimals,
                )
                .await?;
            }
            BaseCommands::Gas => {
                base_cmd::handle_gas_price(&rpc_url).await?;
            }
            BaseCommands::Allowance {
                token,
                owner,
                spender,
                decimals,
            } => {
                base_cmd::handle_allowance(&rpc_url, &token, &owner, &spender, decimals).await?;
            }
            BaseCommands::Wrap {
                phrase,
                pass,
                amount,
            } => {
                base_cmd::handle_wrap(&rpc_url, &phrase, pass.as_deref(), &amount).await?;
            }
            BaseCommands::Unwrap {
                phrase,
                pass,
                amount,
            } => {
                base_cmd::handle_unwrap(&rpc_url, &phrase, pass.as_deref(), &amount).await?;
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