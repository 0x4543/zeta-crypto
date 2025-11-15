pub mod cli_utils;
pub mod config;
pub mod key_derivation;
pub mod mnemonic;
pub mod signer;
pub mod wallet;
pub mod walletconnect;

pub use cli_utils::*;
pub use config::ZetaConfig;
pub use key_derivation::{derive_key_hkdf, derive_key_pbkdf2};
pub use mnemonic::MnemonicHelper;
pub use signer::Signer;
pub use wallet::Wallet;
pub use walletconnect::WalletConnectSession;

pub fn build_info() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let target = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    format!("zeta-crypto {} | target {}", version, target)
}
