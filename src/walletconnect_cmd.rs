use crate::{WalletConnectSession, ZetaConfig};
use anyhow::Result;
use sha2::Digest;
use std::process::Command;

pub fn handle_action(peer: String, action: String) -> Result<()> {
    let mut session = WalletConnectSession::new(&peer);
    match action.as_str() {
        "connect" => session.connect(),
        "disconnect" => session.disconnect(),
        _ => println!("Unknown action: {}", action),
    }
    println!("{}", session.status());
    Ok(())
}

pub fn handle_status(peer: String) -> Result<()> {
    let session = WalletConnectSession::new(&peer);
    if session.is_connected() {
        println!("WalletConnect peer is active and reachable");
    } else {
        println!("Unable to reach peer or session inactive");
    }
    Ok(())
}

pub fn handle_info(peer: String) -> Result<()> {
    let session = WalletConnectSession::new(&peer);
    println!("Peer: {}", peer);
    println!("Status: {}", session.status());
    Ok(())
}

pub fn handle_restore() -> Result<()> {
    match WalletConnectSession::from_file() {
        Some(s) => {
            println!("Restored session:");
            println!("Peer: {}", s.peer());
            println!("Status: {}", s.status());
        }
        None => println!("No saved WalletConnect session found"),
    }
    Ok(())
}

pub fn handle_default(action: &str) {
    let cfg = ZetaConfig::load();
    match cfg.default_peer {
        Some(peer) => {
            let mut session = WalletConnectSession::new(&peer);
            match action {
                "connect" => session.connect(),
                "disconnect" => session.disconnect(),
                _ => {
                    println!("Unknown action");
                    return;
                }
            }
            println!("{}", session.status());
        }
        None => println!("No default_peer found in config."),
    }
}

pub fn handle_last() -> Result<()> {
    match WalletConnectSession::from_file() {
        Some(s) => println!("{}", s.last_updated()),
        None => println!("0"),
    }
    Ok(())
}

pub fn handle_last_updated(peer: &str) -> Result<()> {
    let session = WalletConnectSession::new(peer);
    println!("{}", session.status());
    Ok(())
}

pub fn handle_save(peer: String) {
    println!("Not implemented.");
    println!("Requested peer: {}", peer);
}

pub fn handle_is_default(peer: &str) {
    let cfg = ZetaConfig::load();
    match cfg.default_peer {
        Some(p) if p == peer => println!("true"),
        _ => println!("false"),
    }
}

pub fn handle_short_status(peer: String) -> Result<()> {
    let session = WalletConnectSession::new(&peer);
    if session.is_connected() {
        println!("connected");
    } else {
        println!("disconnected");
    }
    Ok(())
}

pub fn handle_alive() {
    match WalletConnectSession::from_file() {
        Some(s) => {
            if s.is_connected() {
                println!("true");
            } else {
                println!("false");
            }
        }
        None => println!("false"),
    }
}

pub fn handle_active() {
    match WalletConnectSession::from_file() {
        Some(s) => {
            if s.is_connected() {
                println!("true");
            } else {
                println!("false");
            }
        }
        None => println!("false"),
    }
}

pub fn handle_peer_hash() {
    match WalletConnectSession::from_file() {
        Some(s) => {
            let hash = hex::encode(sha2::Sha256::digest(s.peer().as_bytes()));
            println!("{}", &hash[0..16]);
        }
        None => println!("No saved session"),
    }
}

pub fn handle_peer_upper(peer: &str) {
    println!("{}", peer.to_uppercase());
}

pub fn handle_peer_len(peer: &str) {
    println!("{}", peer.len());
}

pub fn handle_show_default_peer() {
    let cfg = ZetaConfig::load();
    match cfg.default_peer {
        Some(p) => println!("{}", p),
        None => println!("No default peer set"),
    }
}

pub fn handle_open_log() -> Result<()> {
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

    let _ = Command::new(cmd)
        .arg(path.to_string_lossy().to_string())
        .spawn();

    println!("Opening log file...");
    Ok(())
}