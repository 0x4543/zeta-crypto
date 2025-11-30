use crate::{WalletConnectSession, ZetaConfig};
use anyhow::Result;

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

pub fn handle_last() -> Result<()> {
    match WalletConnectSession::from_file() {
        Some(s) => println!("{}", s.last_updated()),
        None => println!("0"),
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

pub fn handle_short_status(peer: String) -> Result<()> {
    let session = WalletConnectSession::new(&peer);
    if session.is_connected() {
        println!("connected");
    } else {
        println!("disconnected");
    }
    Ok(())
}

pub fn handle_peer_len(peer: &str) {
    println!("{}", peer.len());
}