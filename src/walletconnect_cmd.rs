use anyhow::Result;
use crate::WalletConnectSession;

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