use zeta_crypto::WalletConnectSession;

pub fn walletconnect_status(peer: &str) {
    let session = WalletConnectSession::new(peer);
    let connected = session.status().contains("connected");
    if connected {
        println!("WalletConnect peer is active and reachable");
    } else {
        println!("Unable to reach peer or session inactive");
    }
}

pub fn walletconnect_info(peer: &str) {
    let session = WalletConnectSession::new(peer);
    println!("Peer: {}", peer);
    println!("Status: {}", session.status());
}

pub fn walletconnect_last() {
    match WalletConnectSession::from_file() {
        Some(s) => println!("{}", s.last_updated()),
        None => println!("0"),
    }
}