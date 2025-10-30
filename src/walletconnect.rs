pub struct WalletConnectSession {
    pub peer_name: String,
    pub connected: bool,
}

impl WalletConnectSession {
    pub fn new(peer_name: &str) -> Self {
        Self {
            peer_name: peer_name.to_string(),
            connected: false,
        }
    }

    pub fn connect(&mut self) {
        println!("Connecting to WalletConnect peer: {}", self.peer_name);
        self.connected = true;
    }

    pub fn disconnect(&mut self) {
        println!("Disconnecting from WalletConnect peer: {}", self.peer_name);
        self.connected = false;
    }

    pub fn status(&self) -> &str {
        if self.connected { "connected" } else { "disconnected" }
    }
}