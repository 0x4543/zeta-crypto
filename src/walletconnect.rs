use std::time::{SystemTime, UNIX_EPOCH};

pub struct WalletConnectSession {
    peer: String,
    status: String,
    last_updated: u64,
}

impl WalletConnectSession {
    pub fn new(peer: &str) -> Self {
        Self {
            peer: peer.to_string(),
            status: "disconnected".to_string(),
            last_updated: current_timestamp(),
        }
    }

    pub fn connect(&mut self) {
        self.status = "connected".to_string();
        self.last_updated = current_timestamp();
    }

    pub fn disconnect(&mut self) {
        self.status = "disconnected".to_string();
        self.last_updated = current_timestamp();
    }

    pub fn status(&self) -> String {
        format!("{} (updated at {})", self.status, self.last_updated)
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}