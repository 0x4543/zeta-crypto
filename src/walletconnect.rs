use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
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
        self.save_to_file();
    }

    pub fn disconnect(&mut self) {
        self.status = "disconnected".to_string();
        self.last_updated = current_timestamp();
        self.save_to_file();
    }

    pub fn status(&self) -> String {
        format!("{} (updated at {})", self.status, self.last_updated)
    }

    pub fn peer(&self) -> &str {
        &self.peer
    }

    pub fn from_file() -> Option<Self> {
        let path = session_file_path();
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn save_to_file(&self) {
        let path = session_file_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn session_file_path() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".zeta_crypto");
    dir.push("session.json");
    dir
}