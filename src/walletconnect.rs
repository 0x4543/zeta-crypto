use crate::storage;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_MAX_BYTES: u64 = 262_144;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletConnectSession {
    peer: String,
    status: String,
    last_updated: u64,
    #[serde(skip)]
    _dirty: bool,
}

impl WalletConnectSession {
    pub fn new(peer: &str) -> Self {
        Self {
            peer: peer.to_string(),
            status: "disconnected".to_string(),
            last_updated: current_timestamp(),
            _dirty: false,
        }
    }

    pub fn connect(&mut self) {
        self.status = "connected".to_string();
        self.last_updated = current_timestamp();
        let _ = self.save_to_file();
        let _ = log_event(&format!("connect peer={}", self.peer));
    }

    pub fn disconnect(&mut self) {
        self.status = "disconnected".to_string();
        self.last_updated = current_timestamp();
        let _ = self.save_to_file();
        let _ = log_event(&format!("disconnect peer={}", self.peer));
    }

    pub fn status(&self) -> String {
        format!("{} (updated at {})", self.status, self.last_updated)
    }

    pub fn peer(&self) -> &str {
        &self.peer
    }

    pub fn from_file() -> Option<Self> {
        let path = storage::get_session_path();
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn last_updated(&self) -> u64 {
        self.last_updated
    }

    pub fn save_to_file(&self) -> io::Result<()> {
        storage::ensure_app_dir()?;
        let path = storage::get_session_path();
        let encoded = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(path, encoded)
    }

    pub fn is_connected(&self) -> bool {
        self.status == "connected"
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn log_event(line: &str) -> io::Result<()> {
    storage::ensure_app_dir()?;
    let path = storage::get_log_path();

    if let Ok(meta) = fs::metadata(&path) {
        if meta.len() > LOG_MAX_BYTES {
            let rotated = path.with_extension("1.txt");
            let _ = fs::rename(&path, rotated);
        }
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let ts = current_timestamp();
    writeln!(file, "[{}] {}", ts, line)?;
    Ok(())
}