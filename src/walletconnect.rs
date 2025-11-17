use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Seek, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_MAX_BYTES: u64 = 262_144; // ~256 KB

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
        log_event(&format!("connect peer={}", self.peer));
    }

    pub fn disconnect(&mut self) {
        self.status = "disconnected".to_string();
        self.last_updated = current_timestamp();
        self.save_to_file();
        log_event(&format!("disconnect peer={}", self.peer));
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

    pub fn last_updated(&self) -> u64 {
        self.last_updated
    }

    pub fn save_to_file(&self) -> std::io::Result<()> {
        let mut path = dirs::home_dir().unwrap_or_default();
        path.push(".zeta_crypto/session.json");
        let encoded = serde_json::to_string_pretty(self).unwrap();
        std::fs::write(path, encoded)
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

fn log_file_path() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".zeta_crypto");
    dir.push("logs.txt");
    dir
}

fn log_rotate_if_needed(path: &PathBuf) {
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > LOG_MAX_BYTES {
            let mut rotated = path.clone();
            rotated.set_file_name("logs.1.txt");
            let _ = fs::rename(path, rotated);
            // recreate empty file
            let _ = fs::File::create(path);
        }
    }
}

fn log_event(line: &str) {
    let path = log_file_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    log_rotate_if_needed(&path);
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let ts = current_timestamp();
        let _ = writeln!(file, "[{}] {}", ts, line);
        let _ = file.flush();
        let _ = file.seek(std::io::SeekFrom::End(0));
    }
}
