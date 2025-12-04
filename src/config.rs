use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ZetaConfig {
    pub default_peer: Option<String>,
    pub auto_connect: Option<bool>,
}

impl ZetaConfig {
    pub fn load() -> Self {
        let path = config_file_path();
        if !path.exists() {
            return ZetaConfig::default();
        }
        match fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).unwrap_or_default(),
            Err(_) => ZetaConfig::default(),
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = config_file_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(path, content)
    }
}

pub fn config_file_path() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".zeta_crypto");
    dir.push("config.toml");
    dir
}
