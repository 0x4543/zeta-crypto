use crate::storage;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ZetaConfig {
    pub default_peer: Option<String>,
    pub auto_connect: Option<bool>,
}

impl ZetaConfig {
    pub fn load() -> Self {
        let path = storage::get_config_path();
        if !path.exists() {
            return ZetaConfig::default();
        }
        match fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).unwrap_or_default(),
            Err(_) => ZetaConfig::default(),
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        storage::ensure_app_dir()?;
        let path = storage::get_config_path();
        let content = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        fs::write(path, content)
    }
}