use std::path::PathBuf;

const APP_DIR: &str = ".zeta_crypto";

pub fn get_app_dir() -> PathBuf {
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(APP_DIR);
    dir
}

pub fn get_config_path() -> PathBuf {
    get_app_dir().join("config.toml")
}

pub fn get_session_path() -> PathBuf {
    get_app_dir().join("session.json")
}

pub fn get_log_path() -> PathBuf {
    get_app_dir().join("logs.txt")
}

pub fn get_cache_dir() -> PathBuf {
    get_app_dir().join("cache")
}

pub fn ensure_app_dir() -> std::io::Result<()> {
    let path = get_app_dir();
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}
