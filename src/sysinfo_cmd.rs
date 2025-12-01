use anyhow::Result;
use std::process::Command;

pub fn handle_health_check() -> Result<()> {
    use std::path::PathBuf;
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".zeta_crypto");

    let cfg = dir.join("config.toml");
    let session = dir.join("session.json");
    let log = dir.join("logs.txt");

    println!("Health Check:");
    println!("config.toml:     {}", cfg.exists());
    println!("session.json:    {}", session.exists());
    println!("logs.txt:        {}", log.exists());
    Ok(())
}

pub fn handle_env() -> Result<()> {
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|_| "unknown".into());

    println!("Zeta CLI version: {}", env!("CARGO_PKG_VERSION"));
    println!("Rust compiler: {}", rustc.trim());
    println!("Platform: {} {}", std::env::consts::OS, std::env::consts::ARCH);
    Ok(())
}

pub fn handle_clear_logs() -> Result<()> {
    use std::io::{self, Write};
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/logs.txt");

    if path.exists() {
        print!("This will clear logs. Type 'yes' to confirm: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        if input.trim().eq_ignore_ascii_case("yes") {
            std::fs::write(&path, "")?;
            println!("Logs cleared.");
        } else {
            println!("Aborted.");
        }
    } else {
        println!("No logs found.");
    }
    Ok(())
}

pub fn handle_log_path() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/logs.txt");
    println!("{}", path.display());
}

pub fn handle_config_path() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/config.toml");
    println!("{}", path.display());
}

pub fn handle_session_path() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/session.json");
    println!("{}", path.display());
}

pub fn handle_cache_path() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/cache");
    println!("{}", path.display());
}

pub fn handle_data_dir() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto");
    println!("{}", path.display());
}

pub fn handle_list_files() -> Result<()> {
    use std::fs;

    let mut dir = dirs::home_dir().unwrap_or_default();
    dir.push(".zeta_crypto");

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => {
            println!("Directory not found");
            return Ok(());
        }
    };

    let mut files: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    files.sort();

    for f in files {
        println!("{}", f);
    }

    Ok(())
}

pub fn handle_cpu_cores() {
    let cores = num_cpus::get();
    println!("{}", cores);
}

pub fn handle_timestamp() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("{}", now);
}

pub fn handle_config_exists() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/config.toml");
    println!("{}", path.exists());
}

pub fn handle_session_exists() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/session.json");
    println!("{}", path.exists());
}

pub fn handle_logs_exist() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/logs.txt");
    println!("{}", path.exists());
}

pub fn handle_config_dir() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto");
    println!("{}", path.display());
}

pub fn handle_cwd() {
    if let Ok(path) = std::env::current_dir() {
        println!("{}", path.display());
    }
}

pub fn handle_session_size() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/session.json");
    if let Ok(meta) = std::fs::metadata(&path) {
        println!("{}", meta.len());
    } else {
        println!("0");
    }
}

pub fn handle_config_size() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/config.toml");
    if let Ok(meta) = std::fs::metadata(&path) {
        println!("{}", meta.len());
    } else {
        println!("0");
    }
}

pub fn handle_session_modified() {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/session.json");
    if let Ok(meta) = std::fs::metadata(&path) {
        if let Ok(time) = meta.modified() {
            if let Ok(secs) = time.duration_since(std::time::UNIX_EPOCH) {
                println!("{}", secs.as_secs());
            }
        }
    }
}

pub fn handle_data_file_count() {
    let mut dir = dirs::home_dir().unwrap_or_default();
    dir.push(".zeta_crypto");
    if let Ok(read) = std::fs::read_dir(&dir) {
        let count = read.count();
        println!("{}", count);
    } else {
        println!("0");
    }
}