use crate::version;
use crate::ZetaConfig;
use anyhow::Result;
use std::io::{self, Write};
use std::process::Command;

pub fn handle_version() -> Result<()> {
    version::print_version_info();
    Ok(())
}

pub fn handle_health_check() -> Result<()> {
    use std::path::PathBuf;
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".zeta_crypto");

    let cfg = dir.join("config.toml");
    let session = dir.join("session.json");
    let log = dir.join("logs.txt");

    println!("Health Check:");
    println!("config.toml: {}", cfg.exists());
    println!("session.json: {}", session.exists());
    println!("logs.txt: {}", log.exists());
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
    println!(
        "Platform: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    Ok(())
}

pub fn handle_cleanup() -> Result<()> {
    let mut dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    dir.push(".zeta_crypto");

    println!(
        "This will remove all logs and saved sessions from {}",
        dir.display()
    );
    print!("Type 'yes' to confirm: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    if input.trim().to_lowercase() == "yes" {
        let _ = std::fs::remove_file(dir.join("logs.txt"));
        let _ = std::fs::remove_file(dir.join("session.json"));
        println!("\x1b[32mCleanup completed.\x1b[0m");
    } else {
        eprintln!("\x1b[31mAborted.\x1b[0m");
    }
    Ok(())
}

pub fn handle_clear_logs() -> Result<()> {
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

pub fn handle_log_path() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/logs.txt");
    println!("{}", path.display());
    Ok(())
}

pub fn handle_log_size() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/logs.txt");
    if path.exists() {
        let metadata = std::fs::metadata(&path)?;
        let size = metadata.len();
        if size < 1024 {
            println!("{} bytes", size);
        } else {
            println!("{:.2} KB", size as f64 / 1024.0);
        }
    } else {
        println!("Log file not found");
    }
    Ok(())
}

pub fn handle_log_count() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/logs.txt");
    if !path.exists() {
        println!("0");
        return Ok(());
    }
    let content = std::fs::read_to_string(&path)?;
    let count = content.lines().count();
    println!("{}", count);
    Ok(())
}

pub fn handle_config_path() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/config.toml");
    println!("{}", path.display());
    Ok(())
}

pub fn handle_session_path() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/session.json");
    println!("{}", path.display());
    Ok(())
}

pub fn handle_cache_path() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/cache");
    println!("{}", path.display());
    Ok(())
}

pub fn handle_data_dir() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto");
    println!("{}", path.display());
    Ok(())
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

pub fn handle_cpu_cores() -> Result<()> {
    let cores = num_cpus::get();
    println!("{}", cores);
    Ok(())
}

pub fn handle_timestamp() -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("{}", now);
    Ok(())
}

pub fn handle_config_exists() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/config.toml");
    println!("{}", path.exists());
    Ok(())
}

pub fn handle_session_exists() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/session.json");
    println!("{}", path.exists());
    Ok(())
}

pub fn handle_logs_exist() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/logs.txt");
    println!("{}", path.exists());
    Ok(())
}

pub fn handle_config_dir() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto");
    println!("{}", path.display());
    Ok(())
}

pub fn handle_cwd() -> Result<()> {
    if let Ok(path) = std::env::current_dir() {
        println!("{}", path.display());
    }
    Ok(())
}

pub fn handle_session_size() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/session.json");
    if let Ok(meta) = std::fs::metadata(&path) {
        println!("{}", meta.len());
    } else {
        println!("0");
    }
    Ok(())
}

pub fn handle_config_size() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/config.toml");
    if let Ok(meta) = std::fs::metadata(&path) {
        println!("{}", meta.len());
    } else {
        println!("0");
    }
    Ok(())
}

pub fn handle_session_modified() -> Result<()> {
    let mut path = dirs::home_dir().unwrap_or_default();
    path.push(".zeta_crypto/session.json");
    if let Ok(meta) = std::fs::metadata(&path) {
        if let Ok(time) = meta.modified() {
            if let Ok(secs) = time.duration_since(std::time::UNIX_EPOCH) {
                println!("{}", secs.as_secs());
            }
        }
    }
    Ok(())
}

pub fn handle_data_file_count() -> Result<()> {
    let mut dir = dirs::home_dir().unwrap_or_default();
    dir.push(".zeta_crypto");
    if let Ok(read) = std::fs::read_dir(&dir) {
        println!("{}", read.count());
    } else {
        println!("0");
    }
    Ok(())
}

pub fn handle_config_show() -> Result<()> {
    let cfg = ZetaConfig::load();
    println!("{:?}", cfg);
    Ok(())
}

pub fn handle_help_all() -> Result<()> {
    println!("Commands:");
    println!("gen-mnemonic");
    println!("derive-wallet");
    println!("sign");
    println!("verify");
    println!("walletconnect");
    println!("walletconnect-status");
    println!("walletconnect-info");
    println!("walletconnect-restore");
    println!("walletconnect-default");
    println!("config-show");
    println!("version-info");
    println!("healthcheck");
    println!("cleanup");
    println!("help-all");
    Ok(())
}