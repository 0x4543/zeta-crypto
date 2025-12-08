use crate::storage;
use crate::ZetaConfig;
use anyhow::Result;
use std::io::{self, Write};
use std::process::Command;

pub fn handle_version() -> Result<()> {
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|_| "unknown".into());

    println!("Zeta Crypto CLI {}", env!("CARGO_PKG_VERSION"));
    println!("Rust compiler: {}", rustc.trim());
    println!(
        "Platform: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    Ok(())
}

pub fn handle_health_check() -> Result<()> {
    let cfg = storage::get_config_path();
    let session = storage::get_session_path();
    let log = storage::get_log_path();

    println!("Health Check:");
    println!("config.toml: {}", cfg.exists());
    println!("session.json: {}", session.exists());
    println!("logs.txt:    {}", log.exists());
    Ok(())
}

pub fn handle_env() -> Result<()> {
    handle_version()
}

pub fn handle_cleanup() -> Result<()> {
    let dir = storage::get_app_dir();

    println!(
        "This will remove all logs and saved sessions from {}",
        dir.display()
    );
    print!("Type 'yes' to confirm: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    if input.trim().to_lowercase() == "yes" {
        let _ = std::fs::remove_file(storage::get_log_path());
        let _ = std::fs::remove_file(storage::get_session_path());
        println!("\x1b[32mCleanup completed.\x1b[0m");
    } else {
        eprintln!("\x1b[31mAborted.\x1b[0m");
    }
    Ok(())
}

pub fn handle_clear_logs() -> Result<()> {
    let path = storage::get_log_path();

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
    println!("{}", storage::get_log_path().display());
    Ok(())
}

pub fn handle_log_size() -> Result<()> {
    let path = storage::get_log_path();
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
    let path = storage::get_log_path();
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
    println!("{}", storage::get_config_path().display());
    Ok(())
}

pub fn handle_session_path() -> Result<()> {
    println!("{}", storage::get_session_path().display());
    Ok(())
}

pub fn handle_cache_path() -> Result<()> {
    println!("{}", storage::get_cache_dir().display());
    Ok(())
}

pub fn handle_data_dir() -> Result<()> {
    println!("{}", storage::get_app_dir().display());
    Ok(())
}

pub fn handle_list_files() -> Result<()> {
    use std::fs;
    let dir = storage::get_app_dir();

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
    println!("{}", storage::get_config_path().exists());
    Ok(())
}

pub fn handle_session_exists() -> Result<()> {
    println!("{}", storage::get_session_path().exists());
    Ok(())
}

pub fn handle_logs_exist() -> Result<()> {
    println!("{}", storage::get_log_path().exists());
    Ok(())
}

pub fn handle_config_dir() -> Result<()> {
    println!("{}", storage::get_app_dir().display());
    Ok(())
}

pub fn handle_cwd() -> Result<()> {
    if let Ok(path) = std::env::current_dir() {
        println!("{}", path.display());
    }
    Ok(())
}

pub fn handle_session_size() -> Result<()> {
    let path = storage::get_session_path();
    if let Ok(meta) = std::fs::metadata(&path) {
        println!("{}", meta.len());
    } else {
        println!("0");
    }
    Ok(())
}

pub fn handle_config_size() -> Result<()> {
    let path = storage::get_config_path();
    if let Ok(meta) = std::fs::metadata(&path) {
        println!("{}", meta.len());
    } else {
        println!("0");
    }
    Ok(())
}

pub fn handle_session_modified() -> Result<()> {
    let path = storage::get_session_path();
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
    let dir = storage::get_app_dir();
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
