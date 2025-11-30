use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

pub fn cleanup(dir: PathBuf) {
    let logs = dir.join("logs.txt");
    let session = dir.join("session.json");
    let _ = fs::remove_file(logs);
    let _ = fs::remove_file(session);
}

pub fn clear_logs(path: PathBuf) {
    let _ = fs::write(path, "");
}

pub fn open_log(path: PathBuf) {
    if !path.exists() {
        println!("Log file not found");
        return;
    }

    let cmd = {
        #[cfg(target_os = "macos")]
        {
            "open"
        }
        #[cfg(target_os = "linux")]
        {
            "xdg-open"
        }
        #[cfg(target_os = "windows")]
        {
            "start"
        }
    };

    let _ = std::process::Command::new(cmd)
        .arg(path.to_string_lossy().to_string())
        .spawn();

    println!("Opening log file...");
}

pub fn confirm(prompt: &str) -> bool {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        input.trim().eq_ignore_ascii_case("yes")
    } else {
        false
    }
}

pub fn health_report(cfg: PathBuf, session: PathBuf, log: PathBuf) {
    println!("Health Check:");
    println!("config.toml:     {}", cfg.exists());
    println!("session.json:    {}", session.exists());
    println!("logs.txt:        {}", log.exists());
}