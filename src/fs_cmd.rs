use std::fs;
use std::path::PathBuf;

pub fn health_exists(path: PathBuf) -> bool {
    path.exists()
}

pub fn file_size(path: PathBuf) -> u64 {
    if let Ok(meta) = fs::metadata(path) {
        meta.len()
    } else {
        0
    }
}

pub fn file_count(dir: PathBuf) -> usize {
    if let Ok(read) = fs::read_dir(dir) {
        read.count()
    } else {
        0
    }
}

pub fn log_count(path: PathBuf) -> usize {
    if let Ok(content) = fs::read_to_string(path) {
        content.lines().count()
    } else {
        0
    }
}

pub fn cwd() -> String {
    if let Ok(path) = std::env::current_dir() {
        path.display().to_string()
    } else {
        String::new()
    }
}

pub fn list_files(dir: PathBuf) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(read) = fs::read_dir(dir) {
        for e in read.flatten() {
            if let Ok(s) = e.file_name().into_string() {
                out.push(s);
            }
        }
    }
    out.sort();
    out
}
