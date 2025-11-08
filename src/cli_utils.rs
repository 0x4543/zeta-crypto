use std::process;

pub fn success(msg: &str) {
    println!("\x1b[32m{}\x1b[0m", msg);
    process::exit(0);
}

pub fn fail(msg: &str) {
    eprintln!("\x1b[31mError:\x1b[0m {}", msg);
    process::exit(1);
}
