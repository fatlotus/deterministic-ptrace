use rust_container::run_sandbox;
use std::io;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let target_args: Vec<&str> = if args.len() > 1 {
        args.iter().skip(1).map(|s| s.as_str()).collect()
    } else {
        vec!["./hello"]
    };

    match run_sandbox(&target_args) {
        Ok(code) => {
            if code == -1 {
                std::process::exit(1);
            }
            std::process::exit(code);
        }
        Err(e) => {
            eprintln!("Sandbox error: {}", e);
            std::process::exit(1);
        }
    }
}
