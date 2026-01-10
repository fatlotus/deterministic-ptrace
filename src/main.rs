use rust_container::run_sandbox;
use std::io;

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let target = if args.len() > 1 {
        &args[1]
    } else {
        "./hello"
    };

    match run_sandbox(target) {
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
