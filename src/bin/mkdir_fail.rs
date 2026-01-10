use std::fs;

fn main() {
    println!("Attempting forbidden mkdir()...");
    match fs::create_dir("test_dir") {
        Ok(_) => println!("Oops, mkdir succeeded or at least didn't kill me."),
        Err(e) => println!("mkdir failed as expected: {}", e),
    }
}
