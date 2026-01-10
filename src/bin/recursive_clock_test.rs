use std::process::Command;
use std::time::SystemTime;

fn main() {
    let fixed_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(123456789);

    println!("Parent: Checking time...");
    assert_eq!(SystemTime::now(), fixed_time);

    println!("Parent: Spawning child...");
    let status = Command::new("./target/debug/clock_test")
        .status()
        .expect("failed to execute child");

    if !status.success() {
        println!("Parent: Child failed with status: {:?}", status);
    }
    assert!(status.success());
    println!("Parent: Child finished successfully");
}
