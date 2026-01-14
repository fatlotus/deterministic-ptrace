use std::time::SystemTime;

fn main() {
    let fixed_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(123456789);

    // Verify that the time is always the same.
    let now = SystemTime::now();
    println!("Child: Time is {:?}", now);
    if now != fixed_time {
        println!("Child: ERROR: Time mismatch. Expected {:?}, got {:?}", fixed_time, now);
    }
    assert_eq!(now, fixed_time);

    // Even if you call it twice.
    assert_eq!(SystemTime::now(), fixed_time);

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify that some (virtual) time has passed.
    assert_eq!(SystemTime::now(), fixed_time + std::time::Duration::from_secs(2));
}
