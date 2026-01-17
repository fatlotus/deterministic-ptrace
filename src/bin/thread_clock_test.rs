use std::time::{SystemTime, Duration};
use std::thread;

fn main() {
    let fixed_time = SystemTime::UNIX_EPOCH + Duration::from_secs(123456789);

    println!("Main: Checking time...");
    assert_eq!(SystemTime::now(), fixed_time);

    println!("Main: Spawning child thread...");
    let handle = thread::spawn(move || {
        println!("Child Thread: Sleeping...");
        thread::sleep(Duration::from_secs(1));
        println!("Child Thread: Checking time...");
        // Child thread should see the same fixed time (or advanced if we want global clock)
        // In our model, we want a global virtual clock.
        assert_eq!(SystemTime::now(), fixed_time + Duration::from_secs(1));
        println!("Child Thread: Finished");
    });

    println!("Main: Joining child thread...");
    handle.join().expect("Thread panicked");
    println!("Main: Child thread joined");

    println!("Main: Checking time...");
    // The time should have advanced by 1 second.
    assert_eq!(SystemTime::now(), fixed_time + Duration::from_secs(1));
    println!("Main: Finished successfully");
}
