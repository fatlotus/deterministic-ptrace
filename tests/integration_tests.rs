use rust_container::{run_sandbox, SandboxedProcess, SandboxState};
use std::thread;
use std::time::Duration;

#[test]
fn test_happy_case() {
    let res = run_sandbox(&[env!("CARGO_BIN_EXE_printf_success")], 1000, Some(Duration::from_secs(1)));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_sad_case() {
    let res = run_sandbox(&[env!("CARGO_BIN_EXE_mkdir_fail")], 1000, Some(Duration::from_secs(1)));
    assert!(!res.is_ok());
}

#[test]
fn test_clock_redirection() {
    let res = run_sandbox(&[env!("CARGO_BIN_EXE_clock_test")], 1000, Some(Duration::from_secs(1)));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_random_determinism() {
    let res = run_sandbox(&[env!("CARGO_BIN_EXE_random_test")], 1000, Some(Duration::from_secs(1)));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_recursive_clock() {
    let res = run_sandbox(&[env!("CARGO_BIN_EXE_recursive_clock_test")], 1000, Some(Duration::from_secs(1)));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_python_hello_world() {
    let res = run_sandbox(&["/usr/bin/python3", "-c", "print('hello world')"], 1000, Some(Duration::from_secs(1)));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_python_random_determinism() {
    let res = run_sandbox(&[
        "/usr/bin/python3",
        "-c",
        "import random; assert(random.randint(0, 10000) == 4046)",
    ], 1000, Some(Duration::from_secs(1)));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_process_cleanup() {
    let pid;
    {
        let proc = SandboxedProcess::new(&[env!("CARGO_BIN_EXE_clock_test")]).unwrap();
        pid = proc.pid();
        // Verify process exists
        assert_eq!(unsafe { libc::kill(pid, 0) }, 0);
        
        // Drop it immediately
    }

    // Give it a moment to be reaped
    thread::sleep(Duration::from_millis(100));

    // Verify process no longer exists
    // kill with 0 returns -1 and sets errno to ESRCH if process doesn't exist
    let res = unsafe { libc::kill(pid, 0) };
    assert!(res == -1);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ESRCH);
}

#[test]
fn test_resume_interface() {
    let mut proc = SandboxedProcess::new(&[env!("CARGO_BIN_EXE_printf_success")]).unwrap();
    loop {
        match proc.resume(std::time::UNIX_EPOCH) {
            Ok(SandboxState::SchedYield) => continue,
            Ok(SandboxState::Exit(0)) => break,
            Ok(state) => panic!("Expected Exit(0), got {:?}", state),
            Err(e) => panic!("Expected Exit(0), got {:?}", e),
        }
    }

    let mut proc = SandboxedProcess::new(&[env!("CARGO_BIN_EXE_mkdir_fail")]).unwrap();
    loop {
        match proc.resume(std::time::UNIX_EPOCH) {
            Ok(SandboxState::SchedYield) => continue,
            Err(_) => break, // Expected error for forbidden syscall
            Ok(state) => panic!("Expected error, got {:?}", state),
        }
    }
}
#[test]
fn test_thread_clock() {
    let res = run_sandbox(&[env!("CARGO_BIN_EXE_thread_clock_test")], 1000, Some(Duration::from_secs(1)));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}
#[test]
fn test_bash_script() {
    let res = run_sandbox(&["/bin/bash", "test_dir/test_script.sh"], 1000, Some(Duration::from_secs(1)));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
#[should_panic(expected = "Real-time limit exceeded")]
fn test_timeout_panic() {
    // This command should take longer than 1 microsecond
    let res = run_sandbox(&["/bin/ls"], 1000000, Some(Duration::from_micros(1)));
    res.expect("Real-time limit exceeded");
}

#[test]
#[should_panic(expected = "Real-time limit exceeded")]
fn test_infinite_loop_timeout() {
    let res = run_sandbox(&[env!("CARGO_BIN_EXE_infinite_loop")], 1000000, Some(Duration::from_millis(100)));
    res.expect("Real-time limit exceeded");
}
