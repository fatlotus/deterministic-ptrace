use rust_container::{run_sandbox, sandbox};
use std::thread;
use std::time::Duration;

#[test]
fn test_happy_case() {
    let res = run_sandbox(env!("CARGO_BIN_EXE_printf_success"));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_sad_case() {
    let res = run_sandbox(env!("CARGO_BIN_EXE_mkdir_fail"));
    assert!(!res.is_ok());
}

#[test]
fn test_clock_redirection() {
    let res = run_sandbox(env!("CARGO_BIN_EXE_clock_test"));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_recursive_clock() {
    let res = run_sandbox(env!("CARGO_BIN_EXE_recursive_clock_test"));
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_process_cleanup() {
    let pid;
    {
        let proc = sandbox::SandboxedProcess::new(env!("CARGO_BIN_EXE_clock_test")).unwrap();
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
    let mut proc = sandbox::SandboxedProcess::new(env!("CARGO_BIN_EXE_printf_success")).unwrap();
    loop {
        match proc.resume(std::time::UNIX_EPOCH) {
            Ok(sandbox::SandboxState::SchedYield) => continue,
            Ok(sandbox::SandboxState::Exit(0)) => break,
            Ok(state) => panic!("Expected Exit(0), got {:?}", state),
            Err(e) => panic!("Expected Exit(0), got {:?}", e),
        }
    }

    let mut proc = sandbox::SandboxedProcess::new(env!("CARGO_BIN_EXE_mkdir_fail")).unwrap();
    loop {
        match proc.resume(std::time::UNIX_EPOCH) {
            Ok(sandbox::SandboxState::SchedYield) => continue,
            Err(_) => break, // Expected error for forbidden syscall
            Ok(state) => panic!("Expected error, got {:?}", state),
        }
    }
}
