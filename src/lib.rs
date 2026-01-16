pub mod driver;
pub mod sandbox;
pub mod vdso;

pub use driver::run_sandbox;
pub use sandbox::{syscall_name, is_allowed};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_happy_case() {
        // Use the newly created Rust binary
        let res = run_sandbox("./target/debug/printf_success");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 0);
    }

    #[test]
    fn test_sad_case() {
        // Use the newly created Rust binary
        let res = run_sandbox("./target/debug/mkdir_fail");
        assert!(!res.is_ok());
    }

    #[test]
    fn test_clock_redirection() {
        let res = run_sandbox("./target/debug/clock_test");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 0);
    }

    #[test]
    fn test_recursive_clock() {
        let res = run_sandbox("./target/debug/recursive_clock_test");
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 0);
    }

    #[test]
    fn test_process_cleanup() {
        use std::thread;
        use std::time::Duration;

        let pid;
        {
            let proc = sandbox::SandboxedProcess::new("./target/debug/clock_test").unwrap();
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
        let mut proc = sandbox::SandboxedProcess::new("./target/debug/printf_success").unwrap();
        loop {
            match proc.resume(std::time::UNIX_EPOCH) {
                Ok(sandbox::SandboxState::SchedYield) => continue,
                Ok(sandbox::SandboxState::Exit(0)) => break,
                Ok(state) => panic!("Expected Exit(0), got {:?}", state),
                Err(e) => panic!("Expected Exit(0), got {:?}", e),
            }
        }

        let mut proc = sandbox::SandboxedProcess::new("./target/debug/mkdir_fail").unwrap();
        // Since we are mocking mkdir_fail, we expect it to try a forbidden syscall
        // and handle_event will return an error (as it does now for forbidden syscalls)
        loop {
            match proc.resume(std::time::UNIX_EPOCH) {
                Ok(sandbox::SandboxState::SchedYield) => continue,
                Err(_) => break, // Expected error for forbidden syscall
                Ok(state) => panic!("Expected error, got {:?}", state),
            }
        }
    }
}
