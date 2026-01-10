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
}
