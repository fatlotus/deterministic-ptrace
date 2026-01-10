use std::io;
use crate::sandbox::{SandboxedProcess, SandboxState};

pub fn run_sandbox(target: &str) -> io::Result<i32> {
    let mut process = SandboxedProcess::new(target)?;
    
    loop {
        match process.resume()? {
            SandboxState::Exit(exit_code) => return Ok(exit_code),
            SandboxState::Pause(sim_seconds, sim_nanoseconds) => continue, // Ignore the passage of time.
            SandboxState::NewChild => continue, // Should not happen yet
        }
    }
}
