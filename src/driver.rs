use std::io;
use crate::sandbox::{SandboxedProcess, SandboxState};

pub fn run_sandbox(target: &str) -> io::Result<i32> {
    let mut processes: Vec<SandboxedProcess> = Vec::new();
    let initial = SandboxedProcess::new(target)?;
    processes.push(initial);

    loop {
        if processes.is_empty() {
            return Ok(0);
        }

        let mut i = 0;
        while i < processes.len() {
            let proc = &mut processes[i];
            let pid = proc.pid();
            
            match proc.resume() {
                Ok(SandboxState::Exit(code)) => {
                    println!("[driver] Process {} exited with code {}", pid, code);
                    processes.remove(i);
                    // If this was the original process, we might want to exit?
                    // The original instructions say: "maintain the invariant that ptraced processes
                    // (SandboxedProcess instances) are only running for the duration of resume()."
                    // And "refactor the driver so that it only stores SandboxedProcess instances."
                    continue; // i stays the same, pointing to next process
                }
                Ok(SandboxState::NewChild(new_proc)) => {
                    processes.push(new_proc);
                    i += 1;
                }
                Ok(SandboxState::Pause(_sec, _nsec)) => {
                    // // Just move to next process for now, or handle scheduling
                    // i += 1;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}
