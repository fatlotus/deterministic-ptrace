use std::io;
use crate::sandbox::{SandboxedProcess, SandboxState};
use std::collections::VecDeque;

pub fn run_sandbox(target: &str) -> io::Result<i32> {
    let mut processes: VecDeque<SandboxedProcess> = VecDeque::new();
    let initial = SandboxedProcess::new(target)?;
    processes.push_back(initial);

    while !processes.is_empty() {
        let mut next = processes.pop_front().unwrap();
        let pid = next.pid();
        println!("[driver] Process {} is running", pid);

        match next.resume() {
            Ok(SandboxState::Exit(code)) => {
                println!("[driver] Process {} exited with code {}", pid, code);
                if code != 0 {
                    return Ok(code);
                }
            }
            Ok(SandboxState::NewChild(new_proc)) => {
                processes.push_back(new_proc);
                processes.push_back(next);
            }
            Ok(SandboxState::Pause(_sec, _nsec)) => {
                processes.push_back(next);
            }
            Ok(SandboxState::SchedYield) => {
                processes.push_back(next);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    Ok(0)
}
