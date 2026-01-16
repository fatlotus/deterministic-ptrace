use std::io;
use crate::sandbox::{SandboxedProcess, SandboxState};
use std::collections::VecDeque;

pub fn run_sandbox(target: &str) -> io::Result<i32> {
    let mut processes: VecDeque<SandboxedProcess> = VecDeque::new();
    let initial = SandboxedProcess::new(target)?;
    processes.push_back(initial);

    let mut now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(123456789);

    while !processes.is_empty() {
        let mut next = processes.pop_front().unwrap();
        let pid = next.pid();
        println!("[driver] Process {} is running", pid);

        let result = next.resume(now);
        println!("[driver] Process {:?} resumed (len={})", result, processes.len());

        match result {
            Ok(SandboxState::Exit(code)) => {
                println!("[driver] Process {} exited with code {}", pid, code);
                if code != 0 {
                    return Ok(code);
                }
            }
            Ok(SandboxState::NewChild(new_proc)) => {
                println!("[driver] Spawning a new process {}", new_proc.pid());
                processes.push_back(new_proc);
                processes.push_back(next);
            }
            Ok(SandboxState::Pause(new_now)) => {
                processes.push_back(next);
                now = new_now;
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
