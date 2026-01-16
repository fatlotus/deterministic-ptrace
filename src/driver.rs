use std::io;
use crate::sandbox::{SandboxedProcess, SandboxState};
use std::collections::VecDeque;

pub fn run_sandbox(target: &str) -> io::Result<i32> {
    let mut runnable: VecDeque<SandboxedProcess> = VecDeque::new();
    let mut sleeping: Vec<(std::time::SystemTime, SandboxedProcess)> = Vec::new();
    let mut waiting: VecDeque<SandboxedProcess> = VecDeque::new();

    let initial = SandboxedProcess::new(target)?;
    runnable.push_back(initial);

    let mut now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(123456789);

    while !runnable.is_empty() || !sleeping.is_empty() || !waiting.is_empty() {
        if runnable.is_empty() && !sleeping.is_empty() {
            // Advance time to the next sleeping process
            sleeping.sort_by_key(|(t, _)| *t);
            let (next_time, _) = sleeping[0];
            now = next_time;
            
            let (ready, still_sleeping): (Vec<_>, Vec<_>) = sleeping.into_iter().partition(|(t, _)| *t <= now);
            for (_, p) in ready {
                runnable.push_back(p);
            }
            sleeping = still_sleeping;
        }

        if runnable.is_empty() {
            if !waiting.is_empty() && sleeping.is_empty() {
                 // Deadlock or finished? If there are only waiting processes, and no sleeping ones, 
                 // we might be in trouble if they are waiting for each other, but here 
                 // they are waiting for subprocesses to exit.
                 // If there are NO runnable processes and NO sleeping processes, but there ARE waiting processes,
                 // it means something is wrong or we are finished.
                 // However, the instructions say "whenever any process exits, add all processes from (3) to the end of (1)".
                 // If we have processes in (3) but (1) and (2) are empty, then (3) will never be moved.
                 // This might happen if a process is waiting for an exit but the exit already happened or something.
                 // Actually, if a process exits, we move (3) to (1). 
                 // If (1) and (2) are empty, we are done unless a process exits.
                 break;
            }
            if !sleeping.is_empty() {
                continue;
            }
            break;
        }

        let mut next = runnable.pop_front().unwrap();
        let pid = next.pid();
        println!("[driver] Process {} is running", pid);

        let result = next.resume(now);
        println!("[driver] Process {:?} resumed (runnable={}, sleeping={}, waiting={})", result, runnable.len(), sleeping.len(), waiting.len());

        match result {
            Ok(SandboxState::Exit(code)) => {
                println!("[driver] Process {} exited with code {}", pid, code);
                while let Some(p) = waiting.pop_front() {
                    runnable.push_back(p);
                }
                if code != 0 && runnable.is_empty() && sleeping.is_empty() && waiting.is_empty() {
                    return Ok(code);
                }
            }
            Ok(SandboxState::NewChild(new_proc)) => {
                println!("[driver] Spawning a new process {}", new_proc.pid());
                runnable.push_back(new_proc);
                runnable.push_back(next);
            }
            Ok(SandboxState::Pause(new_now)) => {
                sleeping.push( (new_now, next) );
            }
            Ok(SandboxState::SchedYield) => {
                runnable.push_back(next);
            }
            Ok(SandboxState::WaitForSubprocess) => {
                waiting.push_back(next);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    Ok(0)
}
