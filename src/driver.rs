use std::io;
use crate::sandbox::{SandboxedProcess, SandboxState};
use std::collections::{VecDeque, BinaryHeap};
use std::cmp::Ordering;

struct SleepingProcess {
    time: std::time::SystemTime,
    process: SandboxedProcess,
}

impl PartialEq for SleepingProcess {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

impl Eq for SleepingProcess {}

impl PartialOrd for SleepingProcess {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SleepingProcess {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order for min-heap (earliest time first)
        other.time.cmp(&self.time)
    }
}

pub fn run_sandbox(args: &[&str], max_steps: usize) -> io::Result<i32> {
    let mut runnable: VecDeque<SandboxedProcess> = VecDeque::new();
    let mut sleeping: BinaryHeap<SleepingProcess> = BinaryHeap::new();
    let mut waiting: Vec<SandboxedProcess> = Vec::new();

    let initial = SandboxedProcess::new(args)?;
    runnable.push_back(initial);

    let mut now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(123456789);

    let mut steps = 0;
    while !runnable.is_empty() || !sleeping.is_empty() || !waiting.is_empty() {
        if runnable.is_empty() && !sleeping.is_empty() {
            // Advance time to the next sleeping process
            let next_sleeping = sleeping.pop().unwrap();
            now = next_sleeping.time;
            runnable.push_back(next_sleeping.process);
        }

        if runnable.is_empty() {
            if !waiting.is_empty() && sleeping.is_empty() {
                 // If there are NO runnable processes and NO sleeping processes, but there ARE waiting processes,
                 // they are waiting for something that won't happen (deadlock).
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
                steps += 1;
                println!("[driver] Process {} exited with code {}", pid, code);
                for p in waiting.drain(..) {
                    runnable.push_back(p);
                }
                if code != 0 && runnable.is_empty() && sleeping.is_empty() && waiting.is_empty() {
                    return Ok(code);
                }
            }
            Ok(SandboxState::NewChild(new_proc)) => {
                steps += 1;
                println!("[driver] Spawning a new process {}", new_proc.pid());
                runnable.push_back(new_proc);
                runnable.push_back(next);
            }
            Ok(SandboxState::Pause(new_now)) => {
                steps += 1;
                sleeping.push(SleepingProcess { time: new_now, process: next });
            }
            Ok(SandboxState::SchedYield) => {
                runnable.push_back(next);
            }
            Ok(SandboxState::WaitForSubprocess) => {
                steps += 1;
                waiting.push(next);
            }
            Err(e) => {
                println!("[driver] Error in run_sandbox: {}", e);
                return Err(e);
            }
        }

        if steps > max_steps {
            println!("[driver] Maximum steps ({}) exceeded", max_steps);
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Maximum steps exceeded"));
        }
    }
    Ok(0)
}
