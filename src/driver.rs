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
    let mut consecutive_yields = 0;
    while !runnable.is_empty() || !sleeping.is_empty() || !waiting.is_empty() {
        if runnable.is_empty() && !sleeping.is_empty() {
            // Advance time to the next sleeping process
            let next_sleeping = sleeping.pop().unwrap();
            println!("[driver] Advancing time to {} to wake up process {}", 
                next_sleeping.time.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 
                next_sleeping.process.pid());
            now = next_sleeping.time;
            runnable.push_back(next_sleeping.process);
        }

        if runnable.is_empty() {
            if !waiting.is_empty() && sleeping.is_empty() {
                 println!("[driver] Deadlock detected: waiting for processes but no sleepers to advance time.");
                 break;
            }
            if !sleeping.is_empty() {
                continue;
            }
            break;
        }

        let mut next = runnable.pop_front().unwrap();
        let pid = next.pid();
        // println!("[driver] Process {} is running", pid);

        let result = next.resume(now);
        // println!("[driver] Process {} resumed with status {:?} (runnable={}, sleeping={}, waiting={})", 
        //    pid, result, runnable.len(), sleeping.len(), waiting.len());

        match result {
            Ok(SandboxState::Exit(code)) => {
                steps += 1;
                consecutive_yields = 0;
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
                consecutive_yields = 0;
                println!("[driver] Spawning a new child process {}", new_proc.pid());
                runnable.push_back(new_proc);
                runnable.push_back(next);
            }
            Ok(SandboxState::Pause(new_now)) => {
                steps += 1;
                consecutive_yields = 0;
                sleeping.push(SleepingProcess { time: new_now, process: next });
            }
            Ok(SandboxState::SchedYield) => {
                consecutive_yields += 1;
                let num_runnable = runnable.len() + 1; // including the one we're pushing back
                runnable.push_back(next);
                
                if consecutive_yields >= num_runnable {
                    // Everyone currently in runnable is blocked in the kernel.
                    // If we have sleeping processes, we should advance time.
                    if !sleeping.is_empty() {
                        let next_sleeping = sleeping.pop().unwrap();
                        println!("[driver] All {} processes yielding, advancing time to {} to wake up process {}", 
                            num_runnable,
                            next_sleeping.time.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                            next_sleeping.process.pid());
                        now = next_sleeping.time;
                        runnable.push_back(next_sleeping.process);
                        consecutive_yields = 0;
                    } else if waiting.is_empty() {
                        // Everyone is yielding and nothing is sleeping and nothing is waiting... 
                        // This might be a busy-wait or infinite yield. 
                        // Give it some time or just break if we want to avoid infinite loops.
                        // For now just keep going, but maybe it's a deadlock.
                    }
                }
            }
            Ok(SandboxState::WaitForSubprocess) => {
                steps += 1;
                consecutive_yields = 0;
                waiting.push(next);
            }
            Err(e) => {
                println!("[driver] Error in run_sandbox for process {}: {}", pid, e);
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
