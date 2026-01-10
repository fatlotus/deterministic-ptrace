use std::collections::HashMap;
use std::io;
use std::ptr;
use libc::{self, c_int, c_void};
use crate::sandbox::{SandboxedProcess, SandboxState};

pub fn run_sandbox(target: &str) -> io::Result<i32> {
    let mut processes: HashMap<i32, SandboxedProcess> = HashMap::new();
    let initial = SandboxedProcess::new(target)?;
    let initial_pid = initial.pid();
    processes.insert(initial_pid, initial);
    
    // Resume the initial process
    unsafe {
        libc::ptrace(libc::PTRACE_SYSCALL, initial_pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
    }

    loop {
        if processes.is_empty() {
            return Ok(0);
        }

        let mut status: c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                // No more children
                return Ok(0);
            }
            return Err(err);
        }

        if let Some(proc) = processes.get_mut(&pid) {
            match proc.handle_event(status)? {
                SandboxState::Exit(code) => {
                    println!("[driver] Process {} exited with code {}", pid, code);
                    processes.remove(&pid);
                    if pid == initial_pid {
                        return Ok(code);
                    }
                }
                SandboxState::Pause(_sec, _nsec) => {
                    unsafe {
                        libc::ptrace(libc::PTRACE_SYSCALL, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                    }
                }
                SandboxState::NewChild(new_pid) => {
                    let new_proc = SandboxedProcess::from_pid(new_pid);
                    processes.insert(new_pid, new_proc);
                    unsafe {
                        libc::ptrace(libc::PTRACE_SYSCALL, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                        libc::ptrace(libc::PTRACE_SYSCALL, new_pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                    }
                }
                SandboxState::Continue => {
                    unsafe {
                        libc::ptrace(libc::PTRACE_SYSCALL, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                    }
                }
            }
        } else {
             // If we intercept a new child before NewChild event (unlikely with PTRACE_EVENT_FORK order),
             // or if we catch some other process (shouldn't occur if we only fork).
             eprintln!("[driver] Unknown pid {} woke up", pid);
             unsafe {
                libc::ptrace(libc::PTRACE_SYSCALL, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
            }
        }
    }
}
