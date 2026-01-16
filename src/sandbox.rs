use libc::{c_int, c_long, c_void, iovec, NT_PRSTATUS, SIGTRAP};
use std::ffi::CString;
use std::io::{self, Write};
use std::ptr;
use crate::vdso::disable_vdso;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

const X86_64_SYS_WRITE: u64 = 1;
const X86_64_SYS_OPENAT: u64 = 257;
const X86_64_SYS_NANOSLEEP: u64 = 35;
const X86_64_SYS_CLOCK_GETTIME: u64 = 228;
const X86_64_SYS_CLOCK_NANOSLEEP: u64 = 230;
const X86_64_SYS_EXECVE: u64 = 59;

pub fn syscall_name(nr: u64) -> &'static str {
    match nr {
        79 => "getcwd",
        72 => "fcntl",
        16 => "ioctl",
        258 => "mkdirat",
        137 => "fstatfs",
        269 => "faccessat",
        257 => "openat",
        3 => "close",
        8 => "lseek",
        0 => "read",
        1 => "write",
        17 => "pread64",
        271 => "ppoll",
        267 => "readlinkat",
        262 => "newfstatat",
        5 => "fstat",
        7 => "poll",
        231 => "exit_group",
        218 => "set_tid_address",
        273 => "set_robust_list",
        35 => "nanosleep",
        228 => "clock_gettime",
        230 => "clock_nanosleep",
        204 => "sched_getaffinity",
        234 => "tgkill",
        131 => "sigaltstack",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        15 => "rt_sigreturn",
        63 => "uname",
        97 => "getrlimit",
        302 => "prlimit64",
        39 => "getpid",
        186 => "gettid",
        99 => "sysinfo",
        202 => "futex",
        11 => "munmap",
        12 => "brk",
        21 => "access",
        158 => "arch_prctl",
        334 => "rseq",
        59 => "execve",
        9 => "mmap",
        10 => "mprotect",
        157 => "prctl",
        318 => "getrandom",
        319 => "memfd_create",
        435 => "clone3",
        61 => "wait4",
        332 => "statx",
        _ => "unknown",
    }
}

pub fn is_allowed(nr: u64) -> bool {
    matches!(
        nr,
        79 | 72
            | 16
            | 137
            | 269
            | 257
            | 3
            | 8
            | 0
            | 1
            | 17
            | 271
            | 267
            | 262
            | 5
            | 7
            | 231
            | 218
            | 273
            | 35
            | 228
            | 230
            | 204
            | 234
            | 131
            | 13
            | 14
            | 15
            | 63
            | 97
            | 302
            | 39
            | 186
            | 99
            | 202
            | 11
            | 12
            | 21
            | 158
            | 334
            | 59
            | 9
            | 10
            | 157
            | 318
            | 319
            | 435
            | 61
            | 332
    )
}

fn print_escaped(child: i32, addr: u64, len: u64) {
    if len == 0 {
        return;
    }
    print!("[container] Bytes: ");
    for i in 0..len {
        let offset = i % (std::mem::size_of::<c_long>() as u64);
        let aligned_addr = addr + i - offset;
        unsafe {
            let data = libc::ptrace(libc::PTRACE_PEEKDATA, child, aligned_addr as *mut c_void, ptr::null_mut::<c_void>());
            if data == -1 && *libc::__errno_location() != 0 {
                break;
            }
            let byte = ((data >> (offset * 8)) & 0xFF) as u8;
            print!("\\x{:02x}", byte);
        }
    }
    println!();
}

fn read_child_string(child: i32, addr: u64, max_len: usize) -> String {
    let mut res = Vec::new();
    let mut i = 0;
    'outer: while i < max_len {
        unsafe {
            let data = libc::ptrace(libc::PTRACE_PEEKDATA, child, (addr + i as u64) as *mut c_void, ptr::null_mut::<c_void>());
            if data == -1 && *libc::__errno_location() != 0 {
                break;
            }
            for j in 0..std::mem::size_of::<c_long>() {
                let byte = ((data >> (j * 8)) & 0xFF) as u8;
                if byte == 0 || res.len() >= max_len - 1 {
                    break 'outer;
                }
                res.push(byte);
            }
        }
        i += std::mem::size_of::<c_long>();
    }
    String::from_utf8_lossy(&res).into_owned()
}

fn write_child_memory(child: i32, addr: u64, data: &[u8]) {
    let mut i = 0;
    while i < data.len() {
        let mut word = 0u64;
        let chunk_size = std::cmp::min(data.len() - i, 8);
        unsafe {
            if chunk_size < 8 {
                // Read existing word to preserve other bytes
                let val = libc::ptrace(libc::PTRACE_PEEKDATA, child, (addr + i as u64) as *mut c_void, ptr::null_mut::<c_void>());
                if val != -1 || *libc::__errno_location() == 0 {
                    word = val as u64;
                }
            }
            
            for j in 0..chunk_size {
                word &= !(0xFF << (j * 8));
                word |= (data[i + j] as u64) << (j * 8);
            }
            
            libc::ptrace(libc::PTRACE_POKEDATA, child, (addr + i as u64) as *mut c_void, word as *mut c_void);
        }
        i += 8;
    }
}

#[derive(Debug)]
pub enum SandboxState {
    NewChild(SandboxedProcess),
    Pause(SystemTime),
    SchedYield,
    WaitForSubprocess,
    Exit(i32),
}

#[derive(Debug)]
pub struct SandboxedProcess {
    child_pid: i32,
    is_entry: bool,
    needs_resume: bool,
}

impl SandboxedProcess {
    pub fn new(command: &str) -> io::Result<Self> {
        unsafe {
            let child = libc::fork();
            if child == 0 {
                libc::ptrace(libc::PTRACE_TRACEME, 0, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                let c_target = CString::new(command.as_bytes()).unwrap();
                let args_ptrs = [c_target.as_ptr(), ptr::null()];
                libc::execvp(c_target.as_ptr(), args_ptrs.as_ptr());
                libc::perror(b"execvp\0".as_ptr() as *const i8);
                libc::exit(1);
            } else if child > 0 {
                let mut status: c_int = 0;
                if libc::waitpid(child, &mut status, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                
                disable_vdso(child);

                libc::ptrace(libc::PTRACE_SETOPTIONS, child, ptr::null_mut::<c_void>(), (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEVFORK) as *mut c_void);

                Ok(SandboxedProcess {
                    child_pid: child,
                    is_entry: true,
                    needs_resume: true,
                })
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn from_pid(pid: i32) -> Self {
        SandboxedProcess {
            child_pid: pid,
            is_entry: true,
            needs_resume: true,
        }
    }

    pub fn resume(&mut self, when: SystemTime) -> io::Result<SandboxState> {
        loop {
            if self.needs_resume {
                unsafe {
                    if libc::ptrace(libc::PTRACE_SYSCALL, self.child_pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                }
                self.needs_resume = false;
            }

            let mut status: c_int = 0;
            let pid = unsafe { libc::waitpid(self.child_pid, &mut status, libc::WNOHANG) };
            if pid == -1 {
                return Err(io::Error::last_os_error());
            }
            if pid == 0 {
                return Ok(SandboxState::SchedYield);
            }

            self.needs_resume = true;

            match self.handle_event(status, when)? {
                Some(state) => return Ok(state),
                None => continue,
            }
        }
    }

    pub fn pid(&self) -> i32 {
        self.child_pid
    }

    pub fn handle_event(&mut self, status: c_int, now: SystemTime) -> io::Result<Option<SandboxState>> {
        let child = self.child_pid;
        
        eprintln!("[debug] Handle event: pid={}, status={:x}, WIFSTOPPED: {}, WSTOPSIG: {:x}, is_entry: {}", child, status, libc::WIFSTOPPED(status), libc::WSTOPSIG(status), self.is_entry);

        if libc::WIFEXITED(status) {
            return Ok(Some(SandboxState::Exit(libc::WEXITSTATUS(status))));
        }

        if libc::WIFSIGNALED(status) {
            return Ok(Some(SandboxState::Exit(-libc::WTERMSIG(status))));
        }

        if (status >> 16) == (libc::PTRACE_EVENT_FORK as i32) || (status >> 16) == (libc::PTRACE_EVENT_CLONE as i32) || (status >> 16) == (libc::PTRACE_EVENT_VFORK as i32) {
            let mut new_pid: c_long = 0;
            unsafe {
                libc::ptrace(libc::PTRACE_GETEVENTMSG, child, ptr::null_mut::<c_void>(), &mut new_pid as *mut c_long);
            }
            println!("[container] New child process detected: {}", new_pid);
            return Ok(Some(SandboxState::NewChild(SandboxedProcess::from_pid(new_pid as i32))));
        }

        if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == (SIGTRAP | 0x80) {
            if self.is_entry {
                let mut regs = [0u64; 64];
                let mut iov = iovec {
                    iov_base: regs.as_mut_ptr() as *mut c_void,
                    iov_len: std::mem::size_of_val(&regs),
                };

                let res = unsafe {
                    libc::ptrace(
                        libc::PTRACE_GETREGSET,
                        child,
                        NT_PRSTATUS as *mut c_void,
                        &mut iov as *mut iovec,
                    )
                };

                if res == 0 {
                    let regs_count = iov.iov_len / std::mem::size_of::<u64>();
                    if regs_count > 15 {
                        let syscall_nr = regs[15];
                        let name = syscall_name(syscall_nr);
                        println!("[container] Syscall: {} ({})", syscall_nr, name);

                        if !is_allowed(syscall_nr) {
                            eprintln!("[container] FORBIDDEN syscall: {} ({}). Killing child.", syscall_nr, name);
                            unsafe {
                                libc::ptrace(libc::PTRACE_KILL, child, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                            }
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "Forbidden syscall"));
                        }

                        if syscall_nr == X86_64_SYS_OPENAT {
                            let path = read_child_string(child, regs[13], 4096);
                            println!("[container] openat(dirfd={}, pathname=\"{}\", ...)", regs[14] as i64, path);
                        }

                        if syscall_nr == X86_64_SYS_WRITE {
                            let fd = regs[14] as i32;
                            let addr = regs[13];
                            let len = regs[12];

                            if fd >= 0 && fd <= 2 && len > 0 && len < 1000000 {
                                println!("[container] write(fd={}, addr={:x}, len={})", fd, addr, len);
                                print_escaped(child, addr, if len > 128 { 128 } else { len });
                                let s = read_child_string(child, addr, len as usize);
                                println!("[container] write(fd={}, addr={:x}, len={}) = \"{}\"", fd, addr, len, s);
                            }
                        }

                        if syscall_nr == X86_64_SYS_CLOCK_GETTIME {
                            let clk_id = regs[14];
                            let timespec_ptr = regs[13];
                            println!("[container] clock_gettime(clk_id={}, timespec_ptr={:x})", clk_id, timespec_ptr);
                            
                            let since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
                            let seconds = since_epoch.as_secs();
                            let nanoseconds = since_epoch.subsec_nanos() as i64;

                            let mut timespec_data = [0u8; 16];
                            timespec_data[0..8].copy_from_slice(&seconds.to_le_bytes());
                            timespec_data[8..16].copy_from_slice(&nanoseconds.to_le_bytes());
                            
                            write_child_memory(child, timespec_ptr, &timespec_data);
                            
                            // Skip the syscall
                            regs[15] = 0xFFFFFFFFFFFFFFFF; 
                            let iov = iovec {
                                iov_base: regs.as_mut_ptr() as *mut c_void,
                                iov_len: std::mem::size_of_val(&regs),
                            };
                            unsafe {
                                libc::ptrace(libc::PTRACE_SETREGSET, child, NT_PRSTATUS as *mut c_void, &iov as *const iovec);
                            }
                        }

                        if syscall_nr == X86_64_SYS_NANOSLEEP || syscall_nr == X86_64_SYS_CLOCK_NANOSLEEP {
                            let (req_ptr, _rem_ptr) = if syscall_nr == X86_64_SYS_NANOSLEEP {
                                (regs[14], regs[13])
                            } else {
                                (regs[12], regs[7])
                            };
                            
                            println!("[container] {}(req_ptr={:x})", name, req_ptr);
                            
                            let tv_sec = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, child, req_ptr as *mut c_void, ptr::null_mut::<c_void>()) as u64 };
                            let tv_nsec = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, child, (req_ptr + 8) as *mut c_void, ptr::null_mut::<c_void>()) as u64 };
                            
                            println!("[container] Requested sleep: {}.{:09}s", tv_sec, tv_nsec);
                            
                            let new_now = now + Duration::from_secs(tv_sec) + Duration::from_nanos(tv_nsec);

                            // Skip the syscall
                            regs[15] = 0xFFFFFFFFFFFFFFFF;
                            let iov = iovec {
                                iov_base: regs.as_mut_ptr() as *mut c_void,
                                iov_len: std::mem::size_of_val(&regs),
                            };
                            unsafe {
                                libc::ptrace(libc::PTRACE_SETREGSET, child, NT_PRSTATUS as *mut c_void, &iov as *const iovec);
                            }

                            self.is_entry = !self.is_entry;
                            return Ok(Some(SandboxState::Pause(new_now)));
                        }

                        if syscall_nr == 61 { // wait4
                            println!("[container] wait4 interception, yielding");
                            self.is_entry = !self.is_entry;
                            return Ok(Some(SandboxState::WaitForSubprocess));
                        }
                    }
                }
                io::stdout().flush()?;
            } else {
                // On exit from "skipped" syscall, set return value to 0
                let mut regs = [0u64; 64];
                let mut iov = iovec {
                    iov_base: regs.as_mut_ptr() as *mut c_void,
                    iov_len: std::mem::size_of_val(&regs),
                };
                let res = unsafe { libc::ptrace(libc::PTRACE_GETREGSET, child, NT_PRSTATUS as *mut c_void, &mut iov as *mut iovec) };
                if res == 0 {
                    let syscall_nr = regs[15];
                    if syscall_nr == 0xFFFFFFFFFFFFFFFF {
                        regs[10] = 0; // Success
                        let iov = iovec {
                            iov_base: regs.as_mut_ptr() as *mut c_void,
                            iov_len: std::mem::size_of_val(&regs),
                        };
                        unsafe {
                            libc::ptrace(libc::PTRACE_SETREGSET, child, NT_PRSTATUS as *mut c_void, &iov as *const iovec);
                        }
                    } else if syscall_nr == X86_64_SYS_EXECVE && regs[10] == 0 {
                         // execve succeeded, disable vDSO in the new process image
                         println!("[container] execve success, disabling vDSO for pid {}", child);
                         disable_vdso(child);
                    }
                }
            }
            self.is_entry = !self.is_entry;
        }

        Ok(None)
    }
}

impl Drop for SandboxedProcess {
    fn drop(&mut self) {
        unsafe {
            let pid = self.child_pid;
            // Check if process still exists
            if libc::kill(pid, 0) == 0 {
                libc::ptrace(libc::PTRACE_KILL, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);
            }
        }
    }
}
