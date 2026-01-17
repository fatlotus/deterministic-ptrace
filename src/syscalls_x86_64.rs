use libc::{c_int, c_long, c_void, iovec, NT_PRSTATUS};
use std::io::{self, Write};
use std::ptr;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use crate::sandbox::{SandboxedProcess, SandboxState, read_child_string, write_child_memory, print_escaped};
use crate::vdso::disable_vdso;

const X86_64_SYS_WRITE: u64 = 1;
const X86_64_SYS_OPENAT: u64 = 257;
const X86_64_SYS_NANOSLEEP: u64 = 35;
const X86_64_SYS_CLOCK_GETTIME: u64 = 228;
const X86_64_SYS_CLOCK_NANOSLEEP: u64 = 230;
const X86_64_SYS_EXECVE: u64 = 59;
const X86_64_SYS_GETRANDOM: u64 = 318;
const X86_64_SYS_WAITID: u64 = 247;
const X86_64_SYS_WAIT4: u64 = 61;

pub fn syscall_name(nr: u64) -> &'static str {
    match nr {
        79 => "getcwd",
        72 => "fcntl",
        16 => "ioctl",
        258 => "mkdirat",
        137 => "fstatfs",
        269 => "faccessat",
        257 => "openat",
        2 => "open",
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
        201 => "time",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        54 => "setsockopt",
        55 => "getsockopt",
        110 => "getppid",
        102 => "getuid",
        104 => "getgid",
        107 => "geteuid",
        108 => "getegid",
        105 => "setuid",
        106 => "setgid",
        217 => "getdents64",
        78 => "getdents",
        32 => "dup",
        33 => "dup2",
        292 => "dup3",
        22 => "pipe",
        293 => "pipe2",
        77 => "ftruncate",
        92 => "chown",
        93 => "fchown",
        90 => "chmod",
        91 => "fchmod",
        80 => "chdir",
        81 => "fchdir",
        85 => "creat",
        86 => "link",
        265 => "linkat",
        88 => "symlink",
        266 => "symlinkat",
        89 => "readlink",
        28 => "madvise",
        60 => "exit",
        247 => "waitid",
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
            | 2
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
            | 56
            | 61
            | 332
            | 201
            | 41 | 42 | 43 | 54 | 55 | 110 | 102 | 104 | 107 | 108 | 105 | 106 | 217 | 78 | 32 | 33 | 292 | 22 | 293 | 77 | 92 | 93 | 90 | 91 | 80 | 81 | 85 | 86 | 265 | 88 | 266 | 89
            | 28
            | 60
            | 247
    )
}

pub fn handle_syscall_event(proc: &mut SandboxedProcess, now: SystemTime) -> io::Result<Option<SandboxState>> {
    let child = proc.pid();
    let is_entry = proc.is_entry();

    if is_entry {
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

                    return Ok(Some(SandboxState::Pause(new_now)));
                }

                if syscall_nr == X86_64_SYS_GETRANDOM {
                    let buf_ptr = regs[14];
                    let buf_len = regs[13];
                    println!("[container] getrandom(buf_ptr={:x}, buf_len={})", buf_ptr, buf_len);
                    
                    let mut data = Vec::with_capacity(buf_len as usize);
                    for i in 0..buf_len {
                        data.push(i as u8);
                    }
                    write_child_memory(child, buf_ptr, &data);
                    
                    proc.set_skipped_return_value(Some(buf_len));
                    
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

                if syscall_nr == X86_64_SYS_WAIT4 || syscall_nr == X86_64_SYS_WAITID {
                    println!("[container] wait interception, yielding");
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
                let ret_val = proc.skipped_return_value().unwrap_or(0);
                regs[10] = ret_val;
                proc.set_skipped_return_value(None);
                
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
                    let sp = get_sp(child)?;
                    disable_vdso(child, sp);
            }
        }
    }
    Ok(None)
}

pub fn get_sp(child: i32) -> io::Result<u64> {
    let mut regs = [0u64; 64];
    let mut iov = iovec {
        iov_base: regs.as_mut_ptr() as *mut c_void,
        iov_len: std::mem::size_of_val(&regs),
    };
    unsafe {
        if libc::ptrace(libc::PTRACE_GETREGSET, child, NT_PRSTATUS as *mut c_void, &mut iov as *mut iovec) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(regs[19])
}
