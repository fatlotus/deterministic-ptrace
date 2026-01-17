use libc::{c_void, iovec, NT_PRSTATUS};
use std::io::{self, Write};
use std::ptr;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use crate::sandbox::{SandboxedProcess, SandboxState, read_child_string, write_child_memory, print_escaped};
use crate::vdso::disable_vdso;

const AARCH64_SYS_WRITE: u64 = 64;
const AARCH64_SYS_OPENAT: u64 = 56;
const AARCH64_SYS_NANOSLEEP: u64 = 101;
const AARCH64_SYS_CLOCK_GETTIME: u64 = 113;
const AARCH64_SYS_CLOCK_NANOSLEEP: u64 = 115;
const AARCH64_SYS_EXECVE: u64 = 221;
const AARCH64_SYS_WAIT4: u64 = 260;

pub fn syscall_name(nr: u64) -> &'static str {
    match nr {
        17 => "getcwd",
        25 => "fcntl",
        29 => "ioctl",
        34 => "mkdirat",
        43 => "fstatfs",
        48 => "faccessat",
        56 => "openat",
        57 => "close",
        62 => "lseek",
        63 => "read",
        64 => "write",
        67 => "pread64",
        73 => "ppoll",
        78 => "readlinkat",
        79 => "newfstatat",
        80 => "fstat",
        94 => "exit_group",
        96 => "set_tid_address",
        99 => "set_robust_list",
        101 => "nanosleep",
        113 => "clock_gettime",
        115 => "clock_nanosleep",
        123 => "sched_getaffinity",
        131 => "tgkill",
        132 => "sigaltstack",
        134 => "rt_sigaction",
        135 => "rt_sigprocmask",
        139 => "rt_sigreturn",
        160 => "uname",
        163 => "getrlimit",
        161 => "prlimit64",
        172 => "getpid",
        178 => "gettid",
        179 => "sysinfo",
        98 => "futex",
        215 => "munmap",
        214 => "brk",
        221 => "execve",
        281 => "execveat",
        222 => "mmap",
        226 => "mprotect",
        66 => "writev",
        65 => "readv",
        220 => "clone",
        167 => "prctl",
        278 => "getrandom",
        279 => "memfd_create",
        435 => "clone3",
        260 => "wait4",
        291 => "statx",
        173 => "getppid",
        174 => "getuid",
        176 => "getgid",
        175 => "geteuid",
        177 => "getegid",
        147 => "setuid",
        144 => "setgid",
        61 => "getdents64",
        23 => "dup",
        24 => "dup3",
        59 => "pipe2",
        72 => "ftruncate",
        52 => "fchmod",
        49 => "fchown",
        198 => "socket",
        203 => "connect",
        202 => "accept",
        208 => "setsockopt",
        209 => "getsockopt",
        293 => "rseq",
        261 => "prlimit64",
        169 => "gettimeofday",
        _ => "unknown",
    }
}

pub fn is_allowed(nr: u64) -> bool {
    matches!(
        nr,
        17 | 25
            | 29
//          | 34 // mkdirat - forbidden for tests
            | 43
            | 48
            | 56
            | 57
            | 62
            | 63
            | 64
            | 65
            | 66
            | 67
            | 73
            | 78
            | 79
            | 80
            | 94
            | 96
            | 99
            | 101
            | 113
            | 115
            | 123
            | 131
            | 132
            | 134
            | 135
            | 139
            | 160
            | 163
            | 161
            | 171
            | 172
            | 178
            | 179
            | 98
            | 215
            | 214
            | 220
            | 221
            | 281
            | 222
            | 226
            | 167
            | 278
            | 279
            | 435
            | 260
            | 0 | 291 | 173 | 174 | 176 | 175 | 177 | 147 | 144 | 61 | 23 | 24 | 59 | 72 | 52 | 49 | 198 | 203 | 202 | 208 | 209 | 261 | 293 | 169
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
            // ARM64: x8 is regs[8], syscall number
            // Arguments: x0..x5 => regs[0..6]
            let syscall_nr = regs[8];
            let name = syscall_name(syscall_nr);

            if !is_allowed(syscall_nr) {
                eprintln!("[container] FORBIDDEN syscall: {} ({}). Killing child.", syscall_nr, name);
                unsafe {
                    libc::ptrace(libc::PTRACE_KILL, child, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Forbidden syscall"));
            }

            if syscall_nr == AARCH64_SYS_OPENAT {
                let _path = read_child_string(child, regs[1], 4096);
            }

            if syscall_nr == AARCH64_SYS_WRITE {
                let fd = regs[0] as i32;
                let addr = regs[1];
                let len = regs[2];

                if fd >= 0 && fd <= 2 && len > 0 && len < 1000000 {
                    print_escaped(child, addr, if len > 128 { 128 } else { len });
                    let _s = read_child_string(child, addr, len as usize);
                }
            }

            if syscall_nr == AARCH64_SYS_CLOCK_GETTIME {
                let _clk_id = regs[0];
                let timespec_ptr = regs[1];
                
                let since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
                let seconds = since_epoch.as_secs();
                let nanoseconds = since_epoch.subsec_nanos() as i64;

                let mut timespec_data = [0u8; 16];
                timespec_data[0..8].copy_from_slice(&seconds.to_le_bytes());
                timespec_data[8..16].copy_from_slice(&nanoseconds.to_le_bytes());
                
                write_child_memory(child, timespec_ptr, &timespec_data);

                // Set return value to 0
                regs[0] = 0;
                let iov_regs = iovec {
                    iov_base: regs.as_ptr() as *mut c_void,
                    iov_len: std::mem::size_of_val(&regs),
                };
                unsafe {
                    libc::ptrace(libc::PTRACE_SETREGSET, child, NT_PRSTATUS as *mut c_void, &iov_regs as *const iovec);
                }

                // Skip the syscall on ARM64 by setting syscall number to -1
                let mut nr: i32 = -1;
               let iov_nr = iovec {
                    iov_base: &mut nr as *mut i32 as *mut c_void,
                    iov_len: std::mem::size_of_val(&nr),
                };
                unsafe {
                    libc::ptrace(libc::PTRACE_SETREGSET, child, 0x404 as *mut c_void, &iov_nr as *const iovec);
                }
            }

            if syscall_nr == AARCH64_SYS_NANOSLEEP || syscall_nr == AARCH64_SYS_CLOCK_NANOSLEEP {
                let (req_ptr, _rem_ptr) = if syscall_nr == AARCH64_SYS_NANOSLEEP {
                    (regs[0], regs[1])
                } else {
                    (regs[2], regs[3])
                };
                
                let tv_sec = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, child, req_ptr as *mut c_void, ptr::null_mut::<c_void>()) as u64 };
                let tv_nsec = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, child, (req_ptr + 8) as *mut c_void, ptr::null_mut::<c_void>()) as u64 };
                
                let new_now = now + Duration::from_secs(tv_sec) + Duration::from_nanos(tv_nsec);

                // Skip the syscall: set syscall number to -1 via NT_ARM_SYSTEM_CALL
                let mut nr: i32 = -1;
                let iov_nr = iovec {
                    iov_base: &mut nr as *mut i32 as *mut c_void,
                    iov_len: std::mem::size_of_val(&nr),
                };
                unsafe {
                    libc::ptrace(libc::PTRACE_SETREGSET, child, 0x404 as *mut c_void, &iov_nr as *const iovec);
                }

                return Ok(Some(SandboxState::Pause(new_now)));
            }

            if syscall_nr == 278 { // getrandom
                let buf_ptr = regs[0];
                let buf_len = regs[1];
                let _flags = regs[2];

                let mut data = Vec::with_capacity(buf_len as usize);
                for i in 0..buf_len {
                    data.push(i as u8);
                }
                write_child_memory(child, buf_ptr, &data);

                // Set return value to bytes written
                regs[0] = buf_len;
                let iov_regs = iovec {
                    iov_base: regs.as_ptr() as *mut c_void,
                    iov_len: std::mem::size_of_val(&regs),
                };
                unsafe {
                    libc::ptrace(libc::PTRACE_SETREGSET, child, NT_PRSTATUS as *mut c_void, &iov_regs as *const iovec);
                }

                // Skip the syscall: set syscall number to -1
                let mut nr: i32 = -1;
                let iov_nr = iovec {
                    iov_base: &mut nr as *mut i32 as *mut c_void,
                    iov_len: std::mem::size_of_val(&nr),
                };
                unsafe {
                    libc::ptrace(libc::PTRACE_SETREGSET, child, 0x404 as *mut c_void, &iov_nr as *const iovec);
                }
            }

            if syscall_nr == AARCH64_SYS_WAIT4 {
                return Ok(Some(SandboxState::WaitForSubprocess));
            }
        }
        io::stdout().flush()?;
    } else {
        // On exit from "skipped" syscall, set return value to 0
        let mut nr: i32 = 0;
        let mut iov_nr = iovec {
            iov_base: &mut nr as *mut i32 as *mut c_void,
            iov_len: std::mem::size_of_val(&nr),
        };
        let res_nr = unsafe { libc::ptrace(libc::PTRACE_GETREGSET, child, 0x404 as *mut c_void, &mut iov_nr as *mut iovec) };

        if res_nr == 0 && nr == -1 {
            // Already handled at entry
        } else {
            // nr is the original syscall number
            let syscall_nr = nr as u64;
            let mut regs = [0u64; 64];
            let mut iov = iovec {
                iov_base: regs.as_mut_ptr() as *mut c_void,
                iov_len: std::mem::size_of_val(&regs),
            };
            let res = unsafe { libc::ptrace(libc::PTRACE_GETREGSET, child, NT_PRSTATUS as *mut c_void, &mut iov as *mut iovec) };
            if res == 0 {
                let ret = regs[0];
                if (syscall_nr == AARCH64_SYS_EXECVE || syscall_nr == 281) && ret == 0 {
                    let sp = get_sp(child)?;
                    disable_vdso(child, sp);
                }
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
    Ok(regs[31])
}
