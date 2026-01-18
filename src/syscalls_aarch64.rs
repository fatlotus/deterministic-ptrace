use libc::{c_void, iovec, NT_PRSTATUS};
use std::io::{self, Write};
use std::ptr;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use crate::sandbox::{SandboxedProcess, SandboxState, read_child_string, write_child_memory, print_escaped};
use crate::vdso::disable_vdso;

use syscalls::Sysno;

pub fn syscall_name(nr: u64) -> &'static str {
    Sysno::new(nr as usize).map(|s| s.name()).unwrap_or("unknown")
}

pub fn is_allowed(nr: u64) -> bool {
    let Some(sysno) = Sysno::new(nr as usize) else { return false };
    
    // Using a matches! block with Sysno variants for clarity/efficiency
    matches!(
        sysno,
        Sysno::getcwd | Sysno::fcntl | Sysno::ioctl | Sysno::fstatfs
            | Sysno::faccessat | Sysno::openat | Sysno::close | Sysno::lseek
            | Sysno::read | Sysno::write | Sysno::readv | Sysno::writev | Sysno::pread64 
            | Sysno::ppoll | Sysno::readlinkat | Sysno::fstatat | Sysno::fstat 
            | Sysno::exit_group | Sysno::set_tid_address | Sysno::set_robust_list 
            | Sysno::nanosleep | Sysno::clock_gettime | Sysno::clock_nanosleep
            | Sysno::sched_getaffinity | Sysno::tgkill | Sysno::sigaltstack 
            | Sysno::rt_sigaction | Sysno::rt_sigprocmask | Sysno::rt_sigreturn 
            | Sysno::uname | Sysno::getrlimit | Sysno::prlimit64 | Sysno::getpid 
            | Sysno::gettid | Sysno::sysinfo | Sysno::futex | Sysno::munmap 
            | Sysno::brk | Sysno::clone | Sysno::execve | Sysno::execveat 
            | Sysno::mmap | Sysno::mprotect | Sysno::prctl | Sysno::getrandom
            | Sysno::memfd_create | Sysno::clone3 | Sysno::wait4 | Sysno::statx 
            | Sysno::getppid | Sysno::getuid | Sysno::getgid | Sysno::geteuid 
            | Sysno::getegid | Sysno::setuid | Sysno::setgid | Sysno::getdents64 
            | Sysno::dup | Sysno::dup3 | Sysno::pipe2 | Sysno::ftruncate
            | Sysno::fchmod | Sysno::fchown | Sysno::socket | Sysno::connect 
            | Sysno::accept | Sysno::setsockopt | Sysno::getsockopt | Sysno::rseq
            | Sysno::gettimeofday | Sysno::madvise | Sysno::exit
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
            let sysno = Sysno::new(syscall_nr as usize);
            let name = sysno.map(|s| s.name()).unwrap_or("unknown");

            if !is_allowed(syscall_nr) {
                eprintln!("[container] FORBIDDEN syscall: {} ({}). Killing child.", syscall_nr, name);
                unsafe {
                    libc::ptrace(libc::PTRACE_KILL, child, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Forbidden syscall"));
            }

            if sysno == Some(Sysno::openat) {
                let _path = read_child_string(child, regs[1], 4096);
            }

            if sysno == Some(Sysno::write) {
                let fd = regs[0] as i32;
                let addr = regs[1];
                let len = regs[2];

                if fd >= 0 && fd <= 2 && len > 0 && len < 1000000 {
                    print_escaped(child, addr, if len > 128 { 128 } else { len });
                    let _s = read_child_string(child, addr, len as usize);
                }
            }

            if sysno == Some(Sysno::clock_gettime) {
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

            if sysno == Some(Sysno::nanosleep) || sysno == Some(Sysno::clock_nanosleep) {
                let (req_ptr, _rem_ptr) = if sysno == Some(Sysno::nanosleep) {
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

            if sysno == Some(Sysno::getrandom) { // getrandom
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

            if sysno == Some(Sysno::wait4) {
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
            let sysno_exit = Sysno::new(syscall_nr as usize);
            let mut regs = [0u64; 64];
            let mut iov = iovec {
                iov_base: regs.as_mut_ptr() as *mut c_void,
                iov_len: std::mem::size_of_val(&regs),
            };
            let res = unsafe { libc::ptrace(libc::PTRACE_GETREGSET, child, NT_PRSTATUS as *mut c_void, &mut iov as *mut iovec) };
            if res == 0 {
                let ret = regs[0];
                if (sysno_exit == Some(Sysno::execve) || sysno_exit == Some(Sysno::execveat)) && ret == 0 {
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
