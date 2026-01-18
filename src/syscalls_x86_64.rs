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
        Sysno::getcwd | Sysno::fcntl | Sysno::ioctl | Sysno::mkdirat | Sysno::fstatfs
            | Sysno::faccessat | Sysno::openat | Sysno::open | Sysno::close | Sysno::lseek
            | Sysno::read | Sysno::write | Sysno::pread64 | Sysno::ppoll | Sysno::readlinkat
            | Sysno::newfstatat | Sysno::fstat | Sysno::poll | Sysno::exit_group | Sysno::set_tid_address
            | Sysno::set_robust_list | Sysno::nanosleep | Sysno::clock_gettime | Sysno::clock_nanosleep
            | Sysno::sched_getaffinity | Sysno::tgkill | Sysno::sigaltstack | Sysno::rt_sigaction
            | Sysno::rt_sigprocmask | Sysno::rt_sigreturn | Sysno::uname | Sysno::getrlimit
            | Sysno::prlimit64 | Sysno::getpid | Sysno::gettid | Sysno::sysinfo | Sysno::futex
            | Sysno::munmap | Sysno::brk | Sysno::access | Sysno::arch_prctl | Sysno::rseq
            | Sysno::execve | Sysno::mmap | Sysno::mprotect | Sysno::prctl | Sysno::getrandom
            | Sysno::memfd_create | Sysno::clone3 | Sysno::wait4 | Sysno::statx | Sysno::time
            | Sysno::socket | Sysno::connect | Sysno::accept | Sysno::setsockopt | Sysno::getsockopt
            | Sysno::getppid | Sysno::getuid | Sysno::getgid | Sysno::geteuid | Sysno::getegid
            | Sysno::setuid | Sysno::setgid | Sysno::getdents64 | Sysno::getdents | Sysno::dup
            | Sysno::dup2 | Sysno::dup3 | Sysno::pipe | Sysno::pipe2 | Sysno::ftruncate
            | Sysno::chown | Sysno::fchown | Sysno::chmod | Sysno::fchmod | Sysno::chdir
            | Sysno::fchdir | Sysno::creat | Sysno::link | Sysno::linkat | Sysno::symlink
            | Sysno::symlinkat| Sysno::readlink | Sysno::madvise | Sysno::exit | Sysno::waitid
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
                let sysno = Sysno::new(syscall_nr as usize);
                let name = sysno.map(|s| s.name()).unwrap_or("unknown");
                println!("[container] Syscall: {} ({})", syscall_nr, name);

                if !is_allowed(syscall_nr) {
                    eprintln!("[container] FORBIDDEN syscall: {} ({}). Killing child.", syscall_nr, name);
                    unsafe {
                        libc::ptrace(libc::PTRACE_KILL, child, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                    }
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Forbidden syscall"));
                }

                if sysno == Some(Sysno::openat) {
                    let path = read_child_string(child, regs[13], 4096);
                    println!("[container] openat(dirfd={}, pathname=\"{}\", ...)", regs[14] as i64, path);
                }

                if sysno == Some(Sysno::write) {
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

                if sysno == Some(Sysno::clock_gettime) {
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

                if sysno == Some(Sysno::nanosleep) || sysno == Some(Sysno::clock_nanosleep) {
                    let (req_ptr, _rem_ptr) = if sysno == Some(Sysno::nanosleep) {
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

                if sysno == Some(Sysno::getrandom) {
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

                if sysno == Some(Sysno::wait4) || sysno == Some(Sysno::waitid) {
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
            let sysno = Sysno::new(syscall_nr as usize);
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
            } else if sysno == Some(Sysno::execve) && regs[10] == 0 {
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
