use libc::{c_void, iovec, NT_PRSTATUS};
use std::io::{self};
use crate::sandbox::{SyscallArgs};
use syscalls::Sysno;

pub fn syscall_name(nr: u64) -> &'static str {
    Sysno::new(nr as usize).map(|s| s.name()).unwrap_or("unknown")
}

pub fn is_allowed(sysno: Sysno) -> bool {
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

pub fn get_syscall_args(child: i32) -> io::Result<SyscallArgs> {
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

    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    // On ARM64, the syscall number is not reliably in x8 on exit.
    // Use NT_ARM_SYSTEM_CALL (0x404) instead.
    let mut nr: i32 = 0;
    let mut iov_nr = iovec {
        iov_base: &mut nr as *mut i32 as *mut c_void,
        iov_len: std::mem::size_of_val(&nr),
    };
    let res_nr = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            child,
            0x404 as *mut c_void,
            &mut iov_nr as *mut iovec,
        )
    };

    if res_nr != 0 {
        return Err(io::Error::last_os_error());
    }

    let syscall_nr = nr as u64;
    let sysno = if nr == -1 {
        None
    } else {
        Sysno::new(syscall_nr as usize)
    };

    Ok(SyscallArgs {
        sysno,
        args: [regs[0], regs[1], regs[2], regs[3], regs[4], regs[5]],
    })
}

pub fn set_syscall_ret(child: i32, ret: u64) -> io::Result<()> {
    let mut regs = [0u64; 64];
    let mut iov = iovec {
        iov_base: regs.as_mut_ptr() as *mut c_void,
        iov_len: std::mem::size_of_val(&regs),
    };

    unsafe {
        if libc::ptrace(libc::PTRACE_GETREGSET, child, NT_PRSTATUS as *mut c_void, &mut iov as *mut iovec) == -1 {
            return Err(io::Error::last_os_error());
        }
        regs[0] = ret;
        if libc::ptrace(libc::PTRACE_SETREGSET, child, NT_PRSTATUS as *mut c_void, &iov as *const iovec) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn skip_syscall(child: i32, ret: u64) -> io::Result<()> {
    // Set return value in x0
    set_syscall_ret(child, ret)?;

    // Skip the syscall on ARM64 by setting syscall number to -1 via NT_ARM_SYSTEM_CALL (0x404)
    let mut nr: i32 = -1;
    let iov_nr = iovec {
        iov_base: &mut nr as *mut i32 as *mut c_void,
        iov_len: std::mem::size_of_val(&nr),
    };
    unsafe {
        if libc::ptrace(libc::PTRACE_SETREGSET, child, 0x404 as *mut c_void, &iov_nr as *const iovec) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn get_syscall_ret(child: i32) -> io::Result<u64> {
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
    Ok(regs[0])
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
