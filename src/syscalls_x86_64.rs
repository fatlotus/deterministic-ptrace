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

    let syscall_nr = regs[15]; // orig_rax
    let sysno = if syscall_nr == 0xFFFFFFFFFFFFFFFFu64 {
        None
    } else {
        Sysno::new(syscall_nr as usize)
    };

    // x86_64: rdi, rsi, rdx, r10, r8, r9
    Ok(SyscallArgs {
        sysno,
        args: [regs[14], regs[13], regs[12], regs[7], regs[9], regs[8]],
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
        regs[10] = ret; // rax
        if libc::ptrace(libc::PTRACE_SETREGSET, child, NT_PRSTATUS as *mut c_void, &iov as *const iovec) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn skip_syscall(child: i32, ret: u64) -> io::Result<()> {
    let mut regs = [0u64; 64];
    let mut iov = iovec {
        iov_base: regs.as_mut_ptr() as *mut c_void,
        iov_len: std::mem::size_of_val(&regs),
    };

    unsafe {
        if libc::ptrace(libc::PTRACE_GETREGSET, child, NT_PRSTATUS as *mut c_void, &mut iov as *mut iovec) == -1 {
            return Err(io::Error::last_os_error());
        }
        regs[15] = 0xFFFFFFFFFFFFFFFFu64; // orig_rax = -1
        regs[10] = ret; // rax
        if libc::ptrace(libc::PTRACE_SETREGSET, child, NT_PRSTATUS as *mut c_void, &iov as *const iovec) == -1 {
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
    Ok(regs[10]) // rax
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
    Ok(regs[19]) // rsp
}
