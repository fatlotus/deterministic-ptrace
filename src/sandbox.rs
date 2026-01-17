use libc::{c_int, c_long, c_void, SIGTRAP};
use std::ffi::CString;
use std::io;
use std::ptr;
use crate::vdso::disable_vdso;
use std::time::SystemTime;
use crate::arch;

// Architecture-dependent syscall details relocated to arch module.

pub fn print_escaped(child: i32, addr: u64, len: u64) {
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
}

pub fn read_child_string(child: i32, addr: u64, max_len: usize) -> String {
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

pub fn write_child_memory(child: i32, addr: u64, data: &[u8]) {
    for i in (0..data.len()).step_by(8) {
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
    pub fn new(args: &[&str]) -> io::Result<Self> {
        unsafe {
            let child = libc::fork();
            if child == 0 {
                libc::ptrace(libc::PTRACE_TRACEME, 0, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
                
                let c_args: Vec<CString> = args.iter()
                    .map(|s| CString::new(*s).unwrap())
                    .collect();
                
                let mut arg_ptrs: Vec<*const libc::c_char> = c_args.iter()
                    .map(|s| s.as_ptr())
                    .collect();
                arg_ptrs.push(ptr::null());

                libc::execvp(arg_ptrs[0], arg_ptrs.as_ptr());
                libc::perror(b"execvp\0".as_ptr() as *const libc::c_char);
                libc::exit(1);
            } else if child > 0 {
                let mut status: c_int = 0;
                if libc::waitpid(child, &mut status, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                
                let sp = arch::get_sp(child)?;
                disable_vdso(child, sp);

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
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
            libc::ptrace(
                libc::PTRACE_SETOPTIONS,
                pid,
                ptr::null_mut::<c_void>(),
                (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEVFORK) as *mut c_void,
            );
        }
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
            let pid = unsafe { libc::waitpid(self.child_pid, &mut status, libc::WNOHANG | 0x40000000) }; // 0x40000000 is __WALL
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

    pub fn is_entry(&self) -> bool {
        self.is_entry
    }

    pub fn set_is_entry(&mut self, is_entry: bool) {
        self.is_entry = is_entry;
    }

    pub fn handle_event(&mut self, status: c_int, now: SystemTime) -> io::Result<Option<SandboxState>> {
        let child = self.child_pid;

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
            return Ok(Some(SandboxState::NewChild(SandboxedProcess::from_pid(new_pid as i32))));
        }

        if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == (SIGTRAP | 0x80) {
            let res = arch::handle_syscall_event(self, now)?;
            self.is_entry = !self.is_entry;
            return Ok(res);
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
