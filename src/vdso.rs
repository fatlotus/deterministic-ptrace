use libc::{c_void, iovec, NT_PRSTATUS};
use std::ptr;

pub fn disable_vdso(child: i32) {
    let mut regs = [0u64; 64];
    let mut iov = iovec {
        iov_base: regs.as_mut_ptr() as *mut c_void,
        iov_len: std::mem::size_of_val(&regs),
    };

    unsafe {
        let res = libc::ptrace(
            libc::PTRACE_GETREGSET,
            child,
            NT_PRSTATUS as *mut c_void,
            &mut iov as *mut iovec,
        );

        if res != 0 {
            return;
        }

        let sp = regs[19];
        let mut addr = sp;
        let argc = libc::ptrace(libc::PTRACE_PEEKDATA, child, addr as *mut c_void, ptr::null_mut::<c_void>()) as u64;
        addr += 8; // skip argc
        addr += (argc + 1) * 8; // skip argv and NULL
        
        // skip envp
        loop {
            let env_ptr = libc::ptrace(libc::PTRACE_PEEKDATA, child, addr as *mut c_void, ptr::null_mut::<c_void>()) as u64;
            addr += 8;
            if env_ptr == 0 {
                break;
            }
        }
        
        // Now we are at auxv
        let mut vdso_addr = 0u64;
        let mut auxv_addr = addr;
        loop {
            let a_type = libc::ptrace(libc::PTRACE_PEEKDATA, child, auxv_addr as *mut c_void, ptr::null_mut::<c_void>()) as u64;
            let a_val = libc::ptrace(libc::PTRACE_PEEKDATA, child, (auxv_addr + 8) as *mut c_void, ptr::null_mut::<c_void>()) as u64;
            if a_type == 0 { // AT_NULL
                break;
            }
            if a_type == 33 { // AT_SYSINFO_EHDR
                vdso_addr = a_val;
                eprintln!("[debug] Found VDSO at {:x} (auxv addr {:x})", vdso_addr, auxv_addr);
                // Zero out AT_SYSINFO_EHDR value
                libc::ptrace(libc::PTRACE_POKEDATA, child, (auxv_addr + 8) as *mut c_void, 0 as *mut c_void);
            }
            auxv_addr += 16;
        }

        if vdso_addr != 0 {
            // Scan stack to zero out other references
            for i in 0..1024 {
                let test_addr = sp + i * 8;
                let val = libc::ptrace(libc::PTRACE_PEEKDATA, child, test_addr as *mut c_void, ptr::null_mut::<c_void>()) as u64;
                if val == vdso_addr {
                    eprintln!("[debug] Zeroing VDSO ref on stack at {:x}", test_addr);
                    libc::ptrace(libc::PTRACE_POKEDATA, child, test_addr as *mut c_void, 0 as *mut c_void);
                }
            }
        }
    }
}
