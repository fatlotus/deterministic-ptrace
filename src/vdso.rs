use libc::c_void;
use std::ptr;
use std::io;

pub fn disable_vdso(child: i32, sp: u64) {
    unsafe {
        let mut addr = sp;
        let argc_res = libc::ptrace(libc::PTRACE_PEEKDATA, child, addr as *mut c_void, ptr::null_mut::<c_void>());
        if argc_res == -1 {
            let err = io::Error::last_os_error();
            println!("[vdso] Failed to read argc from sp {:x}: {:?}", sp, err);
            return;
        }
        let argc = argc_res as u64;
        println!("[vdso] sp={:x}, argc={}", sp, argc);
        addr += 8; // skip argc
        addr += (argc + 1) * 8; // skip argv and NULL
        
        // Skip envp
        loop {
            let val = libc::ptrace(libc::PTRACE_PEEKDATA, child, addr as *mut c_void, ptr::null_mut::<c_void>());
            if val == 0 { 
                addr += 8;
                break; 
            }
            if val == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(0) {
                    println!("[vdso] Error reading envp at {:x}: {:?}", addr, err);
                    return;
                }
                addr += 8;
                break;
            }
            addr += 8;
        }

        let mut vdso_addr = 0u64;
        println!("[vdso] Searching auxv at {:x}", addr);
        loop {
            let key = libc::ptrace(libc::PTRACE_PEEKDATA, child, addr as *mut c_void, ptr::null_mut::<c_void>());
            if key == 0 || key == -1 { break; }
            let val = libc::ptrace(libc::PTRACE_PEEKDATA, child, (addr + 8) as *mut c_void, ptr::null_mut::<c_void>()) as u64;
            
            if key == 33 { // AT_SYSINFO_EHDR
                vdso_addr = val;
                libc::ptrace(libc::PTRACE_POKEDATA, child, (addr + 8) as *mut c_void, 0); 
                println!("[vdso] Found and zeroed AT_SYSINFO_EHDR (33) value at {:x}, original value={:x}", addr + 8, val);
                break;
            }
            addr += 16;
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
