use std::io;

fn main() {
    let mut seed = [0u8; 8];
    let res = unsafe {
        libc::getrandom(seed.as_mut_ptr() as *mut libc::c_void, 8, 0)
    };
    
    if res != 8 {
        panic!("getrandom failed: expected 8, got {}", res);
    }
    
    let seed_val = u64::from_le_bytes(seed);
    println!("Child: Seed is {}", seed_val);
    
    // Deterministic bytes from mocked getrandom: 0, 1, 2, 3, 4, 5, 6, 7
    // seed_val should be 0x0706050403020100 = 506097522914230528
    let expected_seed = 506097522914230528u64;
    assert_eq!(seed_val, expected_seed);
    
    // Generate some "random" numbers using a simple LCG with our seed
    let mut current = seed_val;
    let next_val = |c: &mut u64| {
        *c = c.wrapping_mul(6364136223846793005).wrapping_add(1);
        *c
    };
    
    let r1 = next_val(&mut current);
    let r2 = next_val(&mut current);
    let r3 = next_val(&mut current);
    
    println!("Child: r1 = {}", r1);
    println!("Child: r2 = {}", r2);
    println!("Child: r3 = {}", r3);
    
    // These values are derived from expected_seed
    // seed = 0x0706050403020100
    assert_eq!(r1, 1591007245831318785);
    assert_eq!(r2, 1607095655784081454);
    assert_eq!(r3, 2881956705144939031);
    
    println!("Child: All assertions passed!");
}
