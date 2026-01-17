pub mod driver;
pub mod sandbox;
pub mod vdso;

#[cfg(target_arch = "x86_64")]
#[path = "syscalls_x86_64.rs"]
pub mod arch;

#[cfg(target_arch = "aarch64")]
#[path = "syscalls_aarch64.rs"]
pub mod arch;

pub use driver::run_sandbox;
pub use sandbox::{SandboxedProcess, SandboxState};

