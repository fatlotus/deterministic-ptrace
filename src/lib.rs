pub mod driver;
pub mod syscalls;
pub mod vdso;

#[cfg(target_arch = "x86_64")]
#[path = "sandbox_x86_64.rs"]
pub mod arch;

#[cfg(target_arch = "aarch64")]
#[path = "sandbox_aarch64.rs"]
pub mod arch;

pub use driver::run_sandbox;
pub use syscalls::{SandboxedProcess, SandboxState};

