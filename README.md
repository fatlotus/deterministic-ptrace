# ptrace-sandbox-rust

A basic sandbox implemented in Rust using the `ptrace` system call. This is a translation and enhancement of the original `container.c` program.

## Project Structure

- **`src/lib.rs`**: Library entry point, exports modules.
- **`src/sandbox.rs`**: `SandboxedProcess` struct and core ptrace logic.
- **`src/driver.rs`**: `run_sandbox` wrapper function.
- **`src/vdso.rs`**: Logic to disable vDSO.
- **`src/main.rs`**: CLI wrapper that runs a target program within the sandbox.
- **`src/bin/printf_success.rs`**: A simple test program that prints "Hello, World!".
- **`src/bin/mkdir_fail.rs`**: A test program that attempts a forbidden `mkdir` operation.
- **`src/bin/clock_test.rs`**: A test program for deterministic clock mocking.

## Features

- Intercepts system calls using `ptrace`.
- Restricts allowed system calls (allowlist).
- Logs `openat` and `write` activities, including hex-escaped output for writes.
- Special handling for `openat` to display pathnames.
- Special handling for `write` to display data as hex-escaped bytes.
- Enforces an allowlist of system calls; kills the process on violations.
- **Deterministic Clock**: Mocks `clock_gettime`, `nanosleep`, and `clock_nanosleep`. Time is simulated and only advances when the tracee requests a sleep, ensuring deterministic behavior and fast execution.
- Optimized for AARCH64 register layouts (e.g., in OrbStack).

## Prerequisites

- Rust and Cargo installed.
- A Linux system with `ptrace` support (AARCH64 recommended).

## Building

```bash
cargo build
```

## Running

To run the sandbox with a target program:

```bash
# Run the success test
./target/debug/rust-container ./target/debug/printf_success

# Run the failure test (should kill the child)
./target/debug/rust-container ./target/debug/mkdir_fail
```

## Testing

### Unit Tests

You can run the built-in unit tests with:

```bash
cargo test
```

These tests verify basic functionality like successful execution and correct handling of forbidden syscalls.

### Local CI Testing with `act`

You can verify the GitHub Actions workflow locally using the [act](https://github.com/nektos/act) tool.

To run the ARM64 tests on a Mac (ARM64):
```bash
act -j test --matrix arch:arm64 --matrix os:ubuntu-24.04-arm64 -P ubuntu-24.04-arm64=catthehacker/ubuntu:act-latest --container-options "--privileged"
```

#### ⚠️ Rosetta and Emulation Caveat
When running `act` on a Mac, you may encounter issues trying to run the `x86_64` matrix job if you are on an Apple Silicon (M-series) Mac.

- **ARM64**: Works natively and reliably since the container architecture matches the host.
- **x86_64**: Running `x86_64` containers via Rosetta/QEMU emulation on an ARM Mac does **not** support the `ptrace` features required by this sandbox. You will see test failures (like "Time mismatch" or "Sandbox failed") because the emulation layer does not accurately replicate the ptrace behavior for multi-arch scenarios.
- **Verification**: To properly verify x86_64 changes, use a native x86_64 environment (like a Linux VM or the provided QEMU environment) rather than `act` emulation.

### Clock Mocking Test

To verify the deterministic clock mocking:

```bash
cargo run --bin rust-container -- ./target/debug/clock_test
```

This will run a program that reads the time, sleeps, and reads it again. You'll notice that the "elapsed" time exactly matches the requested sleep duration, even though the real time passes much faster (the sleep is skipped).

## How it works

The sandbox:
1. Forks a child process.
2. The child process calls `ptrace(PTRACE_TRACEME)` and `execvp`.
3. The parent process sets `PTRACE_O_TRACESYSGOOD`.
4. The parent enters a loop using `PTRACE_SYSCALL` to monitor syscall entry points.
5. On entry, it reads registers via `PTRACE_GETREGSET` (mapping `x8` to the syscall number on AARCH64).
6. The syscall is checked against an allowlist.
7. If forbidden, the child process is killed via `PTRACE_KILL`.

## Syscall Allowlist

Includes essential syscalls for Rust's `std` and basic operations:
- `read`, `write`, `openat`, `close`, `lseek`
- `mmap`, `mprotect`, `munmap`, `brk`
- `faccessat`, `faccessat2`, `fstat`, `fstatfs`, `newfstatat`
- `getrandom`, `getpid`, `gettid`, `getrlimit`, `prlimit64`
- `exit_group`, `execve`, `rt_sigreturn`
- `futex`, `set_tid_address`, `set_robust_list`, `sched_getaffinity`, `ppoll`
- `rt_sigsigaction`, `rt_sigprocmask`
- `uname`, `sysinfo`, `getcwd`, `fcntl`, `ioctl`, `readlinkat`, `prctl`, `memfd_create`
