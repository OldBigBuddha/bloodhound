//! Minimal kernel type definitions for bloodhound eBPF programs.
//!
//! These types mirror the layout of kernel structures on the target
//! kernel (**6.8.0-49-generic**, x86_64, Ubuntu 22.04 HWE). Only the
//! fields accessed by bloodhound are included; everything else is
//! opaque padding.
//!
//! # Why not `aya-tool generate`?
//!
//! `task_struct` contains thousands of fields and is ~13 KB in size.
//! Generating the full definition would bloat the `no_std` eBPF crate
//! with tens of thousands of lines of unused types. Instead, we define
//! only the four fields we access (`pid`, `tgid`, `loginuid`,
//! `sessionid`) and pad the gaps.
//!
//! # CO-RE Status (as of 2026-04)
//!
//! The Rust compiler does **not yet** emit `preserve_access_index`
//! BTF relocation markers (the equivalent of Clang's
//! `__attribute__((preserve_access_index))`). This means the BPF
//! loader cannot automatically adjust field offsets for different
//! kernels at load time.
//!
//! As a result, the offsets encoded in this struct are **compile-time
//! fixed** to the target kernel. When rustc gains CO-RE support,
//! this struct definition will work as-is — no code changes needed,
//! only a recompile.
//!
//! # Regeneration
//!
//! When the target kernel changes, update the offsets below.
//! Run the following **on the target VM** (not the build host):
//!
//! ```sh
//! pahole -C task_struct /sys/kernel/btf/vmlinux \
//!     | grep -E 'pid|tgid|loginuid|sessionid'
//! ```
//!
//! Or use the BTF parser script in `docs/ebpf-offsets.md`.
//!
//! Then update the padding sizes and field positions accordingly.

/// Kernel UID type (`linux/uidgid.h`).
///
/// A wrapper around a raw `u32` UID value, matching the kernel's
/// `kuid_t` / `kgid_t` representation.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct kuid_t {
    pub val: u32,
}

/// Minimal `task_struct` layout for kernel 6.8.0-49-generic (x86_64).
///
/// Field offsets verified via BTF / `pahole`:
///
/// | Field       | Offset (hex) | Offset (dec) |
/// |-------------|-------------|--------------|
/// | `pid`       | 0x9a0       | 2464         |
/// | `tgid`      | 0x9a4       | 2468         |
/// | `loginuid`  | 0xc88       | 3208         |
/// | `sessionid` | 0xc8c       | 3212         |
///
/// # Safety
///
/// This struct must **never** be stack-allocated in BPF code. It is
/// only used as a pointee type: obtain a `*const task_struct` from
/// `bpf_get_current_task()` and use `core::ptr::addr_of!` to compute
/// field pointers for `bpf_probe_read_kernel`.
#[repr(C)]
pub struct task_struct {
    /// Opaque padding: bytes 0x000 ..= 0x99f
    _pad0: [u8; 0x9a0],

    /// Process ID (kernel-internal, not necessarily == userspace PID).
    /// Offset: 0x9a0 (2464)
    pub pid: i32,

    /// Thread group ID (== userspace PID for the main thread).
    /// Offset: 0x9a4 (2468)
    pub tgid: i32,

    /// Opaque padding: bytes 0x9a8 ..= 0xc87
    _pad1: [u8; 0xc88 - 0x9a8],

    /// Audit login UID (set once at login, inherited across fork/exec).
    /// Offset: 0xc88 (3208)
    pub loginuid: kuid_t,

    /// Audit session ID.
    /// Offset: 0xc8c (3212)
    pub sessionid: u32,
}
