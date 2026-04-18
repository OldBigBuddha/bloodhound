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

// ── TTY structs ──────────────────────────────────────────────────────────────

/// Minimal `tty_struct` layout for kernel 6.8.0-49-generic (x86_64).
///
/// Used by Layer 1 TTY hooks (`pty_write`, `n_tty_read`) to identify
/// the underlying device class via `tty->driver->{type,subtype}` and
/// drop events from non-pseudo-terminal devices (physical consoles,
/// serial ports, etc.).
///
/// Field offsets (verified against upstream Linux 6.8 `include/linux/tty.h`):
///
/// | Field    | Offset (hex) | Offset (dec) | Notes                            |
/// |----------|--------------|--------------|----------------------------------|
/// | `driver` | 0x10         | 16           | `struct tty_driver *`            |
///
/// Layout (relevant prefix only):
///
/// ```c
/// struct tty_struct {
///     struct kref kref;                        // 4 bytes, off 0
///     int index;                               // 4 bytes, off 4
///     struct device *dev;                      // 8 bytes, off 8
///     struct tty_driver *driver;               // 8 bytes, off 16  ← we read this
///     struct tty_port *port;                   // 8 bytes, off 24
///     ...
/// };
/// ```
///
/// # Verification
///
/// On the target VM:
///
/// ```sh
/// pahole -C tty_struct /sys/kernel/btf/vmlinux | grep driver
/// ```
///
/// Same regeneration caveat as `task_struct` above.
///
/// # Safety
///
/// Same rules as `task_struct`: never stack-allocate; only use as a
/// pointee through `core::ptr::addr_of!` + `bpf_probe_read_kernel`.
#[repr(C)]
pub struct tty_struct {
    /// Opaque padding: bytes 0x000 ..= 0x00f
    /// Covers `kref` (4) + `index` (4) + `dev` (8).
    _pad0: [u8; 0x10],

    /// Pointer to the TTY driver descriptor. Used to inspect device
    /// class via `driver->type` / `driver->subtype`.
    /// Offset: 0x10 (16)
    pub driver: *const tty_driver,
    // Trailing fields (port, ops, ...) are intentionally omitted.
}

/// Minimal `tty_driver` layout for kernel 6.8.0-49-generic (x86_64).
///
/// Field offsets (verified against upstream Linux 6.8 `include/linux/tty_driver.h`):
///
/// | Field     | Offset (hex) | Offset (dec) | Notes                  |
/// |-----------|--------------|--------------|------------------------|
/// | `type`    | 0x38         | 56           | Device class (TTY/PTY) |
/// | `subtype` | 0x3a         | 58           | Master vs slave PTY    |
///
/// Layout (relevant prefix):
///
/// ```c
/// struct tty_driver {
///     struct kref kref;          // 4 bytes, off 0
///     // 4 bytes alignment padding
///     struct cdev **cdevs;       // 8 bytes, off 8
///     struct module *owner;      // 8 bytes, off 16
///     const char *driver_name;   // 8 bytes, off 24
///     const char *name;          // 8 bytes, off 32
///     int name_base;             // 4 bytes, off 40
///     int major;                 // 4 bytes, off 44
///     int minor_start;           // 4 bytes, off 48
///     unsigned int num;          // 4 bytes, off 52
///     short type;                // 2 bytes, off 56  ← we read this
///     short subtype;             // 2 bytes, off 58  ← we read this
///     ...
/// };
/// ```
///
/// # Verification
///
/// On the target VM:
///
/// ```sh
/// pahole -C tty_driver /sys/kernel/btf/vmlinux | grep -E 'type|subtype'
/// ```
#[repr(C)]
pub struct tty_driver {
    /// Opaque padding: bytes 0x00 ..= 0x37
    /// Covers `kref` + alignment + `cdevs` + `owner` + `driver_name`
    /// + `name` + `name_base` + `major` + `minor_start` + `num`.
    _pad0: [u8; 0x38],

    /// Device class identifier; `TTY_DRIVER_TYPE_PTY` (4) for
    /// pseudo-terminals.
    /// Offset: 0x38 (56)
    pub r#type: i16,

    /// Subtype within the class; `PTY_TYPE_SLAVE` (2) for the
    /// pts/* end of a pseudo-terminal pair (the side connected
    /// to the user shell over SSH).
    /// Offset: 0x3a (58)
    pub subtype: i16,
    // Trailing fields are intentionally omitted.
}

// ── TTY device-class constants ───────────────────────────────────────────────
//
// Stable across all supported kernels (defined in `uapi/linux/tty.h`
// and `include/linux/tty_driver.h`).

/// `tty_driver.type` value indicating a pseudo-terminal pair.
pub const TTY_DRIVER_TYPE_PTY: i16 = 0x0004;

/// `tty_driver.subtype` value indicating the **slave** side of a pty
/// pair (i.e. the `/dev/pts/N` device that the user shell talks to).
pub const PTY_TYPE_SLAVE: i16 = 0x0002;
