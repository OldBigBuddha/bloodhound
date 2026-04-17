use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
    bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use bloodhound_common::{EventHeader, COMM_SIZE};

use crate::vmlinux::task_struct;
use crate::{DAEMON_PID, TARGET_AUID};

/// Read auid (loginuid.val) from the current task's task_struct.
///
/// Uses the typed `task_struct` definition from `vmlinux.rs` to compute
/// the field offset via `core::ptr::addr_of!`, replacing the previous
/// hardcoded byte offset (`0xc88`).
///
/// # CO-RE Note
///
/// The field offset is derived at compile time from the struct layout
/// in `vmlinux.rs` (target: kernel 6.8.0-49-generic, x86_64). When
/// the target kernel changes, update `vmlinux.rs` — see that module's
/// documentation for the regeneration procedure.
///
/// When rustc gains `preserve_access_index` support, the BPF loader
/// will automatically relocate this access for different kernels
/// without any code changes.
#[inline(always)]
pub unsafe fn get_current_auid() -> u32 {
    let task = bpf_get_current_task();
    if task == 0 {
        return u32::MAX;
    }
    let task_ptr = task as *const task_struct;

    // Read loginuid (kuid_t) via typed pointer.
    // addr_of! computes the field offset from the struct definition
    // in vmlinux.rs, avoiding a hardcoded hex constant.
    let loginuid_ptr = core::ptr::addr_of!((*task_ptr).loginuid);
    bpf_probe_read_kernel(loginuid_ptr)
        .map(|kuid| kuid.val)
        .unwrap_or(u32::MAX)
}

/// Read sessionid from the current task's task_struct.
///
/// Same CO-RE approach as `get_current_auid` — the offset comes from
/// the typed struct definition in `vmlinux.rs`.
#[inline(always)]
pub unsafe fn get_current_sessionid() -> u32 {
    let task = bpf_get_current_task();
    if task == 0 {
        return u32::MAX;
    }
    let task_ptr = task as *const task_struct;

    let sessionid_ptr = core::ptr::addr_of!((*task_ptr).sessionid);
    bpf_probe_read_kernel(sessionid_ptr)
        .unwrap_or(u32::MAX)
}

/// Check if the current task should be traced (matches TARGET_AUID).
#[inline(always)]
pub unsafe fn should_trace() -> bool {
    let auid = get_current_auid();
    let target = core::ptr::read_volatile(&raw const TARGET_AUID);
    if auid != target {
        return false;
    }
    // Don't trace ourselves
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let daemon_pid = core::ptr::read_volatile(&raw const DAEMON_PID);
    if tgid == daemon_pid {
        return false;
    }
    true
}

/// Populate an EventHeader with current task info.
#[inline(always)]
pub unsafe fn get_task_info(kind: u8) -> EventHeader {
    let timestamp_ns = bpf_ktime_get_ns();
    let auid = get_current_auid();
    let sessionid = get_current_sessionid();
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; COMM_SIZE],
    };

    // ppid is populated in userspace from /proc
    EventHeader {
        kind,
        _pad: [0; 3],
        timestamp_ns,
        auid,
        sessionid,
        pid: tgid,
        ppid: 0,
        comm,
    }
}
