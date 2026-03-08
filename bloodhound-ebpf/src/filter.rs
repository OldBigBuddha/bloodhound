use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
    bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use bloodhound_common::{EventHeader, COMM_SIZE};

use crate::{DAEMON_PID, TARGET_AUID};

/// Read auid (loginuid.val) from the current task's task_struct.
///
/// # Kernel-Specific Hardcoded Offset
///
/// The loginuid field offset (`0xc88`) was obtained by parsing
/// `/sys/kernel/btf/vmlinux` on the target kernel (6.8.0-49-generic, Ubuntu).
/// This offset varies across kernel versions and configurations.
///
/// To find the correct offset for a different kernel:
/// ```sh
/// pahole -C task_struct /sys/kernel/btf/vmlinux | grep loginuid
/// ```
/// Or use the Python BTF parser in this project's e2e scripts.
///
/// In production, use CO-RE (Compile Once, Run Everywhere) relocations
/// instead of hardcoded offsets. Aya supports this via `#[repr(C)]`
/// BTF-aware struct definitions.
#[inline(always)]
pub unsafe fn get_current_auid() -> u32 {
    let task = bpf_get_current_task();
    if task == 0 {
        return u32::MAX;
    }
    let task_ptr = task as *const u8;

    // Read loginuid.val from task_struct.
    // On kernel 6.8, loginuid is at a specific offset in task_struct.
    // We use bpf_probe_read_kernel to read it safely.
    // The BTF verifier will validate the access at load time.
    //
    // task_struct.loginuid is of type kuid_t which contains a single u32 val field.
    // We read it using the known field offset approach.
    // Note: In Aya with CO-RE, the verifier adjusts offsets automatically
    // when using BTF-aware reads.
    let mut auid: u32 = u32::MAX;
    // loginuid offset in task_struct for kernel 6.8.0-49-generic (Ubuntu 22.04 HWE)
    // See docs/ebpf-offsets.md for the full offset table and verification procedure.
    //   loginuid: offset=0xc88 (3208 bytes)
    //   sessionid: offset=0xc8c (3212 bytes)
    // ⚠️  IMPORTANT: Always verify on the TARGET KERNEL (VM), not the build host.
    //     Wrong offset → reads garbage → should_trace() always returns false → 0 events.
    let loginuid_offset: usize = 0xc88;
    let _ = bpf_probe_read_kernel(
        task_ptr.add(loginuid_offset) as *const u32,
    )
    .map(|v| auid = v);
    auid
}

/// Read sessionid from the current task's task_struct.
#[inline(always)]
pub unsafe fn get_current_sessionid() -> u32 {
    let task = bpf_get_current_task();
    if task == 0 {
        return u32::MAX;
    }
    let task_ptr = task as *const u8;

    let mut sessionid: u32 = u32::MAX;
    // sessionid offset in task_struct (immediately after loginuid, +4 bytes)
    // ⚠️  Same kernel-version caveat as loginuid above.
    let sessionid_offset: usize = 0xc8c;
    let _ = bpf_probe_read_kernel(
        task_ptr.add(sessionid_offset) as *const u32,
    )
    .map(|v| sessionid = v);
    sessionid
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
