use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use bloodhound_common::*;

use crate::filter::get_current_auid;
use crate::helpers::emit_event;
use crate::vmlinux::task_struct;
use crate::{DAEMON_PID, TARGET_AUID};

#[inline(always)]
unsafe fn is_daemon() -> bool {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let daemon_pid = core::ptr::read_volatile(&raw const DAEMON_PID);
    daemon_pid != 0 && tgid == daemon_pid
}

/// Emit an LSM event. Builds flat bytes on the stack.
#[inline(always)]
unsafe fn emit_lsm_event(kind: u8, payload_bytes: &[u8]) {
    let auid = get_current_auid();
    let timestamp_ns = bpf_ktime_get_ns();
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; COMM_SIZE],
    };
    let sessionid = crate::filter::get_current_sessionid();

    let header = EventHeader {
        kind,
        _pad: [0; 3],
        timestamp_ns,
        auid,
        sessionid,
        pid,
        ppid: 0,
        comm,
    };

    let total_size = EventHeader::SIZE + payload_bytes.len();
    let mut buf = [0u8; 256];
    if total_size > buf.len() {
        return;
    }
    core::ptr::copy_nonoverlapping(
        &header as *const EventHeader as *const u8,
        buf.as_mut_ptr(),
        EventHeader::SIZE,
    );
    if !payload_bytes.is_empty() {
        core::ptr::copy_nonoverlapping(
            payload_bytes.as_ptr(),
            buf.as_mut_ptr().add(EventHeader::SIZE),
            payload_bytes.len(),
        );
    }
    emit_event(&buf[..total_size]);
}

// ── lsm/task_kill ────────────────────────────────────────────────────────────
//
// Protects the daemon from being killed by the target user.
//
// # Linux Permission Model & LSM Interaction
//
// The kernel's `check_kill_permission()` checks DAC (standard Unix
// permissions) BEFORE calling the LSM `security_task_kill()` hook.
// This means:
//
//   - If testuser (uid 1000) tries to kill a root daemon:
//     DAC returns -EPERM immediately → LSM hook is NEVER invoked.
//   - If testuser has CAP_KILL (or uses a setuid binary):
//     DAC allows → LSM hook fires → we return -EPERM to block.
//
// The LSM hook is a **secondary defense** for cases that bypass DAC.
// Both layers together protect the daemon.
//
// See docs/ebpf-offsets.md for full explanation and offset verification.

#[lsm]
pub fn task_kill(ctx: LsmContext) -> i32 {
    match unsafe { try_task_kill(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_task_kill(ctx: &LsmContext) -> Result<i32, i64> {
    if is_daemon() {
        return Ok(0);
    }

    let auid = get_current_auid();
    let target_auid = core::ptr::read_volatile(&raw const TARGET_AUID);

    // Only care about kills from the target user
    if auid != target_auid {
        return Ok(0);
    }

    // Read the target task_struct pointer from context.
    // LSM hook signature: security_task_kill(task_struct *p, siginfo *info, int sig, cred *cred)
    //   ctx.arg(0) = target task_struct *p
    //   ctx.arg(2) = signal number
    let target_task: *const task_struct = ctx.arg(0);
    let sig: i32 = ctx.arg(2);

    // Read the target task's tgid (= userspace PID) via typed struct access.
    // The field offset is derived from the task_struct definition in vmlinux.rs
    // (target: kernel 6.8.0-49-generic), replacing the previous hardcoded
    // offset (0x9a4). See vmlinux.rs for the regeneration procedure.
    let tgid_ptr = core::ptr::addr_of!((*target_task).tgid);
    let target_tgid: u32 = bpf_probe_read_kernel(tgid_ptr)
        .map(|v| v as u32)
        .unwrap_or(0);

    let daemon_pid = core::ptr::read_volatile(&raw const DAEMON_PID);

    // Only block kills targeting the daemon process
    if daemon_pid != 0 && target_tgid == daemon_pid {
        let payload = LsmTaskKillPayload {
            target_pid: target_tgid,
            signal: sig as u32,
            return_code: -1,
        };
        let bytes = core::slice::from_raw_parts(
            &payload as *const _ as *const u8,
            LsmTaskKillPayload::SIZE,
        );
        emit_lsm_event(EventKind::LsmTaskKill as u8, bytes);
        Ok(-1) // -EPERM: block target user from killing daemon
    } else {
        // Allow kills to non-daemon processes, but still emit an event for observability
        let payload = LsmTaskKillPayload {
            target_pid: target_tgid,
            signal: sig as u32,
            return_code: 0,
        };
        let bytes = core::slice::from_raw_parts(
            &payload as *const _ as *const u8,
            LsmTaskKillPayload::SIZE,
        );
        emit_lsm_event(EventKind::LsmTaskKill as u8, bytes);
        Ok(0)
    }
}

// ── lsm/bpf ─────────────────────────────────────────────────────────────────

#[lsm]
pub fn bpf_hook(ctx: LsmContext) -> i32 {
    match unsafe { try_bpf_hook(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_bpf_hook(_ctx: &LsmContext) -> Result<i32, i64> {
    if is_daemon() {
        return Ok(0);
    }

    let auid = get_current_auid();
    let target_auid = core::ptr::read_volatile(&raw const TARGET_AUID);
    if auid != target_auid {
        return Ok(0); // Allow non-target user BPF operations
    }

    let payload = LsmBpfPayload {
        cmd: 0,
        return_code: -1,
    };
    let bytes = core::slice::from_raw_parts(
        &payload as *const _ as *const u8,
        LsmBpfPayload::SIZE,
    );
    emit_lsm_event(EventKind::LsmBpf as u8, bytes);
    Ok(-1) // -EPERM: block target user BPF operations
}

// ── lsm/ptrace_access_check ─────────────────────────────────────────────────

#[lsm]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_ptrace(_ctx: &LsmContext) -> Result<i32, i64> {
    if is_daemon() {
        return Ok(0);
    }

    let auid = get_current_auid();
    let target_auid = core::ptr::read_volatile(&raw const TARGET_AUID);
    if auid != target_auid {
        return Ok(0); // Allow non-target user ptrace
    }

    let daemon_pid = core::ptr::read_volatile(&raw const DAEMON_PID);
    let payload = LsmPtracePayload {
        target_pid: daemon_pid,
        return_code: -1,
    };
    let bytes = core::slice::from_raw_parts(
        &payload as *const _ as *const u8,
        LsmPtracePayload::SIZE,
    );
    emit_lsm_event(EventKind::LsmPtraceAccessCheck as u8, bytes);
    Ok(-1) // Block target user ptrace on daemon
}

// ── lsm/file_open ───────────────────────────────────────────────────────────

#[lsm]
pub fn file_open(ctx: LsmContext) -> i32 {
    match unsafe { try_file_open(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_file_open(_ctx: &LsmContext) -> Result<i32, i64> {
    if is_daemon() {
        return Ok(0);
    }
    let auid = get_current_auid();
    let target_auid = core::ptr::read_volatile(&raw const TARGET_AUID);
    if auid != target_auid {
        return Ok(0);
    }

    let payload = LsmFileOpenPayload {
        path_len: 0,
        _pad: [0; 2],
        return_code: 0,
    };
    let bytes = core::slice::from_raw_parts(
        &payload as *const _ as *const u8,
        LsmFileOpenPayload::SIZE,
    );
    emit_lsm_event(EventKind::LsmFileOpen as u8, bytes);
    Ok(0)
}

// ── lsm/inode_unlink ─────────────────────────────────────────────────────────

#[lsm]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    match unsafe { try_inode_op(&ctx, EventKind::LsmInodeUnlink as u8) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_inode_op(_ctx: &LsmContext, kind: u8) -> Result<i32, i64> {
    if is_daemon() {
        return Ok(0);
    }
    let auid = get_current_auid();
    let target_auid = core::ptr::read_volatile(&raw const TARGET_AUID);
    if auid != target_auid {
        return Ok(0);
    }
    let payload = LsmInodePayload {
        path_len: 0,
        _pad: [0; 2],
        return_code: 0,
    };
    let bytes = core::slice::from_raw_parts(
        &payload as *const _ as *const u8,
        LsmInodePayload::SIZE,
    );
    emit_lsm_event(kind, bytes);
    Ok(0)
}

// ── lsm/inode_rename ─────────────────────────────────────────────────────────

#[lsm]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    match unsafe { try_inode_rename(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_inode_rename(_ctx: &LsmContext) -> Result<i32, i64> {
    if is_daemon() {
        return Ok(0);
    }
    let auid = get_current_auid();
    let target_auid = core::ptr::read_volatile(&raw const TARGET_AUID);
    if auid != target_auid {
        return Ok(0);
    }
    let payload = LsmInodeRenamePayload {
        old_path_len: 0,
        new_path_len: 0,
        return_code: 0,
    };
    let bytes = core::slice::from_raw_parts(
        &payload as *const _ as *const u8,
        LsmInodeRenamePayload::SIZE,
    );
    emit_lsm_event(EventKind::LsmInodeRename as u8, bytes);
    Ok(0)
}

// ── lsm/task_fix_setuid ─────────────────────────────────────────────────────

#[lsm]
pub fn task_fix_setuid(ctx: LsmContext) -> i32 {
    match unsafe { try_setuid(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_setuid(_ctx: &LsmContext) -> Result<i32, i64> {
    let auid = get_current_auid();
    let target_auid = core::ptr::read_volatile(&raw const TARGET_AUID);
    if auid != target_auid {
        return Ok(0);
    }
    let payload = LsmSetuidPayload {
        old_uid: 0,
        new_uid: 0,
        old_gid: 0,
        new_gid: 0,
        return_code: 0,
    };
    let bytes = core::slice::from_raw_parts(
        &payload as *const _ as *const u8,
        LsmSetuidPayload::SIZE,
    );
    emit_lsm_event(EventKind::LsmTaskFixSetuid as u8, bytes);
    Ok(0)
}
