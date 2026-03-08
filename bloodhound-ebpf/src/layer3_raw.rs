use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::tracepoint,
    programs::TracePointContext,
};
use bloodhound_common::*;

use crate::filter::{get_task_info, should_trace};
use crate::helpers::emit_event;
use crate::maps::{EXCLUSION_BITMAP, SYSCALL_ENTRY_MAP, TIER2_BITMAP};

// ── raw_syscalls:sys_enter ───────────────────────────────────────────────────

#[tracepoint]
pub fn raw_sys_enter(ctx: TracePointContext) -> u32 {
    match unsafe { try_raw_sys_enter(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_raw_sys_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // raw_syscalls/sys_enter: offset 8 = id (long), offset 16 = args[0..6]
    let nr: i64 = ctx.read_at(8).map_err(|_| -1i64)?;
    let nr = nr as u64;

    if nr >= BITMAP_SIZE as u64 {
        return Ok(0);
    }

    let nr_idx = nr as u32;

    // Check exclusion bitmap
    if let Some(excluded) = EXCLUSION_BITMAP.get(nr_idx) {
        if *excluded != 0 {
            return Ok(0);
        }
    }

    // Check Tier 2 bitmap (skip if handled by rich extraction)
    if let Some(tier2) = TIER2_BITMAP.get(nr_idx) {
        if *tier2 != 0 {
            return Ok(0);
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(EventKind::RawSyscall as u8);

    // Read the 6 raw args from the tracepoint context
    let mut args = [0u64; 6];
    for i in 0..6 {
        args[i] = ctx.read_at(16 + i * 8).unwrap_or(0);
    }

    let entry = SyscallEntry {
        header,
        syscall_nr: nr,
        args,
    };

    let _ = SYSCALL_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

// ── raw_syscalls:sys_exit ────────────────────────────────────────────────────

#[tracepoint]
pub fn raw_sys_exit(ctx: TracePointContext) -> u32 {
    match unsafe { try_raw_sys_exit(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_raw_sys_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let entry = match SYSCALL_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };

    // raw_syscalls/sys_exit: offset 8 = id, offset 16 = ret
    let return_code: i64 = ctx.read_at(16).map_err(|_| -1i64)?;

    let payload = RawSyscallPayload {
        syscall_nr: entry.syscall_nr,
        args: entry.args,
        return_code,
    };

    // Emit as flat bytes: EventHeader + RawSyscallPayload
    let total_size = EventHeader::SIZE + RawSyscallPayload::SIZE;
    let mut buf = [0u8; 256]; // EventHeader + RawSyscallPayload fits easily
    core::ptr::copy_nonoverlapping(
        &entry.header as *const EventHeader as *const u8,
        buf.as_mut_ptr(),
        EventHeader::SIZE,
    );
    core::ptr::copy_nonoverlapping(
        &payload as *const RawSyscallPayload as *const u8,
        buf.as_mut_ptr().add(EventHeader::SIZE),
        RawSyscallPayload::SIZE,
    );

    emit_event(&buf[..total_size]);

    let _ = SYSCALL_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}
