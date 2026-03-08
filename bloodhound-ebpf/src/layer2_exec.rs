use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use bloodhound_common::*;

use crate::filter::{get_task_info, should_trace};
use crate::helpers::{emit_event, bpf_memcpy, increment_drop_count};
use crate::maps::{ASSEMBLY_BUF, EXECVE_ENTRY_MAP, EXECVE_TMP_BUF, SCRATCH_BUF};

// ── sys_enter_execve ─────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_execve(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // Tracepoint args layout for sys_enter_execve:
    // offset 16: filename pointer (u64)
    // offset 24: argv pointer (u64)
    let filename_ptr: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let argv_ptr: u64 = ctx.read_at(24).map_err(|_| -1i64)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(EventKind::Execve as u8);

    // Read filename into scratch buffer 0
    let filename_len = read_filename(filename_ptr as *const u8);

    // Read argv into scratch buffer 1
    let argv_len = read_argv(argv_ptr as *const *const u8);

    let entry_ptr = match EXECVE_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let mut entry = unsafe { &mut *entry_ptr };
    
    entry.header = header;
    entry.filename_len = filename_len;
    entry.argv_len = argv_len;

    // Copy from scratch buffers into entry.
    // ⚠️  BPF verifier constraint: MUST use bpf_memcpy() here, NOT copy_nonoverlapping.
    // copy_nonoverlapping with variable length up to MAX_PATH_SIZE (4095) gets
    // unrolled by LLVM into 4095 individual load/store pairs. With multiple call
    // sites, this easily exceeds the BPF verifier's 1M instruction limit.
    // bpf_memcpy uses the bpf_probe_read_kernel helper (1 BPF instruction per copy).
    if filename_len > 0 {
        if let Some(scratch) = SCRATCH_BUF.get_ptr(0) {
            let copy_len = (filename_len as usize).min(MAX_PATH_SIZE - 1);
            bpf_memcpy(
                entry.filename_buf.as_mut_ptr(),
                (*scratch).buf.as_ptr(),
                copy_len as u32,
            );
        }
    }
    if argv_len > 0 {
        if let Some(scratch) = SCRATCH_BUF.get_ptr(1) {
            let copy_len = (argv_len as usize).min(MAX_ARGV_SIZE - 1);
            bpf_memcpy(
                entry.argv_buf.as_mut_ptr(),
                (*scratch).buf.as_ptr(),
                copy_len as u32,
            );
        }
    }

    let _ = EXECVE_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

// ── sys_exit_execve ──────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_exit_execve(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_execve(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_sys_exit_execve(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let entry = match EXECVE_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => e,
        None => return Ok(0),
    };

    // sys_exit tracepoint: offset 16 = return value (i64)
    let return_code: i64 = ctx.read_at(16).map_err(|_| -1i64)?;

    // Build event bytes: header + ExecvePayload + filename + argv
    let filename_len = (entry.filename_len as usize).min(MAX_PATH_SIZE - 1);
    let argv_len = (entry.argv_len as usize).min(MAX_ARGV_SIZE - 1);

    let payload = ExecvePayload {
        filename_len: entry.filename_len,
        argv_len: entry.argv_len,
        return_code: return_code as i32,
    };

    // Build flat buffer on stack (limited, but sufficient for header + payload)
    // Use emit_event with a stack buffer for the fixed parts,
    // then append variable data
    let total_size = EventHeader::SIZE + ExecvePayload::SIZE + filename_len + argv_len;

    // Use the larger assembly buffer for execve events (can exceed 4KB)
    if let Some(asm) = ASSEMBLY_BUF.get_ptr_mut(0) {
        let buf = &mut (*asm).buf;
        if total_size > buf.len() {
            let _ = EXECVE_ENTRY_MAP.remove(&pid_tgid);
            return Ok(0);
        }

        let ptr = buf.as_mut_ptr();

        // Write header
        core::ptr::copy_nonoverlapping(
            &entry.header as *const EventHeader as *const u8,
            ptr,
            EventHeader::SIZE,
        );

        // Write payload
        core::ptr::copy_nonoverlapping(
            &payload as *const ExecvePayload as *const u8,
            ptr.add(EventHeader::SIZE),
            ExecvePayload::SIZE,
        );

        // Write filename (variable length — MUST use bpf_memcpy, see comment above)
        // ⚠️  copy_nonoverlapping here would unroll to up to 4095 load/store pairs
        let fname_offset = EventHeader::SIZE + ExecvePayload::SIZE;
        if filename_len > 0 {
            bpf_memcpy(
                ptr.add(fname_offset),
                entry.filename_buf.as_ptr(),
                filename_len as u32,
            );
        }

        // Write argv (variable length — use bpf_memcpy)
        let argv_offset = fname_offset + filename_len;
        if argv_len > 0 && argv_offset + argv_len <= buf.len() {
            bpf_memcpy(
                ptr.add(argv_offset),
                entry.argv_buf.as_ptr(),
                argv_len as u32,
            );
        }

        let event_slice = &buf[..total_size];
        emit_event(event_slice);
    }

    let _ = EXECVE_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── sys_enter_execveat ───────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_execveat(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_execveat(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // execveat: offset 16=dirfd, offset 24=filename, offset 32=argv
    let filename_ptr: u64 = ctx.read_at(24).map_err(|_| -1i64)?;
    let argv_ptr: u64 = ctx.read_at(32).map_err(|_| -1i64)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(EventKind::Execveat as u8);

    let filename_len = read_filename(filename_ptr as *const u8);
    let argv_len = read_argv(argv_ptr as *const *const u8);

    let entry_ptr = match EXECVE_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let mut entry = unsafe { &mut *entry_ptr };
    
    entry.header = header;
    entry.filename_len = filename_len;
    entry.argv_len = argv_len;

    if filename_len > 0 {
        if let Some(scratch) = SCRATCH_BUF.get_ptr(0) {
            let copy_len = (filename_len as usize).min(MAX_PATH_SIZE - 1);
            bpf_memcpy(
                entry.filename_buf.as_mut_ptr(),
                (*scratch).buf.as_ptr(),
                copy_len as u32,
            );
        }
    }
    if argv_len > 0 {
        if let Some(scratch) = SCRATCH_BUF.get_ptr(1) {
            let copy_len = (argv_len as usize).min(MAX_ARGV_SIZE - 1);
            bpf_memcpy(
                entry.argv_buf.as_mut_ptr(),
                (*scratch).buf.as_ptr(),
                copy_len as u32,
            );
        }
    }

    let _ = EXECVE_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_execveat(ctx: TracePointContext) -> u32 {
    // Reuse the same exit handler
    match unsafe { try_sys_exit_execve(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

// ── Helper functions ─────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn read_filename(filename_ptr: *const u8) -> u16 {
    if filename_ptr.is_null() {
        return 0;
    }
    let buf = match SCRATCH_BUF.get_ptr_mut(0) {
        Some(b) => &mut (*b).buf,
        None => return 0,
    };
    match bpf_probe_read_user_str_bytes(filename_ptr, buf) {
        Ok(s) => s.len() as u16,
        Err(_) => 0,
    }
}

/// Read argv entries from userspace into SCRATCH_BUF slot 1.
///
/// # BPF Verifier Constraints
///
/// This function works around three BPF verifier limitations:
///
/// 1. **No variable-offset helper calls**: The verifier rejects
///    `bpf_probe_read_user_str(map_value + variable_offset, ...)` because
///    it cannot prove `offset + size ≤ map_size` when offset and size are
///    tracked independently. We work around this by reading each arg into
///    a separate temp buffer (slot 3) at offset 0, then copying.
///
/// 2. **No `copy_nonoverlapping` for large sizes**: LLVM unrolls
///    `copy_nonoverlapping(src, dst, 256)` into 256 individual load/store
///    pairs, which blows up instruction count (256 × 20 iterations = 5120
///    extra insns). We use `bpf_probe_read_kernel` helper instead (1 insn).
///
/// 3. **Instruction count limit (1M)**: The loop is capped at MAX_ARGS=20
///    (not MAX_ARGV_COUNT=128) to stay under the 1M instruction limit.
///
/// # Resulting Limitations
///
/// - **Max 20 argv entries** (args beyond 20 are silently dropped)
/// - **Max 255 bytes per arg** (longer args are truncated)
/// - **Total argv buffer: 4096 bytes** (shared across all entries)
#[inline(always)]
unsafe fn read_argv(argv_ptr: *const *const u8) -> u16 {
    if argv_ptr.is_null() {
        return 0;
    }
    let buf = match SCRATCH_BUF.get_ptr_mut(1) {
        Some(b) => &mut (*b).buf,
        None => return 0,
    };
    // Use scratch slot 3 as temp buffer — always read at offset 0 (verifier happy)
    let tmp = match SCRATCH_BUF.get_ptr_mut(3) {
        Some(b) => &mut (*b).buf,
        None => return 0,
    };

    const MASK: usize = MAX_ARGV_SIZE - 1; // 0xFFF
    // Max bytes per single arg — must be power of 2 for bitmask bounds
    const MAX_SINGLE_ARG: usize = 256;
    const ARG_MASK: usize = MAX_SINGLE_ARG - 1; // 0xFF
    // Break when offset exceeds this — ensures offset + MAX_SINGLE_ARG ≤ MAX_ARGV_SIZE
    const OFFSET_LIMIT: usize = MAX_ARGV_SIZE - MAX_SINGLE_ARG; // 3840
    // Limit iterations to keep BPF instruction count under 1M limit
    // (each iteration generates ~2K insns due to helper calls and bounds checks)
    const MAX_ARGS: usize = 20;

    let mut offset: usize = 0;

    for i in 0..MAX_ARGS {
        let safe_offset = offset & MASK;
        if safe_offset > OFFSET_LIMIT {
            break;
        }

        let arg_ptr: *const u8 = match bpf_probe_read_user(argv_ptr.add(i) as *const *const u8) {
            Ok(p) => p,
            Err(_) => break,
        };
        if arg_ptr.is_null() {
            break;
        }

        // Read into FULL temp buffer at offset 0 — verifier always sees off=0, size=4096
        match bpf_probe_read_user_str_bytes(arg_ptr, tmp) {
            Ok(s) => {
                // Clamp len to MAX_SINGLE_ARG-1 via bitmask
                let len = s.len() & ARG_MASK;
                // Use raw bpf_probe_read_kernel helper for copy (single BPF helper call,
                // NOT unrolled like copy_nonoverlapping which becomes 256 load/store pairs)
                let _ = aya_ebpf::helpers::gen::bpf_probe_read_kernel(
                    buf.as_mut_ptr().add(safe_offset) as *mut core::ffi::c_void,
                    MAX_SINGLE_ARG as u32,
                    tmp.as_ptr() as *const core::ffi::c_void,
                );
                offset = safe_offset + len;
                // Null separator
                let sep_off = offset & MASK;
                if sep_off < MASK && sep_off <= OFFSET_LIMIT {
                    buf[sep_off] = 0;
                    offset = sep_off + 1;
                }
            }
            Err(_) => break,
        }
    }

    (offset & MASK) as u16
}

