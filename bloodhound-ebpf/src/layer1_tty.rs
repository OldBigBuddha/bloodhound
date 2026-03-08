use aya_ebpf::{
    helpers::bpf_probe_read_kernel_buf,
    macros::kprobe,
    programs::ProbeContext,
};
use bloodhound_common::*;

use crate::filter::{get_task_info, should_trace};
use crate::helpers::emit_event;
use crate::maps::{ASSEMBLY_BUF, SCRATCH_BUF};

// ── kprobe:pty_write ─────────────────────────────────────────────────────────

/// kprobe on `pty_write(struct tty_struct *tty, const u8 *buf, size_t count)`
///
/// # Why pty_write and not tty_write?
///
/// On kernel 6.8+, `tty_write` is the VFS `.write_iter` handler with signature
/// `(struct kiocb *iocb, struct iov_iter *from)`. The old `(tty_struct*, buf*, count)`
/// signature no longer applies. `pty_write` retains the original 3-arg signature
/// and is called for all PTY writes (which is what SSH sessions use).
///
/// # Why not share try_tty_capture with n_tty_read?
///
/// BPF verifier constraint: `ctx.arg(N)` compiles to reading the Nth register
/// from the ProbeContext at a fixed offset. The verifier requires this offset
/// to be a compile-time constant. Passing the arg index as a function parameter
/// causes LLVM to generate a variable ctx offset, which the verifier rejects:
///   `dereference of modified ctx ptr R1 off=<N> disallowed`
/// Therefore each kprobe must hardcode its own ctx.arg() calls.
#[kprobe]
pub fn tty_write_probe(ctx: ProbeContext) -> u32 {
    match unsafe { try_tty_write(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// TTY write capture: pty_write(tty*, buf*, count) → arg(1)=buf, arg(2)=count
unsafe fn try_tty_write(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // pty_write: arg0=tty_struct*, arg1=buf*, arg2=count
    let buf_ptr: *const u8 = ctx.arg(1).ok_or(-1i64)?;
    let count: usize = ctx.arg(2).ok_or(-1i64)?;

    emit_tty_event(EventKind::TtyWrite as u8, buf_ptr, count)
}

// ── kprobe:n_tty_read ────────────────────────────────────────────────────────

/// kprobe on `n_tty_read(struct tty_struct *tty, struct file *file,
///                        u8 *buf, size_t count, void **cookie, unsigned long offset)`
///
/// Same kernel 6.8+ caveat as pty_write: `tty_read` is now VFS `.read_iter`
/// with `(kiocb*, iov_iter*)`. `n_tty_read` is the N_TTY line discipline read
/// which retains the direct buffer interface.
///
/// Note: at kprobe entry, the user buffer has NOT been filled yet. This kprobe
/// captures the buffer pointer and size, but the actual data is only available
/// AFTER the function returns. For full data capture, a kretprobe would be
/// needed. Currently we capture the metadata (pid, comm, timestamp) and the
/// buffer address as a marker that a read occurred.
#[kprobe]
pub fn tty_read_probe(ctx: ProbeContext) -> u32 {
    match unsafe { try_tty_read(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// TTY read capture: n_tty_read(tty*, file*, buf*, count, ...) → arg(2)=buf, arg(3)=count
unsafe fn try_tty_read(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // n_tty_read: arg0=tty_struct*, arg1=file*, arg2=buf*, arg3=count
    let buf_ptr: *const u8 = ctx.arg(2).ok_or(-1i64)?;
    let count: usize = ctx.arg(3).ok_or(-1i64)?;

    emit_tty_event(EventKind::TtyRead as u8, buf_ptr, count)
}

// ── Shared event assembly ────────────────────────────────────────────────────

/// Assemble and emit a TTY event. Shared by write and read paths.
///
/// # Kernel vs User space buffer
///
/// `buf_ptr` is a **kernel-space** pointer in both `pty_write` and
/// `n_tty_read` contexts — the TTY layer allocates internal buffers for data
/// passing. We MUST use `bpf_probe_read_kernel_buf` (not `_user_buf`) or
/// the read will silently fail and return an error, causing no event emission.
/// This was a subtle bug: `bpf_probe_read_user_buf` returns -EFAULT on
/// kernel pointers but the BPF code treats any error as "skip this event",
/// so the failure was completely silent — kprobes fired, `should_trace()`
/// passed, but no events ever appeared in the output.
#[inline(always)]
unsafe fn emit_tty_event(kind: u8, buf_ptr: *const u8, count: usize) -> Result<u32, i64> {
    // Clamp to MAX_TTY_DATA - 1 to leave room for null terminator.
    // BPF verifier constraint: using MAX_TTY_DATA (not -1) would make the
    // buffer access exactly equal to map value_size, which the verifier
    // rejects for bpf_probe_read helpers.
    let data_len = count.min(MAX_TTY_DATA - 1);
    if data_len == 0 {
        return Ok(0);
    }

    // Read TTY data into scratch buffer 2
    let scratch = match SCRATCH_BUF.get_ptr_mut(2) {
        Some(s) => s,
        None => return Ok(0),
    };

    // BPF verifier constraint: slice upper bound must be < map value_size.
    // Using MAX_PATH_SIZE (4096) would be off + size == value_size, which
    // the verifier may reject depending on context. Using -1 ensures
    // off + size < value_size.
    let dest = &mut (&mut (*scratch).buf)[..data_len.min(MAX_PATH_SIZE - 1)];
    if bpf_probe_read_kernel_buf(buf_ptr, dest).is_err() {
        return Ok(0);
    }

    let header = get_task_info(kind);
    let payload = TtyPayload {
        data_len: data_len as u16,
        _pad: [0; 2],
    };

    // Assemble event in assembly buffer: header + payload + data
    let total_size = EventHeader::SIZE + TtyPayload::SIZE + data_len;
    let asm = match ASSEMBLY_BUF.get_ptr_mut(0) {
        Some(s) => s,
        None => return Ok(0),
    };
    let out = &mut (*asm).buf;
    if total_size > out.len() {
        return Ok(0);
    }

    core::ptr::copy_nonoverlapping(
        &header as *const EventHeader as *const u8,
        out.as_mut_ptr(),
        EventHeader::SIZE,
    );
    core::ptr::copy_nonoverlapping(
        &payload as *const TtyPayload as *const u8,
        out.as_mut_ptr().add(EventHeader::SIZE),
        TtyPayload::SIZE,
    );
    // NOTE: This copy_nonoverlapping is safe for the BPF verifier because
    // data_len ≤ MAX_TTY_DATA - 1 = 255, which is small enough that LLVM
    // unrolling to ~255 load/store pairs doesn't hit the 1M instruction limit.
    // For larger variable-length copies, use bpf_memcpy (helpers.rs) instead.
    core::ptr::copy_nonoverlapping(
        (*scratch).buf.as_ptr(),
        out.as_mut_ptr().add(EventHeader::SIZE + TtyPayload::SIZE),
        data_len,
    );

    emit_event(&out[..total_size]);
    Ok(0)
}
