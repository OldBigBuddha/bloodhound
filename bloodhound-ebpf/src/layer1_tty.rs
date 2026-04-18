use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
        bpf_probe_read_user_buf,
    },
    macros::{kprobe, kretprobe, map},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};
use bloodhound_common::*;

use crate::filter::{get_task_info, should_trace};
use crate::helpers::emit_event;
use crate::maps::{ASSEMBLY_BUF, SCRATCH_BUF};
use crate::vmlinux::{tty_driver, tty_struct, PTY_TYPE_SLAVE, TTY_DRIVER_TYPE_PTY};

// ── kprobe → kretprobe correlation map ───────────────────────────────────────

/// Per-task scratch for `n_tty_read` kprobe → kretprobe handoff.
///
/// At kprobe entry, the userspace destination buffer has not been
/// populated yet. We stash `(buf_ptr, count)` keyed by `pid_tgid`,
/// then look it up at kretprobe to read the actually-written bytes
/// (clamped by the return value).
///
/// Entries are removed on the kretprobe path; in the rare case the
/// kretprobe is not invoked (e.g., task exit during read), the entry
/// is overwritten on the next read by the same task. The 10240-entry
/// capacity (= `SYSCALL_ENTRY_MAP_SIZE`) is sufficient for any
/// realistic concurrent-task count.
#[repr(C)]
#[derive(Clone, Copy)]
struct TtyReadEntry {
    buf_ptr: u64,
    count: u64,
}

#[map]
static TTY_READ_ENTRY_MAP: HashMap<u64, TtyReadEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, 0);

// ── Pseudo-terminal device filter ────────────────────────────────────────────

/// Returns `true` when the given `tty_struct *` represents the slave end
/// of a pseudo-terminal pair (i.e. a `/dev/pts/N` device).
///
/// Per `docs/tracing.md` §Layer 1, only interactive SSH sessions (which
/// allocate a pts pair) are in scope. Physical console TTYs (`tty1`–`6`),
/// serial consoles, and other non-pty devices are deliberately excluded
/// in BPF so that no irrelevant traffic reaches userspace.
///
/// Returns `false` on any read failure or null `driver` pointer — the
/// safe direction is to drop the event when the device class cannot be
/// determined.
#[inline(always)]
unsafe fn is_pts_slave(tty: *const tty_struct) -> bool {
    if tty.is_null() {
        return false;
    }
    // Read tty->driver (a pointer to struct tty_driver).
    let driver_ptr_ptr = core::ptr::addr_of!((*tty).driver);
    let driver: *const tty_driver = match bpf_probe_read_kernel(driver_ptr_ptr) {
        Ok(d) => d,
        Err(_) => return false,
    };
    if driver.is_null() {
        return false;
    }

    // Read driver->type and driver->subtype.
    let type_ptr = core::ptr::addr_of!((*driver).r#type);
    let drv_type: i16 = match bpf_probe_read_kernel(type_ptr) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if drv_type != TTY_DRIVER_TYPE_PTY {
        return false;
    }

    let subtype_ptr = core::ptr::addr_of!((*driver).subtype);
    let drv_subtype: i16 = match bpf_probe_read_kernel(subtype_ptr) {
        Ok(s) => s,
        Err(_) => return false,
    };
    drv_subtype == PTY_TYPE_SLAVE
}

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
    let tty: *const tty_struct = ctx.arg(0).ok_or(-1i64)?;
    if !is_pts_slave(tty) {
        return Ok(0);
    }

    let buf_ptr: *const u8 = ctx.arg(1).ok_or(-1i64)?;
    let count: usize = ctx.arg(2).ok_or(-1i64)?;

    emit_tty_event(EventKind::TtyWrite as u8, buf_ptr, count, false)
}

// ── kprobe + kretprobe:n_tty_read ────────────────────────────────────────────

/// kprobe on `n_tty_read(struct tty_struct *tty, struct file *file,
///                        u8 *buf, size_t count, void **cookie, unsigned long offset)`
///
/// Same kernel 6.8+ caveat as pty_write: `tty_read` is now VFS `.read_iter`
/// with `(kiocb*, iov_iter*)`. `n_tty_read` is the N_TTY line discipline read
/// which retains the direct buffer interface.
///
/// # Two-stage capture (kprobe + kretprobe)
///
/// At function entry, the destination buffer has **not** been filled —
/// the kernel writes into it during execution. We therefore:
///
/// 1. (entry) Apply the auid + pts/* filter, then stash `(buf_ptr, count)`
///    in `TTY_READ_ENTRY_MAP` keyed by `pid_tgid`. No event is emitted.
/// 2. (return) Look up the stashed pointer, clamp `count` by the return
///    value (bytes actually read), and read+emit the data.
///
/// **Important:** On kernel 6.8+, the third argument to `n_tty_read` is
/// `unsigned char *kbuf` — a **kernel-space** buffer allocated by the
/// VFS layer. The VFS performs `copy_to_user` to the caller's userspace
/// buffer after `n_tty_read` returns. Therefore the kretprobe must use
/// `bpf_probe_read_kernel_buf`, not `_user_buf`. This is the symmetric
/// pitfall to the one documented on `emit_tty_event` for `pty_write`.
///
/// Closes the gap acknowledged in the previous implementation, which
/// captured only metadata. This is required by `docs/tracing.md` §Layer 1
/// for any DSL pattern that depends on what the user typed.
///
/// # Option chosen: kretprobe (Option A)
///
/// The issue suggested `fexit` (Option B) as preferred when supported.
/// We chose kretprobe because:
///   - Works on every kernel that supports kprobes (no BTF requirement
///     on the program type itself).
///   - Matches the existing kprobe-based attachment in this file with
///     no userspace changes besides linking the new program.
///   - Aya's `fexit` macro requires `function = "<name>"` BTF resolution
///     and the entry signature must be expressible as `FromBtfArgument`
///     types; `n_tty_read`'s 6-arg signature is awkward for this in the
///     current aya-ebpf 0.1.x line. kretprobe sidesteps that complexity.
///
/// Cost of kretprobe vs fexit: one extra map lookup/insert per read,
/// negligible at human typing rates.
#[kprobe]
pub fn tty_read_probe(ctx: ProbeContext) -> u32 {
    match unsafe { try_tty_read_entry(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// kprobe entry handler: filter + stash buffer pointer for the matching
/// kretprobe to consume.
unsafe fn try_tty_read_entry(ctx: &ProbeContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }

    // n_tty_read: arg0=tty_struct*, arg1=file*, arg2=buf*, arg3=count
    let tty: *const tty_struct = ctx.arg(0).ok_or(-1i64)?;
    if !is_pts_slave(tty) {
        return Ok(0);
    }

    let buf_ptr: *const u8 = ctx.arg(2).ok_or(-1i64)?;
    let count: usize = ctx.arg(3).ok_or(-1i64)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = TtyReadEntry {
        buf_ptr: buf_ptr as u64,
        count: count as u64,
    };
    let _ = TTY_READ_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

/// kretprobe on `n_tty_read`. Reads the bytes the kernel wrote into the
/// userspace buffer (clamped by the return value) and emits a `TtyRead`
/// event.
#[kretprobe]
pub fn tty_read_ret_probe(ctx: RetProbeContext) -> u32 {
    match unsafe { try_tty_read_ret(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_tty_read_ret(ctx: &RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // Pull and immediately remove the stashed entry. If absent, the entry
    // probe filtered this call (wrong auid or non-pts device) and there's
    // nothing to do.
    let entry = match TTY_READ_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };
    let _ = TTY_READ_ENTRY_MAP.remove(&pid_tgid);

    // n_tty_read returns ssize_t: bytes read on success, negative errno
    // on failure. Drop on failure / EOF.
    let ret: i64 = ctx.ret().unwrap_or(0);
    if ret <= 0 {
        return Ok(0);
    }

    let buf_ptr = entry.buf_ptr as *const u8;
    if buf_ptr.is_null() {
        return Ok(0);
    }

    // Clamp the actually-read length by the originally-requested count.
    let bytes_read = (ret as usize).min(entry.count as usize);
    emit_tty_event(EventKind::TtyRead as u8, buf_ptr, bytes_read, false)
}

// ── Shared event assembly ────────────────────────────────────────────────────

/// Assemble and emit a TTY event. Shared by write and read paths.
///
/// # Kernel vs User space buffer
///
/// Both `pty_write` and `n_tty_read` (kernel 6.8+) receive **kernel-space**
/// pointers — the TTY layer allocates internal buffers for data passing,
/// and the VFS does the `copy_to_user` / `copy_from_user` bookkeeping
/// outside of these functions. Picking the wrong helper silently fails:
/// `bpf_probe_read_user_buf` returns `-EFAULT` on kernel pointers, and
/// vice versa. Because we ignore the error and skip the event, the
/// failure is invisible — kprobes fire, `should_trace()` passes, but no
/// events ever appear in the output.
///
/// The `from_user` flag selects the helper, kept as a parameter to make
/// the choice explicit at each call site and guard against future hook
/// additions where a genuinely userspace buffer appears:
///   - `false` → `bpf_probe_read_kernel_buf` (used by both current paths)
///   - `true`  → `bpf_probe_read_user_buf`   (reserved for future hooks)
#[inline(always)]
unsafe fn emit_tty_event(
    kind: u8,
    buf_ptr: *const u8,
    count: usize,
    from_user: bool,
) -> Result<u32, i64> {
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
    let read_result = if from_user {
        bpf_probe_read_user_buf(buf_ptr, dest)
    } else {
        bpf_probe_read_kernel_buf(buf_ptr, dest)
    };
    if read_result.is_err() {
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
