use aya_ebpf::helpers::bpf_probe_read_user_str_bytes;
use bloodhound_common::MAX_PATH_SIZE;

use crate::maps::{DROP_COUNT, EVENTS, SCRATCH_BUF};

/// Read a user-space string into the per-CPU scratch buffer at the given index.
/// Returns the number of bytes read (including null terminator), or 0 on failure.
#[inline(always)]
pub unsafe fn read_user_str(src: *const u8, scratch_idx: u32) -> u16 {
    let buf = match SCRATCH_BUF.get_ptr_mut(scratch_idx) {
        Some(b) => &mut (*b).buf,
        None => return 0,
    };

    match bpf_probe_read_user_str_bytes(src, buf) {
        Ok(s) => s.len() as u16,
        Err(_) => 0,
    }
}

/// Write raw bytes to the ring buffer using output().
/// This is the correct approach for variable-length data.
#[inline(always)]
pub unsafe fn emit_event(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    match EVENTS.output(data, 0) {
        Ok(()) => true,
        Err(_) => {
            increment_drop_count();
            false
        }
    }
}

/// Increment the per-CPU drop counter.
///
/// Uses `PerCpuArray<u64>` so each CPU writes to its own slot (no
/// cross-CPU race). Userspace reads all slots and sums them via the
/// drop-counter bridge (see `bloodhound::drop_counter`).
#[inline(always)]
pub unsafe fn increment_drop_count() {
    if let Some(ptr) = DROP_COUNT.get_ptr_mut(0) {
        *ptr = (*ptr).wrapping_add(1);
    }
}

/// Copy bytes between kernel memory regions using `bpf_probe_read_kernel` helper.
///
/// Unlike `core::ptr::copy_nonoverlapping`, this compiles to a single BPF helper
/// call instruction. `copy_nonoverlapping` with variable or large sizes gets
/// unrolled by LLVM into N individual load/store pairs, which can exceed the
/// BPF verifier's 1M instruction limit.
///
/// # BPF Verifier Constraint
///
/// Use this for any copy > ~64 bytes or any variable-length copy between map values.
/// Small fixed-size copies (e.g., `size_of::<EventHeader>()` = 48 bytes) can still
/// use `copy_nonoverlapping` safely.
#[inline(always)]
pub unsafe fn bpf_memcpy(dst: *mut u8, src: *const u8, len: u32) {
    let _ = aya_ebpf::helpers::gen::bpf_probe_read_kernel(
        dst as *mut core::ffi::c_void,
        len,
        src as *const core::ffi::c_void,
    );
}
