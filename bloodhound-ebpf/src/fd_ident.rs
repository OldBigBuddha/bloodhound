//! File-descriptor identity resolution for BPF rich extractors.
//!
//! Translates a process-local file descriptor into the underlying
//! `(dev, ino)` pair using the kernel fd-table traversal:
//!
//! ```text
//! task_struct → files_struct → fdtable → file → inode → super_block
//!                                              ↘
//!                                               i_ino (u64)
//!                                              i_sb → s_dev (u32)
//! ```
//!
//! # Verifier and CO-RE caveats
//!
//! The traversal uses several `bpf_probe_read_kernel` calls. Each is one
//! BPF helper invocation, which is much cheaper than an unrolled load loop
//! (verifier-friendly). All offsets come from `vmlinux.rs` and are
//! compile-time fixed to the target kernel; field reads that fail (wrong
//! offset, NULL pointer, fd out of range) return zero rather than aborting,
//! matching the userspace contract that "0 means unresolved".
//!
//! This module is shared by the `openat` (dev, ino) extension (issue #6)
//! and the file-backed `mmap` rich extractor (issue #10).

use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};

use crate::vmlinux::{fdtable, file, files_struct, inode, super_block, FILES_OFFSET_IN_TASK};

/// `(device, inode)` pair returned by [`fd_to_dev_ino`].
///
/// Both fields are zero when the fd does not resolve to a file-backed inode
/// (closed fd, anonymous mapping, or kernel struct layout mismatch).
#[derive(Clone, Copy, Default)]
pub struct DevIno {
    pub dev: u64,
    pub ino: u64,
}

/// Resolve a process-local fd to the underlying `(dev, ino)` pair.
///
/// Returns [`DevIno::default`] (both zero) on any failure: negative fd,
/// out-of-range fd, NULL pointer in the chain, or any read failure.
///
/// # Safety
///
/// Caller must be in a BPF program context where `bpf_get_current_task()`
/// returns a valid pointer. The returned `DevIno` carries no references.
#[inline(always)]
pub unsafe fn fd_to_dev_ino(fd: i32) -> DevIno {
    if fd < 0 {
        return DevIno::default();
    }

    let task_addr = bpf_get_current_task();
    if task_addr == 0 {
        return DevIno::default();
    }

    // task->files (raw pointer, read from a fixed offset to avoid
    // padding the entire `task_struct` for this single field).
    let files_pp = (task_addr as usize + FILES_OFFSET_IN_TASK) as *const *mut files_struct;
    let files = match bpf_probe_read_kernel(files_pp) {
        Ok(p) if !p.is_null() => p,
        _ => return DevIno::default(),
    };

    // files->fdt
    let fdt_p = core::ptr::addr_of!((*files).fdt);
    let fdt = match bpf_probe_read_kernel(fdt_p) {
        Ok(p) if !p.is_null() => p,
        _ => return DevIno::default(),
    };

    // fdt->max_fds — bound the fd index against the table.
    let max_fds_p = core::ptr::addr_of!((*fdt).max_fds);
    let max_fds = bpf_probe_read_kernel(max_fds_p).unwrap_or(0);
    if (fd as u32) >= max_fds {
        return DevIno::default();
    }

    // fdt->fd (struct file **)
    let fd_array_p = core::ptr::addr_of!((*fdt).fd);
    let fd_array = match bpf_probe_read_kernel(fd_array_p) {
        Ok(p) if !p.is_null() => p,
        _ => return DevIno::default(),
    };

    // fd_array[fd] — the struct file *
    let file_pp = fd_array.add(fd as usize) as *const *mut file;
    let f = match bpf_probe_read_kernel(file_pp) {
        Ok(p) if !p.is_null() => p,
        _ => return DevIno::default(),
    };

    // file->f_inode
    let inode_p = core::ptr::addr_of!((*f).f_inode);
    let i = match bpf_probe_read_kernel(inode_p) {
        Ok(p) if !p.is_null() => p,
        _ => return DevIno::default(),
    };

    // inode->i_ino
    let i_ino_p = core::ptr::addr_of!((*i).i_ino);
    let ino = bpf_probe_read_kernel(i_ino_p).unwrap_or(0);

    // inode->i_sb
    let sb_p = core::ptr::addr_of!((*i).i_sb);
    let sb = match bpf_probe_read_kernel(sb_p) {
        Ok(p) if !p.is_null() => p,
        _ => return DevIno { dev: 0, ino },
    };

    // super_block->s_dev (u32 encoded)
    let s_dev_p = core::ptr::addr_of!((*sb).s_dev);
    let dev = bpf_probe_read_kernel(s_dev_p).unwrap_or(0);

    DevIno {
        dev: dev as u64,
        ino,
    }
}

