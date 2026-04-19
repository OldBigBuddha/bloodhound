use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use bloodhound_common::*;

use crate::fd_ident::fd_to_dev_ino;
use crate::filter::{get_task_info, should_trace};
use crate::helpers::{emit_event, bpf_memcpy, increment_drop_count};
use crate::maps::{
    ASSEMBLY_BUF, RICH_ENTRY_MAP, SCRATCH_BUF, SOCKET_TABLE, SYSCALL_TMP_BUF, SocketInfo,
};

// ── Emit helpers ─────────────────────────────────────────────────────────────

/// Emit a fixed-size event (header + payload) to the ring buffer.
#[inline(always)]
unsafe fn emit_fixed<T: Sized>(header: &EventHeader, payload: &T) {
    let total = EventHeader::SIZE + core::mem::size_of::<T>();
    let mut buf = [0u8; 256];
    if total > buf.len() {
        return;
    }
    core::ptr::copy_nonoverlapping(
        header as *const EventHeader as *const u8,
        buf.as_mut_ptr(),
        EventHeader::SIZE,
    );
    core::ptr::copy_nonoverlapping(
        payload as *const T as *const u8,
        buf.as_mut_ptr().add(EventHeader::SIZE),
        core::mem::size_of::<T>(),
    );
    emit_event(&buf[..total]);
}

/// Emit event with variable-length data appended. Uses assembly buffer.
#[inline(always)]
unsafe fn emit_varlen<T: Sized>(header: &EventHeader, payload: &T, var_data: &[u8]) {
    let fixed = EventHeader::SIZE + core::mem::size_of::<T>();
    let total = fixed + var_data.len();
    let asm = match ASSEMBLY_BUF.get_ptr_mut(0) {
        Some(s) => s,
        None => return,
    };
    let buf = &mut (*asm).buf;
    if total > buf.len() {
        return;
    }
    core::ptr::copy_nonoverlapping(
        header as *const EventHeader as *const u8,
        buf.as_mut_ptr(),
        EventHeader::SIZE,
    );
    core::ptr::copy_nonoverlapping(
        payload as *const T as *const u8,
        buf.as_mut_ptr().add(EventHeader::SIZE),
        core::mem::size_of::<T>(),
    );
    if !var_data.is_empty() {
        // ⚠️  BPF verifier constraint: MUST use bpf_memcpy for variable-length copies.
        // copy_nonoverlapping with var_data.len() (up to 4095) gets unrolled by LLVM
        // into thousands of load/store pairs, exceeding the 1M instruction limit.
        bpf_memcpy(buf.as_mut_ptr().add(fixed), var_data.as_ptr(), var_data.len() as u32);
    }
    emit_event(&buf[..total]);
}

// ── Common tracepoint exit args ──────────────────────────────────────────────
// sys_exit tracepoints: offset 16 = return value (i64)

// ── openat ───────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct OpenatEntryData {
    flags: u32,
    mode: u32,
    filename_len: u16,
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_openat(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }
    // sys_enter_openat: offset 16=dfd, 24=filename, 32=flags, 40=mode
    let filename_ptr: u64 = ctx.read_at(24).map_err(|_| -1i64)?;
    let flags: u32 = ctx.read_at(32).map_err(|_| -1i64)?;
    let mode: u64 = ctx.read_at(40).unwrap_or(0);

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(EventKind::Openat as u8);

    let filename_len = if filename_ptr != 0 {
        let buf = match SCRATCH_BUF.get_ptr_mut(0) {
            Some(b) => &mut (*b).buf,
            None => return Ok(0),
        };
        match bpf_probe_read_user_str_bytes(filename_ptr as *const u8, buf) {
            Ok(s) => s.len() as u16,
            Err(_) => 0,
        }
    } else {
        0
    };

    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = OpenatEntryData {
        flags,
        mode: mode as u32,
        filename_len,
    };
    core::ptr::copy_nonoverlapping(
        &ed as *const _ as *const u8,
        entry.data.as_mut_ptr(),
        core::mem::size_of::<OpenatEntryData>().min(256),
    );
    entry.data_len = core::mem::size_of::<OpenatEntryData>() as u16;

    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_openat(&ctx) } {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

unsafe fn try_sys_exit_openat(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: OpenatEntryData =
        core::ptr::read_unaligned(entry.data.as_ptr() as *const OpenatEntryData);

    // Resolve (dev, ino) from the returned fd. Negative return ⇒ open failed,
    // skip the traversal and emit zeros (per issue #6 acceptance criteria).
    let dev_ino = if ret >= 0 {
        fd_to_dev_ino(ret as i32)
    } else {
        crate::fd_ident::DevIno::default()
    };

    let filename_len = (ed.filename_len as usize).min(MAX_PATH_SIZE - 1);

    // For successful opens, resolve the returned fd to a (dev, ino) pair so
    // downstream consumers can match on inode identity rather than path string
    // (issue #6). Zero values indicate unresolved/failed opens.
    let dev_ino = if ret >= 0 {
        crate::fd_ident::fd_to_dev_ino(ret as i32)
    } else {
        crate::fd_ident::DevIno::default()
    };

    let payload = OpenatPayload {
        flags: ed.flags,
        mode: ed.mode,
        filename_len: ed.filename_len,
        _pad: [0; 2],
        return_code: ret as i32,
        _pad2: [0; 4],
        dev: dev_ino.dev,
        ino: dev_ino.ino,
    };

    if filename_len > 0 {
        if let Some(scratch) = SCRATCH_BUF.get_ptr(0) {
            let data = &(&(*scratch).buf)[..filename_len];
            emit_varlen(&entry.header, &payload, data);
        } else {
            emit_fixed(&entry.header, &payload);
        }
    } else {
        emit_fixed(&entry.header, &payload);
    }

    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── read / write ─────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct ReadWriteEntryData {
    fd: u32,
    requested_size: u64,
    fd_type: u8,
}

#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_rw(&ctx, EventKind::Read as u8) } {
        Ok(_) => 0, Err(_) => 0,
    }
}
#[tracepoint]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_rw(&ctx) } {
        Ok(_) => 0, Err(_) => 0,
    }
}
#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_rw(&ctx, EventKind::Write as u8) } {
        Ok(_) => 0, Err(_) => 0,
    }
}
#[tracepoint]
pub fn sys_exit_write(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_rw(&ctx) } {
        Ok(_) => 0, Err(_) => 0,
    }
}

unsafe fn try_sys_enter_rw(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }
    // sys_enter_read/write: offset 16=fd, 24=buf, 32=count
    let fd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let count: u64 = ctx.read_at(32).unwrap_or(0);

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);

    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = ReadWriteEntryData {
        fd: fd as u32,
        requested_size: count,
        fd_type: FD_TYPE_OTHER,
    };
    core::ptr::copy_nonoverlapping(
        &ed as *const _ as *const u8,
        entry.data.as_mut_ptr(),
        core::mem::size_of::<ReadWriteEntryData>(),
    );
    entry.data_len = core::mem::size_of::<ReadWriteEntryData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_sys_exit_rw(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: ReadWriteEntryData =
        core::ptr::read_unaligned(entry.data.as_ptr() as *const ReadWriteEntryData);
    let payload = ReadWritePayload {
        fd: ed.fd,
        fd_type: ed.fd_type,
        _pad: [0; 3],
        requested_size: ed.requested_size,
        return_code: ret,
    };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── connect / bind ───────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnBindData {
    family: u16,
    port: u16,
    addr_v4: u32,
    addr_v6: [u8; 16],
}

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_sockaddr(&ctx, EventKind::Connect as u8) } {
        Ok(_) => 0, Err(_) => 0,
    }
}
#[tracepoint]
pub fn sys_exit_connect(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_sockaddr(&ctx) } {
        Ok(_) => 0, Err(_) => 0,
    }
}
#[tracepoint]
pub fn sys_enter_bind(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_sockaddr(&ctx, EventKind::Bind as u8) } {
        Ok(_) => 0, Err(_) => 0,
    }
}
#[tracepoint]
pub fn sys_exit_bind(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_sockaddr(&ctx) } {
        Ok(_) => 0, Err(_) => 0,
    }
}

unsafe fn try_sys_enter_sockaddr(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() {
        return Ok(0);
    }
    // connect/bind: offset 16=fd, 24=uservaddr, 32=addrlen
    let uservaddr: u64 = ctx.read_at(24).map_err(|_| -1i64)?;
    let addrlen: u64 = ctx.read_at(32).unwrap_or(0);

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);

    let mut family: u16 = 0;
    let mut port: u16 = 0;
    let mut addr_v4: u32 = 0;
    let mut addr_v6 = [0u8; 16];

    if uservaddr != 0 && addrlen >= 2 {
        if let Ok(f) = bpf_probe_read_user(uservaddr as *const u16) {
            family = f;
        }
        if family == 2 && addrlen >= 8 {
            // AF_INET
            if let Ok(p) = bpf_probe_read_user((uservaddr + 2) as *const u16) {
                port = u16::from_be(p);
            }
            if let Ok(a) = bpf_probe_read_user((uservaddr + 4) as *const u32) {
                addr_v4 = a;
            }
        } else if family == 10 && addrlen >= 28 {
            // AF_INET6
            if let Ok(p) = bpf_probe_read_user((uservaddr + 2) as *const u16) {
                port = u16::from_be(p);
            }
            for i in 0..16u64 {
                if let Ok(b) = bpf_probe_read_user((uservaddr + 8 + i) as *const u8) {
                    addr_v6[i as usize] = b;
                }
            }
        }
    }

    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = ConnBindData { family, port, addr_v4, addr_v6 };
    core::ptr::copy_nonoverlapping(
        &ed as *const _ as *const u8,
        entry.data.as_mut_ptr(),
        core::mem::size_of::<ConnBindData>(),
    );
    entry.data_len = core::mem::size_of::<ConnBindData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_sys_exit_sockaddr(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: ConnBindData =
        core::ptr::read_unaligned(entry.data.as_ptr() as *const ConnBindData);

    let payload = ConnectBindPayload {
        family: ed.family,
        port: ed.port,
        addr_v4: ed.addr_v4,
        addr_v6: ed.addr_v6,
        return_code: ret as i32,
    };
    emit_fixed(&entry.header, &payload);

    // Populate socket table for packet correlation
    if ret >= 0 {
        let socket_info = SocketInfo {
            pid: entry.header.pid,
            auid: entry.header.auid,
            comm: entry.header.comm,
        };
        let key = compute_socket_key(ed.family, ed.port, ed.addr_v4);
        let _ = SOCKET_TABLE.insert(&key, &socket_info, 0);
    }

    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

#[inline(always)]
fn compute_socket_key(family: u16, port: u16, addr_v4: u32) -> u64 {
    ((family as u64) << 48) | ((port as u64) << 32) | (addr_v4 as u64)
}

// ── listen ───────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct ListenData { fd: u32, backlog: u32 }

#[tracepoint]
pub fn sys_enter_listen(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_listen(&ctx) } { Ok(_) => 0, Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_listen(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_listen(&ctx) } { Ok(_) => 0, Err(_) => 0 }
}

unsafe fn try_enter_listen(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    let fd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let backlog: u64 = ctx.read_at(24).unwrap_or(0);
    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(EventKind::Listen as u8);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = ListenData { fd: fd as u32, backlog: backlog as u32 };
    core::ptr::copy_nonoverlapping(&ed as *const _ as *const u8, entry.data.as_mut_ptr(), core::mem::size_of::<ListenData>());
    entry.data_len = core::mem::size_of::<ListenData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_listen(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) { Some(e) => *e, None => return Ok(0) };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: ListenData = core::ptr::read_unaligned(entry.data.as_ptr() as *const ListenData);
    let payload = ListenPayload { fd: ed.fd, backlog: ed.backlog, return_code: ret as i32 };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── socket ───────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketData { domain: u32, sock_type: u32, protocol: u32 }

#[tracepoint]
pub fn sys_enter_socket(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_socket(&ctx) } { Ok(_) => 0, Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_socket(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_socket(&ctx) } { Ok(_) => 0, Err(_) => 0 }
}

unsafe fn try_enter_socket(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    let domain: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let stype: u64 = ctx.read_at(24).unwrap_or(0);
    let proto: u64 = ctx.read_at(32).unwrap_or(0);
    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(EventKind::Socket as u8);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = SocketData { domain: domain as u32, sock_type: stype as u32, protocol: proto as u32 };
    core::ptr::copy_nonoverlapping(&ed as *const _ as *const u8, entry.data.as_mut_ptr(), core::mem::size_of::<SocketData>());
    entry.data_len = core::mem::size_of::<SocketData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_socket(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) { Some(e) => *e, None => return Ok(0) };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: SocketData = core::ptr::read_unaligned(entry.data.as_ptr() as *const SocketData);
    let payload = SocketPayload { domain: ed.domain, sock_type: ed.sock_type, protocol: ed.protocol, return_code: ret as i32 };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── clone / clone3 ───────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct CloneData { flags: u64 }

#[tracepoint]
pub fn sys_enter_clone(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_clone(&ctx, EventKind::Clone as u8) } { Ok(_) => 0, Err(_) => 0 }
}
#[tracepoint]
pub fn sys_enter_clone3(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_clone(&ctx, EventKind::Clone3 as u8) } { Ok(_) => 0, Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_clone(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_clone(&ctx) } { Ok(_) => 0, Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_clone3(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_clone(&ctx) } { Ok(_) => 0, Err(_) => 0 }
}

unsafe fn try_enter_clone(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    let flags: u64 = ctx.read_at(16).unwrap_or(0);
    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = CloneData { flags };
    core::ptr::copy_nonoverlapping(&ed as *const _ as *const u8, entry.data.as_mut_ptr(), core::mem::size_of::<CloneData>());
    entry.data_len = core::mem::size_of::<CloneData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_clone(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) { Some(e) => *e, None => return Ok(0) };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: CloneData = core::ptr::read_unaligned(entry.data.as_ptr() as *const CloneData);
    let payload = ClonePayload { flags: ed.flags, return_code: ret };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── Generic path-based enter/exit ────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct PathData { path_len: u16 }

unsafe fn try_enter_path(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // First arg after syscall_nr is the path pointer (offset 16 or 24 for *at)
    let pathname: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let path_len = if pathname != 0 {
        let buf = match SCRATCH_BUF.get_ptr_mut(0) { Some(b) => &mut (*b).buf, None => return Ok(0) };
        match bpf_probe_read_user_str_bytes(pathname as *const u8, buf) { Ok(s) => s.len() as u16, Err(_) => 0 }
    } else { 0 };
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = PathData { path_len };
    core::ptr::copy_nonoverlapping(&ed as *const _ as *const u8, entry.data.as_mut_ptr(), core::mem::size_of::<PathData>());
    entry.data_len = core::mem::size_of::<PathData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_enter_at_path(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // *at variants: offset 16=dirfd, 24=pathname
    let pathname: u64 = ctx.read_at(24).map_err(|_| -1i64)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let path_len = if pathname != 0 {
        let buf = match SCRATCH_BUF.get_ptr_mut(0) { Some(b) => &mut (*b).buf, None => return Ok(0) };
        match bpf_probe_read_user_str_bytes(pathname as *const u8, buf) { Ok(s) => s.len() as u16, Err(_) => 0 }
    } else { 0 };
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = PathData { path_len };
    core::ptr::copy_nonoverlapping(&ed as *const _ as *const u8, entry.data.as_mut_ptr(), core::mem::size_of::<PathData>());
    entry.data_len = core::mem::size_of::<PathData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_path(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) { Some(e) => *e, None => return Ok(0) };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: PathData = core::ptr::read_unaligned(entry.data.as_ptr() as *const PathData);
    let path_len = (ed.path_len as usize).min(MAX_PATH_SIZE - 1);
    let payload = PathPayload { path_len: ed.path_len, _pad: [0; 2], return_code: ret as i32 };
    if path_len > 0 {
        if let Some(scratch) = SCRATCH_BUF.get_ptr(0) {
            emit_varlen(&entry.header, &payload, &(&(*scratch).buf)[..path_len]);
        } else {
            emit_fixed(&entry.header, &payload);
        }
    } else {
        emit_fixed(&entry.header, &payload);
    }
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── Generic fd-based enter/exit ──────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct FdData { fd: u32 }

unsafe fn try_enter_fd(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    let fd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = FdData { fd: fd as u32 };
    core::ptr::copy_nonoverlapping(&ed as *const _ as *const u8, entry.data.as_mut_ptr(), core::mem::size_of::<FdData>());
    entry.data_len = core::mem::size_of::<FdData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_fd(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) { Some(e) => *e, None => return Ok(0) };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: FdData = core::ptr::read_unaligned(entry.data.as_ptr() as *const FdData);
    let payload = FdPayload { fd: ed.fd, return_code: ret as i32 };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── Generic two-path enter/exit ──────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct TwoPathData { path1_len: u16, path2_len: u16 }

unsafe fn try_enter_two_path(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    let path1_ptr: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let path2_ptr: u64 = ctx.read_at(24).unwrap_or(0);
    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let path1_len = if path1_ptr != 0 {
        let buf = match SCRATCH_BUF.get_ptr_mut(0) { Some(b) => &mut (*b).buf, None => return Ok(0) };
        match bpf_probe_read_user_str_bytes(path1_ptr as *const u8, buf) { Ok(s) => s.len() as u16, Err(_) => 0 }
    } else { 0 };
    let path2_len = if path2_ptr != 0 {
        let buf = match SCRATCH_BUF.get_ptr_mut(1) { Some(b) => &mut (*b).buf, None => return Ok(0) };
        match bpf_probe_read_user_str_bytes(path2_ptr as *const u8, buf) { Ok(s) => s.len() as u16, Err(_) => 0 }
    } else { 0 };
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = TwoPathData { path1_len, path2_len };
    core::ptr::copy_nonoverlapping(&ed as *const _ as *const u8, entry.data.as_mut_ptr(), core::mem::size_of::<TwoPathData>());
    entry.data_len = core::mem::size_of::<TwoPathData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_two_path(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) { Some(e) => *e, None => return Ok(0) };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: TwoPathData = core::ptr::read_unaligned(entry.data.as_ptr() as *const TwoPathData);
    let payload = TwoPathPayload { path1_len: ed.path1_len, path2_len: ed.path2_len, return_code: ret as i32 };
    let p1 = (ed.path1_len as usize).min(MAX_PATH_SIZE - 1);
    let p2 = (ed.path2_len as usize).min(MAX_PATH_SIZE - 1);
    if p1 + p2 == 0 {
        emit_fixed(&entry.header, &payload);
    } else {
        // Assemble var data in assembly buffer
        let asm = match ASSEMBLY_BUF.get_ptr_mut(0) { Some(s) => s, None => { emit_fixed(&entry.header, &payload); let _ = RICH_ENTRY_MAP.remove(&pid_tgid); return Ok(0); } };
        let dst = &mut (*asm).buf;
        let mut offset = 0;
        if p1 > 0 {
            if let Some(s0) = SCRATCH_BUF.get_ptr(0) {
                // ⚠️  BPF verifier constraint: bpf_memcpy required (p1 up to 4095 bytes)
                bpf_memcpy(dst.as_mut_ptr().add(offset), (*s0).buf.as_ptr(), p1 as u32);
                offset += p1;
            }
        }
        if p2 > 0 {
            if let Some(s1) = SCRATCH_BUF.get_ptr(1) {
                // ⚠️  BPF verifier constraint: bpf_memcpy required (p2 up to 4095 bytes)
                bpf_memcpy(dst.as_mut_ptr().add(offset), (*s1).buf.as_ptr(), p2 as u32);
                offset += p2;
            }
        }
        emit_varlen(&entry.header, &payload, &dst[..offset]);
    }
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── sendto / recvfrom ────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct SendRecvData { fd: u32, family: u16, port: u16, addr_v4: u32, addr_v6: [u8; 16], size: u64 }

unsafe fn try_enter_sendto_recvfrom(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // sendto: offset 16=fd, 24=buf, 32=len, 40=flags, 48=addr, 56=addrlen
    let fd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let len: u64 = ctx.read_at(32).unwrap_or(0);
    let addr: u64 = ctx.read_at(48).unwrap_or(0);
    let addrlen: u64 = ctx.read_at(56).unwrap_or(0);

    let mut family: u16 = 0; let mut port: u16 = 0; let mut addr_v4: u32 = 0; let mut addr_v6 = [0u8; 16];
    if addr != 0 && addrlen >= 2 {
        if let Ok(f) = bpf_probe_read_user(addr as *const u16) { family = f; }
        if family == 2 && addrlen >= 8 {
            if let Ok(p) = bpf_probe_read_user((addr + 2) as *const u16) { port = u16::from_be(p); }
            if let Ok(a) = bpf_probe_read_user((addr + 4) as *const u32) { addr_v4 = a; }
        } else if family == 10 && addrlen >= 28 {
            if let Ok(p) = bpf_probe_read_user((addr + 2) as *const u16) { port = u16::from_be(p); }
            for i in 0..16u64 { if let Ok(b) = bpf_probe_read_user((addr + 8 + i) as *const u8) { addr_v6[i as usize] = b; } }
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = SendRecvData { fd: fd as u32, family, port, addr_v4, addr_v6, size: len };
    core::ptr::copy_nonoverlapping(&ed as *const _ as *const u8, entry.data.as_mut_ptr(), core::mem::size_of::<SendRecvData>());
    entry.data_len = core::mem::size_of::<SendRecvData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_sendto_recvfrom(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) { Some(e) => *e, None => return Ok(0) };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: SendRecvData = core::ptr::read_unaligned(entry.data.as_ptr() as *const SendRecvData);
    let payload = SendtoRecvfromPayload { fd: ed.fd, family: ed.family, port: ed.port, addr_v4: ed.addr_v4, addr_v6: ed.addr_v6, size: ed.size, return_code: ret };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── All tracepoint entry points (path / fd / two-path / sendto-recvfrom) ─────

#[tracepoint] pub fn sys_enter_chdir(c: TracePointContext) -> u32 { match unsafe { try_enter_path(&c, EventKind::Chdir as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_chdir(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_fchdir(c: TracePointContext) -> u32 { match unsafe { try_enter_fd(&c, EventKind::Fchdir as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_fchdir(c: TracePointContext) -> u32 { match unsafe { try_exit_fd(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_unlink(c: TracePointContext) -> u32 { match unsafe { try_enter_path(&c, EventKind::Unlink as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_unlink(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_unlinkat(c: TracePointContext) -> u32 { match unsafe { try_enter_at_path(&c, EventKind::Unlinkat as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_unlinkat(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_rmdir(c: TracePointContext) -> u32 { match unsafe { try_enter_path(&c, EventKind::Rmdir as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_rmdir(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_mkdir(c: TracePointContext) -> u32 { match unsafe { try_enter_path(&c, EventKind::Mkdir as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_mkdir(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_mkdirat(c: TracePointContext) -> u32 { match unsafe { try_enter_at_path(&c, EventKind::Mkdirat as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_mkdirat(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_symlink(c: TracePointContext) -> u32 { match unsafe { try_enter_two_path(&c, EventKind::Symlink as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_symlink(c: TracePointContext) -> u32 { match unsafe { try_exit_two_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_symlinkat(c: TracePointContext) -> u32 { match unsafe { try_enter_two_path(&c, EventKind::Symlinkat as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_symlinkat(c: TracePointContext) -> u32 { match unsafe { try_exit_two_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_link(c: TracePointContext) -> u32 { match unsafe { try_enter_two_path(&c, EventKind::Link as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_link(c: TracePointContext) -> u32 { match unsafe { try_exit_two_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_linkat(c: TracePointContext) -> u32 { match unsafe { try_enter_two_path(&c, EventKind::Linkat as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_linkat(c: TracePointContext) -> u32 { match unsafe { try_exit_two_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_rename(c: TracePointContext) -> u32 { match unsafe { try_enter_two_path(&c, EventKind::Rename as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_rename(c: TracePointContext) -> u32 { match unsafe { try_exit_two_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_renameat2(c: TracePointContext) -> u32 { match unsafe { try_enter_two_path(&c, EventKind::Renameat2 as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_renameat2(c: TracePointContext) -> u32 { match unsafe { try_exit_two_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_chmod(c: TracePointContext) -> u32 { match unsafe { try_enter_path(&c, EventKind::Chmod as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_chmod(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_fchmod(c: TracePointContext) -> u32 { match unsafe { try_enter_fd(&c, EventKind::Fchmod as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_fchmod(c: TracePointContext) -> u32 { match unsafe { try_exit_fd(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_fchmodat(c: TracePointContext) -> u32 { match unsafe { try_enter_at_path(&c, EventKind::Fchmodat as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_fchmodat(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_chown(c: TracePointContext) -> u32 { match unsafe { try_enter_path(&c, EventKind::Chown as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_chown(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_fchown(c: TracePointContext) -> u32 { match unsafe { try_enter_fd(&c, EventKind::Fchown as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_fchown(c: TracePointContext) -> u32 { match unsafe { try_exit_fd(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_fchownat(c: TracePointContext) -> u32 { match unsafe { try_enter_at_path(&c, EventKind::Fchownat as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_fchownat(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_truncate(c: TracePointContext) -> u32 { match unsafe { try_enter_path(&c, EventKind::Truncate as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_truncate(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_ftruncate(c: TracePointContext) -> u32 { match unsafe { try_enter_fd(&c, EventKind::Ftruncate as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_ftruncate(c: TracePointContext) -> u32 { match unsafe { try_exit_fd(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_mount(c: TracePointContext) -> u32 { match unsafe { try_enter_two_path(&c, EventKind::Mount as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_mount(c: TracePointContext) -> u32 { match unsafe { try_exit_two_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_umount2(c: TracePointContext) -> u32 { match unsafe { try_enter_path(&c, EventKind::Umount2 as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_umount2(c: TracePointContext) -> u32 { match unsafe { try_exit_path(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_sendto(c: TracePointContext) -> u32 { match unsafe { try_enter_sendto_recvfrom(&c, EventKind::Sendto as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_sendto(c: TracePointContext) -> u32 { match unsafe { try_exit_sendto_recvfrom(&c) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_enter_recvfrom(c: TracePointContext) -> u32 { match unsafe { try_enter_sendto_recvfrom(&c, EventKind::Recvfrom as u8) } { Ok(_)|Err(_) => 0 } }
#[tracepoint] pub fn sys_exit_recvfrom(c: TracePointContext) -> u32 { match unsafe { try_exit_sendto_recvfrom(&c) } { Ok(_)|Err(_) => 0 } }

// ── dup / dup2 / dup3 / fcntl(F_DUPFD*) — issue #5 ───────────────────────────
//
// The four syscalls share a payload (`oldfd`, `newfd`, `cloexec`).
// `oldfd` and `cloexec` are known at enter; `newfd` comes from the exit
// return value. `fcntl` is gated on `cmd ∈ {F_DUPFD, F_DUPFD_CLOEXEC}`;
// other commands are not stashed and fall through to Tier 1 raw capture.

#[repr(C)]
#[derive(Clone, Copy)]
struct DupEntryData {
    oldfd: u32,
    cloexec: u8,
    _pad: [u8; 3],
}

#[tracepoint]
pub fn sys_enter_dup(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_dup_family(&ctx, EventKind::Dup as u8, 0) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_dup(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_dup_family(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_enter_dup2(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_dup_family(&ctx, EventKind::Dup2 as u8, 0) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_dup2(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_dup_family(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_enter_dup3(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_dup3(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_dup3(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_dup_family(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_enter_fcntl(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_fcntl(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_fcntl(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_dup_family(&ctx) } { Ok(_)|Err(_) => 0 }
}

unsafe fn try_enter_dup_family(
    ctx: &TracePointContext,
    kind: u8,
    cloexec: u8,
) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    let oldfd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    stash_dup_entry(kind, oldfd as u32, cloexec)
}

unsafe fn try_enter_dup3(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // dup3: offset 16=oldfd, 24=newfd, 32=flags
    let oldfd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let flags: u64 = ctx.read_at(32).unwrap_or(0);
    let cloexec = if (flags as u32) & O_CLOEXEC != 0 { 1u8 } else { 0u8 };
    stash_dup_entry(EventKind::Dup3 as u8, oldfd as u32, cloexec)
}

unsafe fn try_enter_fcntl(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // fcntl: offset 16=fd, 24=cmd, 32=arg
    let fd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let cmd: u64 = ctx.read_at(24).unwrap_or(0);
    let cmd32 = cmd as u32;
    // Only rich-extract the F_DUPFD family. All other fcntl commands fall
    // through to Tier 1 raw capture (the Tier 2 bitmap entry for fcntl is
    // intentionally not set, so raw capture still emits the event).
    if cmd32 != F_DUPFD && cmd32 != F_DUPFD_CLOEXEC {
        return Ok(0);
    }
    let cloexec = if cmd32 == F_DUPFD_CLOEXEC { 1u8 } else { 0u8 };
    stash_dup_entry(EventKind::Fcntl as u8, fd as u32, cloexec)
}

#[inline(always)]
unsafe fn stash_dup_entry(kind: u8, oldfd: u32, cloexec: u8) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = DupEntryData { oldfd, cloexec, _pad: [0; 3] };
    core::ptr::copy_nonoverlapping(
        &ed as *const _ as *const u8,
        entry.data.as_mut_ptr(),
        core::mem::size_of::<DupEntryData>(),
    );
    entry.data_len = core::mem::size_of::<DupEntryData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_dup_family(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: DupEntryData =
        core::ptr::read_unaligned(entry.data.as_ptr() as *const DupEntryData);
    let payload = DupPayload {
        oldfd: ed.oldfd,
        newfd: ret as i32,
        cloexec: ed.cloexec,
        _pad: [0; 3],
        return_code: ret,
    };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── pread64 / pwrite64 — issue #7 ────────────────────────────────────────────
//
// Mirrors the read/write rich extractor with an additional `offset` argument.

#[repr(C)]
#[derive(Clone, Copy)]
struct PreadPwriteEntryData {
    fd: u32,
    requested_size: u64,
    offset: i64,
    fd_type: u8,
}

#[tracepoint]
pub fn sys_enter_pread64(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_prw(&ctx, EventKind::Pread64 as u8) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_pread64(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_prw(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_enter_pwrite64(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_prw(&ctx, EventKind::Pwrite64 as u8) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_pwrite64(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_prw(&ctx) } { Ok(_)|Err(_) => 0 }
}

unsafe fn try_enter_prw(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // pread64/pwrite64: offset 16=fd, 24=buf, 32=count, 40=pos
    let fd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let count: u64 = ctx.read_at(32).unwrap_or(0);
    let pos: u64 = ctx.read_at(40).unwrap_or(0);

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = PreadPwriteEntryData {
        fd: fd as u32,
        requested_size: count,
        offset: pos as i64,
        fd_type: FD_TYPE_OTHER,
    };
    core::ptr::copy_nonoverlapping(
        &ed as *const _ as *const u8,
        entry.data.as_mut_ptr(),
        core::mem::size_of::<PreadPwriteEntryData>(),
    );
    entry.data_len = core::mem::size_of::<PreadPwriteEntryData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_prw(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: PreadPwriteEntryData =
        core::ptr::read_unaligned(entry.data.as_ptr() as *const PreadPwriteEntryData);
    let payload = PreadPwritePayload {
        fd: ed.fd,
        fd_type: ed.fd_type,
        _pad: [0; 3],
        requested_size: ed.requested_size,
        offset: ed.offset,
        return_code: ret,
    };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── readv / writev — issue #8 ────────────────────────────────────────────────
//
// Bounded iov traversal: sums `iov_len` across the first MAX_IOV_TRAVERSE
// entries to produce a "total requested" approximation. Beyond the cap,
// the `iov_truncated` flag tells consumers the size is a lower bound.
//
// **Verifier note**: the loop is unrolled to a fixed bound (8) precisely
// because BPF rejects unbounded iteration. Each iteration costs one
// `bpf_probe_read_user`.

/// Layout of `struct iovec` in user memory: { void *iov_base; size_t iov_len; }
#[repr(C)]
#[derive(Clone, Copy)]
struct UserIovec {
    iov_base: u64,
    iov_len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ReadvWritevEntryData {
    fd: u32,
    iov_count: u32,
    iov_truncated: u8,
    _pad: [u8; 3],
    requested_size: u64,
    fd_type: u8,
}

#[tracepoint]
pub fn sys_enter_readv(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_rwv(&ctx, EventKind::Readv as u8) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_readv(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_rwv(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_enter_writev(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_rwv(&ctx, EventKind::Writev as u8) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_writev(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_rwv(&ctx) } { Ok(_)|Err(_) => 0 }
}

unsafe fn try_enter_rwv(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // readv/writev: offset 16=fd, 24=iov, 32=iovcnt
    let fd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let iov_ptr: u64 = ctx.read_at(24).unwrap_or(0);
    let iovcnt: u64 = ctx.read_at(32).unwrap_or(0);

    let mut total: u64 = 0;
    let traverse = if iovcnt > MAX_IOV_TRAVERSE as u64 {
        MAX_IOV_TRAVERSE
    } else {
        iovcnt as u32
    };
    let truncated = if iovcnt > MAX_IOV_TRAVERSE as u64 { 1u8 } else { 0u8 };

    if iov_ptr != 0 {
        // Fully unrolled, fixed-bound loop. The verifier needs the upper
        // bound to be a compile-time constant; `MAX_IOV_TRAVERSE = 8` is
        // small enough to keep instruction count comfortably below 1 M.
        let stride = core::mem::size_of::<UserIovec>() as u64;
        let mut i: u32 = 0;
        while i < MAX_IOV_TRAVERSE {
            if i >= traverse {
                break;
            }
            let entry_addr = iov_ptr + (i as u64) * stride;
            if let Ok(iov) = bpf_probe_read_user(entry_addr as *const UserIovec) {
                total = total.wrapping_add(iov.iov_len);
            }
            i += 1;
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = ReadvWritevEntryData {
        fd: fd as u32,
        iov_count: iovcnt as u32,
        iov_truncated: truncated,
        _pad: [0; 3],
        requested_size: total,
        fd_type: FD_TYPE_OTHER,
    };
    core::ptr::copy_nonoverlapping(
        &ed as *const _ as *const u8,
        entry.data.as_mut_ptr(),
        core::mem::size_of::<ReadvWritevEntryData>(),
    );
    entry.data_len = core::mem::size_of::<ReadvWritevEntryData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_rwv(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: ReadvWritevEntryData =
        core::ptr::read_unaligned(entry.data.as_ptr() as *const ReadvWritevEntryData);
    let payload = ReadvWritevPayload {
        fd: ed.fd,
        fd_type: ed.fd_type,
        iov_truncated: ed.iov_truncated,
        _pad: [0; 2],
        iov_count: ed.iov_count,
        _pad2: [0; 4],
        requested_size: ed.requested_size,
        return_code: ret,
    };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── mmap (file-backed) — issue #10 ───────────────────────────────────────────
//
// Anonymous mappings (MAP_ANONYMOUS or fd == -1) are filtered at enter
// before any expensive work, so they do not consume a ring buffer slot.
// File-backed mappings carry the (dev, ino) of the underlying file via
// the same fd_ident traversal used by openat (issue #6).

#[repr(C)]
#[derive(Clone, Copy)]
struct MmapEntryData {
    fd: i32,
    prot: u32,
    flags: u32,
    length: u64,
    offset: u64,
}

#[tracepoint]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_mmap(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_mmap(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_mmap(&ctx) } { Ok(_)|Err(_) => 0 }
}

unsafe fn try_enter_mmap(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // mmap: offset 16=addr, 24=length, 32=prot, 40=flags, 48=fd, 56=offset
    let length: u64 = ctx.read_at(24).unwrap_or(0);
    let prot: u64 = ctx.read_at(32).unwrap_or(0);
    let flags: u64 = ctx.read_at(40).unwrap_or(0);
    let fd_raw: i64 = ctx.read_at(48).unwrap_or(-1);
    let offset: u64 = ctx.read_at(56).unwrap_or(0);

    // Cheap filter: skip anonymous mappings and fd == -1. The dominant
    // mmap caller (malloc-class allocations) takes this path, keeping the
    // ring-buffer cost bounded.
    if fd_raw < 0 || (flags as u32) & MAP_ANONYMOUS != 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(EventKind::Mmap as u8);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = MmapEntryData {
        fd: fd_raw as i32,
        prot: prot as u32,
        flags: flags as u32,
        length,
        offset,
    };
    core::ptr::copy_nonoverlapping(
        &ed as *const _ as *const u8,
        entry.data.as_mut_ptr(),
        core::mem::size_of::<MmapEntryData>(),
    );
    entry.data_len = core::mem::size_of::<MmapEntryData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_mmap(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: MmapEntryData =
        core::ptr::read_unaligned(entry.data.as_ptr() as *const MmapEntryData);

    // Resolve (dev, ino) from the fd captured at enter. Use the enter-time
    // fd because the syscall return value is the mapped address, not an fd.
    let dev_ino = fd_to_dev_ino(ed.fd);

    let payload = MmapPayload {
        fd: ed.fd,
        prot: ed.prot,
        flags: ed.flags,
        _pad: [0; 4],
        length: ed.length,
        offset: ed.offset,
        dev: dev_ino.dev,
        ino: dev_ino.ino,
        return_code: ret,
    };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}

// ── sendfile / splice (opt-in) — issue #9 ────────────────────────────────────
//
// These two syscalls move data between two fds. Rich extraction is gated
// on a userspace flag (`--enable-rich-sendfile`); when the flag is not
// set, the userspace loader does not attach these tracepoints and does
// not register them in `TIER2_BITMAP`, so Tier 1 raw capture continues
// to surface them. The BPF programs themselves are always compiled in.

#[repr(C)]
#[derive(Clone, Copy)]
struct SendfileSpliceEntryData {
    in_fd: u32,
    out_fd: u32,
    in_fd_type: u8,
    out_fd_type: u8,
    _pad: [u8; 2],
    size: u64,
}

#[tracepoint]
pub fn sys_enter_sendfile(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_sendfile(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_sendfile(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_sendfile_splice(&ctx, EventKind::Sendfile as u8) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_enter_splice(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_splice(&ctx) } { Ok(_)|Err(_) => 0 }
}
#[tracepoint]
pub fn sys_exit_splice(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_sendfile_splice(&ctx, EventKind::Splice as u8) } { Ok(_)|Err(_) => 0 }
}

unsafe fn try_enter_sendfile(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // sendfile: offset 16=out_fd, 24=in_fd, 32=offset(*), 40=count
    let out_fd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let in_fd: u64 = ctx.read_at(24).unwrap_or(0);
    let count: u64 = ctx.read_at(40).unwrap_or(0);
    stash_sendfile_splice_entry(EventKind::Sendfile as u8, in_fd as u32, out_fd as u32, count)
}

unsafe fn try_enter_splice(ctx: &TracePointContext) -> Result<u32, i64> {
    if !should_trace() { return Ok(0); }
    // splice: offset 16=fd_in, 24=off_in*, 32=fd_out, 40=off_out*, 48=len, 56=flags
    let in_fd: u64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let out_fd: u64 = ctx.read_at(32).unwrap_or(0);
    let len: u64 = ctx.read_at(48).unwrap_or(0);
    stash_sendfile_splice_entry(EventKind::Splice as u8, in_fd as u32, out_fd as u32, len)
}

#[inline(always)]
unsafe fn stash_sendfile_splice_entry(
    kind: u8,
    in_fd: u32,
    out_fd: u32,
    size: u64,
) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let header = get_task_info(kind);
    let entry_ptr = match SYSCALL_TMP_BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return Ok(0),
    };
    let entry = unsafe { &mut *entry_ptr };
    entry.data_len = 0;
    entry.header = header;
    let ed = SendfileSpliceEntryData {
        in_fd,
        out_fd,
        in_fd_type: FD_TYPE_OTHER,
        out_fd_type: FD_TYPE_OTHER,
        _pad: [0; 2],
        size,
    };
    core::ptr::copy_nonoverlapping(
        &ed as *const _ as *const u8,
        entry.data.as_mut_ptr(),
        core::mem::size_of::<SendfileSpliceEntryData>(),
    );
    entry.data_len = core::mem::size_of::<SendfileSpliceEntryData>() as u16;
    let _ = RICH_ENTRY_MAP.insert(&pid_tgid, &entry, 0);
    Ok(0)
}

unsafe fn try_exit_sendfile_splice(ctx: &TracePointContext, _kind: u8) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let entry = match RICH_ENTRY_MAP.get(&pid_tgid) {
        Some(e) => *e,
        None => return Ok(0),
    };
    let ret: i64 = ctx.read_at(16).map_err(|_| -1i64)?;
    let ed: SendfileSpliceEntryData =
        core::ptr::read_unaligned(entry.data.as_ptr() as *const SendfileSpliceEntryData);
    let payload = SendfileSplicePayload {
        in_fd: ed.in_fd,
        out_fd: ed.out_fd,
        in_fd_type: ed.in_fd_type,
        out_fd_type: ed.out_fd_type,
        _pad: [0; 6],
        size: ed.size,
        return_code: ret,
    };
    emit_fixed(&entry.header, &payload);
    let _ = RICH_ENTRY_MAP.remove(&pid_tgid);
    Ok(0)
}
