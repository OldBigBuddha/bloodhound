use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use bloodhound_common::*;

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
