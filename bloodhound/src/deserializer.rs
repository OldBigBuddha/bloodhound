use anyhow::{bail, Result};
use serde::Serialize;

use bloodhound_common::*;

/// Deserialized BehaviorEvent ready for JSON serialization.
#[derive(Debug, Serialize)]
pub struct BehaviorEvent {
    pub header: EventHeaderJson,
    pub event: EventTypeJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proc: Option<ProcInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_code: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct EventHeaderJson {
    pub timestamp: f64,
    pub auid: u32,
    pub sessionid: u32,
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub comm: String,
}

#[derive(Debug, Serialize)]
pub struct EventTypeJson {
    #[serde(rename = "type")]
    pub event_type: String,
    pub name: String,
    pub layer: String,
}

#[derive(Debug, Serialize)]
pub struct ProcInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
}

/// Parse raw ring buffer bytes into a BehaviorEvent.
pub fn deserialize(data: &[u8]) -> Result<BehaviorEvent> {
    if data.len() < 1 {
        bail!("Event data too short");
    }

    let kind_byte = data[0];
    let kind = EventKind::from_u8(kind_byte);

    match kind {
        Some(EventKind::PacketIngress) | Some(EventKind::PacketEgress) => {
            deserialize_packet(data)
        }
        Some(k) => deserialize_process_event(data, k),
        None => bail!("Unknown event kind: {}", kind_byte),
    }
}

fn deserialize_process_event(data: &[u8], kind: EventKind) -> Result<BehaviorEvent> {
    if data.len() < EventHeader::SIZE {
        bail!("Event data too short for header");
    }

    let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const EventHeader) };
    let payload = &data[EventHeader::SIZE..];

    let header_json = EventHeaderJson {
        timestamp: header.timestamp_ns as f64 / 1_000_000_000.0,
        auid: header.auid,
        sessionid: header.sessionid,
        pid: header.pid,
        ppid: if header.ppid != 0 { Some(header.ppid) } else { None },
        comm: comm_to_string(&header.comm),
    };

    let (event_type, name, layer, args, return_code) = match kind {
        EventKind::TtyRead => parse_tty(payload, "tty_read")?,
        EventKind::TtyWrite => parse_tty(payload, "tty_write")?,
        EventKind::Execve => parse_execve(payload, "execve")?,
        EventKind::Execveat => parse_execve(payload, "execveat")?,
        EventKind::RawSyscall => parse_raw_syscall(payload)?,
        EventKind::Openat => parse_openat(payload)?,
        EventKind::Read => parse_read_write(payload, "read")?,
        EventKind::Write => parse_read_write(payload, "write")?,
        EventKind::Connect => parse_connect_bind(payload, "connect")?,
        EventKind::Bind => parse_connect_bind(payload, "bind")?,
        EventKind::Listen => parse_listen(payload)?,
        EventKind::Socket => parse_socket(payload)?,
        EventKind::Clone => parse_clone(payload, "clone")?,
        EventKind::Clone3 => parse_clone(payload, "clone3")?,
        EventKind::Chdir => parse_path_event(payload, "chdir")?,
        EventKind::Fchdir => parse_fd_event(payload, "fchdir")?,
        EventKind::Unlink => parse_path_event(payload, "unlink")?,
        EventKind::Unlinkat => parse_path_event(payload, "unlinkat")?,
        EventKind::Rename => parse_two_path_event(payload, "rename")?,
        EventKind::Renameat2 => parse_two_path_event(payload, "renameat2")?,
        EventKind::Mkdir => parse_path_event(payload, "mkdir")?,
        EventKind::Mkdirat => parse_path_event(payload, "mkdirat")?,
        EventKind::Rmdir => parse_path_event(payload, "rmdir")?,
        EventKind::Symlink => parse_two_path_event(payload, "symlink")?,
        EventKind::Symlinkat => parse_two_path_event(payload, "symlinkat")?,
        EventKind::Link => parse_two_path_event(payload, "link")?,
        EventKind::Linkat => parse_two_path_event(payload, "linkat")?,
        EventKind::Chmod => parse_path_event(payload, "chmod")?,
        EventKind::Fchmod => parse_fd_event(payload, "fchmod")?,
        EventKind::Fchmodat => parse_path_event(payload, "fchmodat")?,
        EventKind::Chown => parse_path_event(payload, "chown")?,
        EventKind::Fchown => parse_fd_event(payload, "fchown")?,
        EventKind::Fchownat => parse_path_event(payload, "fchownat")?,
        EventKind::Truncate => parse_path_event(payload, "truncate")?,
        EventKind::Ftruncate => parse_fd_event(payload, "ftruncate")?,
        EventKind::Mount => parse_two_path_event(payload, "mount")?,
        EventKind::Umount2 => parse_path_event(payload, "umount2")?,
        EventKind::Sendto => parse_sendto_recvfrom(payload, "sendto")?,
        EventKind::Recvfrom => parse_sendto_recvfrom(payload, "recvfrom")?,
        EventKind::Dup => parse_dup(payload, "dup")?,
        EventKind::Dup2 => parse_dup(payload, "dup2")?,
        EventKind::Dup3 => parse_dup(payload, "dup3")?,
        EventKind::Fcntl => parse_dup(payload, "fcntl")?,
        EventKind::Pread64 => parse_pread_pwrite(payload, "pread64")?,
        EventKind::Pwrite64 => parse_pread_pwrite(payload, "pwrite64")?,
        EventKind::Readv => parse_readv_writev(payload, "readv")?,
        EventKind::Writev => parse_readv_writev(payload, "writev")?,
        EventKind::Mmap => parse_mmap(payload)?,
        EventKind::Sendfile => parse_sendfile_splice(payload, "sendfile")?,
        EventKind::Splice => parse_sendfile_splice(payload, "splice")?,
        EventKind::LsmFileOpen => parse_lsm_simple(payload, "file_open")?,
        EventKind::LsmTaskKill => parse_lsm_task_kill(payload)?,
        EventKind::LsmBpf => parse_lsm_bpf(payload)?,
        EventKind::LsmPtraceAccessCheck => parse_lsm_ptrace(payload)?,
        EventKind::LsmInodeUnlink => parse_lsm_simple(payload, "inode_unlink")?,
        EventKind::LsmInodeRename => parse_lsm_simple(payload, "inode_rename")?,
        EventKind::LsmTaskFixSetuid => parse_lsm_setuid(payload)?,
        _ => bail!("Unexpected event kind in process event"),
    };

    Ok(BehaviorEvent {
        header: header_json,
        event: EventTypeJson {
            event_type,
            name,
            layer,
        },
        proc: None, // Filled by enricher
        args,
        return_code,
    })
}

fn deserialize_packet(data: &[u8]) -> Result<BehaviorEvent> {
    if data.len() < PacketEventHeader::SIZE {
        bail!("Packet event data too short");
    }

    let pkt_header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const PacketEventHeader) };
    let pkt_data = &data[PacketEventHeader::SIZE..];

    let name = if pkt_header.kind == EventKind::PacketIngress as u8 {
        "ingress"
    } else {
        "egress"
    };

    let encoded_data = base64::engine::general_purpose::STANDARD.encode(pkt_data);

    let args = serde_json::json!({
        "data": encoded_data,
        "ifindex": pkt_header.ifindex,
    });

    Ok(BehaviorEvent {
        header: EventHeaderJson {
            timestamp: pkt_header.timestamp_ns as f64 / 1_000_000_000.0,
            auid: 0,       // Filled by packet correlator
            sessionid: 0,
            pid: 0,
            ppid: None,
            comm: String::new(),
        },
        event: EventTypeJson {
            event_type: "PACKET".to_string(),
            name: name.to_string(),
            layer: "behavior".to_string(),
        },
        proc: None,
        args: Some(args),
        return_code: None,
    })
}

// ── Payload parsers ──────────────────────────────────────────────────────────

use base64::Engine;

fn parse_tty(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < TtyPayload::SIZE {
        bail!("TTY payload too short");
    }
    let tty = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const TtyPayload) };
    let data_start = TtyPayload::SIZE;
    let data_len = (tty.data_len as usize).min(payload.len() - data_start);
    let raw_data = &payload[data_start..data_start + data_len];
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw_data);

    let args = serde_json::json!({ "data": encoded });
    Ok(("TTY".into(), name.into(), "intent".into(), Some(args), None))
}

fn parse_execve(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < ExecvePayload::SIZE {
        bail!("Execve payload too short");
    }
    let execve = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const ExecvePayload) };
    let var_data = &payload[ExecvePayload::SIZE..];

    let filename_len = (execve.filename_len as usize).min(var_data.len());
    let filename = extract_string(&var_data[..filename_len]);

    let argv_start = filename_len;
    let argv_len = (execve.argv_len as usize).min(var_data.len().saturating_sub(argv_start));
    let argv_data = &var_data[argv_start..argv_start + argv_len];
    let argv = extract_argv(argv_data);

    let args = serde_json::json!({
        "filename": filename,
        "argv": argv,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "tooling".into(),
        Some(args),
        Some(execve.return_code as i64),
    ))
}

fn parse_raw_syscall(payload: &[u8]) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < RawSyscallPayload::SIZE {
        bail!("Raw syscall payload too short");
    }
    let raw = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const RawSyscallPayload) };

    let args = serde_json::json!({
        "syscall_nr": raw.syscall_nr,
        "raw_args": [raw.args[0], raw.args[1], raw.args[2], raw.args[3], raw.args[4], raw.args[5]],
    });

    Ok((
        "SYSCALL".into(),
        raw.syscall_nr.to_string(),
        "behavior".into(),
        Some(args),
        Some(raw.return_code),
    ))
}

fn parse_openat(payload: &[u8]) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < OpenatPayload::SIZE {
        bail!("Openat payload too short");
    }
    let openat = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const OpenatPayload) };
    let var_data = &payload[OpenatPayload::SIZE..];
    let filename_len = (openat.filename_len as usize).min(var_data.len());
    let filename = extract_string(&var_data[..filename_len]);
    let flags = decode_open_flags(openat.flags);

    // dev/ino are populated only when the open succeeded and the kernel
    // fd-table traversal was successful. Zero ⇒ omit, so consumers can
    // distinguish "unresolved" from "real inode 0 on dev 0".
    let mut args = serde_json::json!({
        "filename": filename,
        "flags": flags,
        "mode": openat.mode,
    });
    if openat.dev != 0 || openat.ino != 0 {
        let obj = args.as_object_mut().expect("openat args is an object");
        obj.insert("dev".into(), serde_json::Value::from(openat.dev));
        obj.insert("ino".into(), serde_json::Value::from(openat.ino));
    }

    Ok((
        "TRACEPOINT".into(),
        "openat".into(),
        "behavior".into(),
        Some(args),
        Some(openat.return_code as i64),
    ))
}

fn parse_read_write(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < ReadWritePayload::SIZE {
        bail!("ReadWrite payload too short");
    }
    let rw = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const ReadWritePayload) };

    let fd_type_str = match rw.fd_type {
        FD_TYPE_REGULAR => "regular",
        FD_TYPE_PIPE => "pipe",
        FD_TYPE_SOCKET => "socket",
        FD_TYPE_TTY => "tty",
        _ => "other",
    };

    let args = serde_json::json!({
        "fd": rw.fd,
        "fd_type": fd_type_str,
        "requested_size": rw.requested_size,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(rw.return_code),
    ))
}

fn parse_connect_bind(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < ConnectBindPayload::SIZE {
        bail!("ConnectBind payload too short");
    }
    let cb = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const ConnectBindPayload) };

    let addr = if cb.family == 2 {
        format_ipv4(cb.addr_v4)
    } else if cb.family == 10 {
        format_ipv6(&cb.addr_v6)
    } else {
        String::new()
    };

    let args = serde_json::json!({
        "family": cb.family,
        "port": cb.port,
        "addr": addr,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(cb.return_code as i64),
    ))
}

fn parse_listen(payload: &[u8]) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < ListenPayload::SIZE {
        bail!("Listen payload too short");
    }
    let listen = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const ListenPayload) };

    let args = serde_json::json!({
        "fd": listen.fd,
        "backlog": listen.backlog,
    });

    Ok((
        "TRACEPOINT".into(),
        "listen".into(),
        "behavior".into(),
        Some(args),
        Some(listen.return_code as i64),
    ))
}

fn parse_socket(payload: &[u8]) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < SocketPayload::SIZE {
        bail!("Socket payload too short");
    }
    let sock = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const SocketPayload) };

    let args = serde_json::json!({
        "domain": sock.domain,
        "type": sock.sock_type,
        "protocol": sock.protocol,
    });

    Ok((
        "TRACEPOINT".into(),
        "socket".into(),
        "behavior".into(),
        Some(args),
        Some(sock.return_code as i64),
    ))
}

fn parse_clone(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < ClonePayload::SIZE {
        bail!("Clone payload too short");
    }
    let clone = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const ClonePayload) };

    let flags = decode_clone_flags(clone.flags);
    let args = serde_json::json!({
        "flags": flags,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(clone.return_code),
    ))
}

fn parse_path_event(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < PathPayload::SIZE {
        bail!("Path payload too short");
    }
    let path = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const PathPayload) };
    let var_data = &payload[PathPayload::SIZE..];
    let path_len = (path.path_len as usize).min(var_data.len());
    let filename = extract_string(&var_data[..path_len]);

    let args = serde_json::json!({
        "filename": filename,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(path.return_code as i64),
    ))
}

fn parse_fd_event(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < FdPayload::SIZE {
        bail!("Fd payload too short");
    }
    let fd = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const FdPayload) };

    let args = serde_json::json!({
        "fd": fd.fd,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(fd.return_code as i64),
    ))
}

fn parse_two_path_event(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < TwoPathPayload::SIZE {
        bail!("TwoPath payload too short");
    }
    let tp = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const TwoPathPayload) };
    let var_data = &payload[TwoPathPayload::SIZE..];

    let p1_len = (tp.path1_len as usize).min(var_data.len());
    let path1 = extract_string(&var_data[..p1_len]);

    let p2_start = p1_len;
    let p2_len = (tp.path2_len as usize).min(var_data.len().saturating_sub(p2_start));
    let path2 = extract_string(&var_data[p2_start..p2_start + p2_len]);

    let args = serde_json::json!({
        "oldpath": path1,
        "newpath": path2,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(tp.return_code as i64),
    ))
}

fn parse_sendto_recvfrom(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < SendtoRecvfromPayload::SIZE {
        bail!("SendtoRecvfrom payload too short");
    }
    let sr = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const SendtoRecvfromPayload) };

    let addr = if sr.family == 2 {
        format_ipv4(sr.addr_v4)
    } else if sr.family == 10 {
        format_ipv6(&sr.addr_v6)
    } else {
        String::new()
    };

    let args = serde_json::json!({
        "fd": sr.fd,
        "family": sr.family,
        "port": sr.port,
        "addr": addr,
        "size": sr.size,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(sr.return_code),
    ))
}

fn parse_dup(
    payload: &[u8],
    name: &str,
) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < DupPayload::SIZE {
        bail!("Dup payload too short");
    }
    let d = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const DupPayload) };

    let args = serde_json::json!({
        "oldfd": d.oldfd,
        "newfd": d.newfd,
        "cloexec": d.cloexec != 0,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(d.return_code),
    ))
}

fn parse_pread_pwrite(
    payload: &[u8],
    name: &str,
) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < PreadPwritePayload::SIZE {
        bail!("PreadPwrite payload too short");
    }
    let p = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const PreadPwritePayload) };

    let fd_type_str = match p.fd_type {
        FD_TYPE_REGULAR => "regular",
        FD_TYPE_PIPE => "pipe",
        FD_TYPE_SOCKET => "socket",
        FD_TYPE_TTY => "tty",
        _ => "other",
    };

    let args = serde_json::json!({
        "fd": p.fd,
        "fd_type": fd_type_str,
        "size": p.requested_size,
        "offset": p.offset,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(p.return_code),
    ))
}

fn parse_readv_writev(
    payload: &[u8],
    name: &str,
) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < ReadvWritevPayload::SIZE {
        bail!("ReadvWritev payload too short");
    }
    let p = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const ReadvWritevPayload) };

    let fd_type_str = match p.fd_type {
        FD_TYPE_REGULAR => "regular",
        FD_TYPE_PIPE => "pipe",
        FD_TYPE_SOCKET => "socket",
        FD_TYPE_TTY => "tty",
        _ => "other",
    };

    let args = serde_json::json!({
        "fd": p.fd,
        "fd_type": fd_type_str,
        "size": p.requested_size,
        "iov_count": p.iov_count,
        "iov_truncated": p.iov_truncated != 0,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(p.return_code),
    ))
}

fn parse_mmap(
    payload: &[u8],
) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < MmapPayload::SIZE {
        bail!("Mmap payload too short");
    }
    let p = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const MmapPayload) };

    let mut args = serde_json::json!({
        "fd": p.fd,
        "prot": decode_mmap_prot(p.prot),
        "flags": decode_mmap_flags(p.flags),
        "length": p.length,
        "offset": p.offset,
    });
    if p.dev != 0 || p.ino != 0 {
        let obj = args.as_object_mut().expect("mmap args is an object");
        obj.insert("dev".into(), serde_json::Value::from(p.dev));
        obj.insert("ino".into(), serde_json::Value::from(p.ino));
    }

    Ok((
        "TRACEPOINT".into(),
        "mmap".into(),
        "behavior".into(),
        Some(args),
        Some(p.return_code),
    ))
}

fn parse_sendfile_splice(
    payload: &[u8],
    name: &str,
) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < SendfileSplicePayload::SIZE {
        bail!("SendfileSplice payload too short");
    }
    let p = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const SendfileSplicePayload) };

    let in_type = fd_type_to_str(p.in_fd_type);
    let out_type = fd_type_to_str(p.out_fd_type);

    let args = serde_json::json!({
        "in_fd": p.in_fd,
        "out_fd": p.out_fd,
        "in_fd_type": in_type,
        "out_fd_type": out_type,
        "size": p.size,
    });

    Ok((
        "TRACEPOINT".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        Some(p.return_code),
    ))
}

fn fd_type_to_str(t: u8) -> &'static str {
    match t {
        FD_TYPE_REGULAR => "regular",
        FD_TYPE_PIPE => "pipe",
        FD_TYPE_SOCKET => "socket",
        FD_TYPE_TTY => "tty",
        _ => "other",
    }
}

fn parse_lsm_simple(payload: &[u8], name: &str) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    let return_code = if payload.len() >= 8 {
        let p = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const LsmFileOpenPayload) };
        Some(p.return_code as i64)
    } else {
        None
    };

    Ok((
        "LSM".into(),
        name.into(),
        "behavior".into(),
        None,
        return_code,
    ))
}

fn parse_lsm_task_kill(payload: &[u8]) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < LsmTaskKillPayload::SIZE {
        bail!("LSM task_kill payload too short");
    }
    let tk = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const LsmTaskKillPayload) };

    let args = serde_json::json!({
        "target_pid": tk.target_pid,
        "signal": tk.signal,
    });

    Ok((
        "LSM".into(),
        "task_kill".into(),
        "behavior".into(),
        Some(args),
        Some(tk.return_code as i64),
    ))
}

fn parse_lsm_bpf(payload: &[u8]) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < LsmBpfPayload::SIZE {
        bail!("LSM bpf payload too short");
    }
    let bpf = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const LsmBpfPayload) };

    let args = serde_json::json!({
        "cmd": bpf.cmd,
    });

    Ok((
        "LSM".into(),
        "bpf".into(),
        "behavior".into(),
        Some(args),
        Some(bpf.return_code as i64),
    ))
}

fn parse_lsm_ptrace(payload: &[u8]) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < LsmPtracePayload::SIZE {
        bail!("LSM ptrace payload too short");
    }
    let pt = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const LsmPtracePayload) };

    let args = serde_json::json!({
        "target_pid": pt.target_pid,
    });

    Ok((
        "LSM".into(),
        "ptrace_access_check".into(),
        "behavior".into(),
        Some(args),
        Some(pt.return_code as i64),
    ))
}

fn parse_lsm_setuid(payload: &[u8]) -> Result<(String, String, String, Option<serde_json::Value>, Option<i64>)> {
    if payload.len() < LsmSetuidPayload::SIZE {
        bail!("LSM setuid payload too short");
    }
    let su = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const LsmSetuidPayload) };

    let args = serde_json::json!({
        "old_uid": su.old_uid,
        "new_uid": su.new_uid,
        "old_gid": su.old_gid,
        "new_gid": su.new_gid,
    });

    Ok((
        "LSM".into(),
        "task_fix_setuid".into(),
        "behavior".into(),
        Some(args),
        Some(su.return_code as i64),
    ))
}

// ── Utility functions ────────────────────────────────────────────────────────

fn comm_to_string(comm: &[u8; COMM_SIZE]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(COMM_SIZE);
    String::from_utf8_lossy(&comm[..end]).to_string()
}

fn extract_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

fn extract_argv(data: &[u8]) -> Vec<String> {
    let mut argv = Vec::new();
    if data.is_empty() {
        return argv;
    }
    for chunk in data.split(|&b| b == 0) {
        if !chunk.is_empty() {
            argv.push(String::from_utf8_lossy(chunk).to_string());
        }
    }
    argv
}

fn format_ipv4(addr: u32) -> String {
    let bytes = addr.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn format_ipv6(addr: &[u8; 16]) -> String {
    let mut parts = Vec::new();
    for i in (0..16).step_by(2) {
        parts.push(format!("{:02x}{:02x}", addr[i], addr[i + 1]));
    }
    parts.join(":")
}

fn decode_open_flags(flags: u32) -> Vec<String> {
    let mut result = Vec::new();
    let access = flags & 0o3;
    match access {
        0 => result.push("O_RDONLY".into()),
        1 => result.push("O_WRONLY".into()),
        2 => result.push("O_RDWR".into()),
        _ => {}
    }
    if flags & 0o100 != 0 { result.push("O_CREAT".into()); }
    if flags & 0o200 != 0 { result.push("O_EXCL".into()); }
    if flags & 0o1000 != 0 { result.push("O_TRUNC".into()); }
    if flags & 0o2000 != 0 { result.push("O_APPEND".into()); }
    if flags & 0o4000 != 0 { result.push("O_NONBLOCK".into()); }
    if flags & 0o10000 != 0 { result.push("O_DSYNC".into()); }
    if flags & 0o4010000 == 0o4010000 { result.push("O_SYNC".into()); }
    if flags & 0o200000 != 0 { result.push("O_DIRECTORY".into()); }
    if flags & 0o400000 != 0 { result.push("O_NOFOLLOW".into()); }
    if flags & 0o2000000 != 0 { result.push("O_CLOEXEC".into()); }
    result
}

fn decode_mmap_prot(prot: u32) -> Vec<String> {
    let mut result = Vec::new();
    if prot == 0 {
        result.push("PROT_NONE".into());
        return result;
    }
    if prot & 0x1 != 0 { result.push("PROT_READ".into()); }
    if prot & 0x2 != 0 { result.push("PROT_WRITE".into()); }
    if prot & 0x4 != 0 { result.push("PROT_EXEC".into()); }
    if result.is_empty() { result.push(format!("0x{:x}", prot)); }
    result
}

fn decode_mmap_flags(flags: u32) -> Vec<String> {
    let mut result = Vec::new();
    // MAP_SHARED=0x01, MAP_PRIVATE=0x02 are mutually exclusive
    match flags & 0x3 {
        0x01 => result.push("MAP_SHARED".into()),
        0x02 => result.push("MAP_PRIVATE".into()),
        0x03 => result.push("MAP_SHARED_VALIDATE".into()),
        _ => {}
    }
    if flags & 0x10 != 0 { result.push("MAP_FIXED".into()); }
    if flags & 0x20 != 0 { result.push("MAP_ANONYMOUS".into()); }
    if flags & 0x100 != 0 { result.push("MAP_GROWSDOWN".into()); }
    if flags & 0x800 != 0 { result.push("MAP_DENYWRITE".into()); }
    if flags & 0x1000 != 0 { result.push("MAP_EXECUTABLE".into()); }
    if flags & 0x2000 != 0 { result.push("MAP_LOCKED".into()); }
    if flags & 0x4000 != 0 { result.push("MAP_NORESERVE".into()); }
    if flags & 0x8000 != 0 { result.push("MAP_POPULATE".into()); }
    if flags & 0x10000 != 0 { result.push("MAP_NONBLOCK".into()); }
    if flags & 0x20000 != 0 { result.push("MAP_STACK".into()); }
    if flags & 0x40000 != 0 { result.push("MAP_HUGETLB".into()); }
    if flags & 0x100000 != 0 { result.push("MAP_FIXED_NOREPLACE".into()); }
    if result.is_empty() { result.push(format!("0x{:x}", flags)); }
    result
}

fn decode_clone_flags(flags: u64) -> Vec<String> {
    let mut result = Vec::new();
    if flags & 0x00000100 != 0 { result.push("CLONE_VM".into()); }
    if flags & 0x00000200 != 0 { result.push("CLONE_FS".into()); }
    if flags & 0x00000400 != 0 { result.push("CLONE_FILES".into()); }
    if flags & 0x00000800 != 0 { result.push("CLONE_SIGHAND".into()); }
    if flags & 0x00010000 != 0 { result.push("CLONE_THREAD".into()); }
    if flags & 0x00020000 != 0 { result.push("CLONE_NEWNS".into()); }
    if flags & 0x02000000 != 0 { result.push("CLONE_NEWUTS".into()); }
    if flags & 0x04000000 != 0 { result.push("CLONE_NEWIPC".into()); }
    if flags & 0x10000000 != 0 { result.push("CLONE_NEWUSER".into()); }
    if flags & 0x20000000 != 0 { result.push("CLONE_NEWPID".into()); }
    if flags & 0x40000000 != 0 { result.push("CLONE_NEWNET".into()); }
    if result.is_empty() { result.push(format!("0x{:x}", flags)); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    // ── Test helpers: construct raw byte buffers as BPF would produce ────

    fn make_event_header(kind: EventKind) -> EventHeader {
        let mut comm = [0u8; COMM_SIZE];
        comm[..4].copy_from_slice(b"test");
        EventHeader {
            kind: kind as u8,
            _pad: [0; 3],
            timestamp_ns: 1_500_000_000, // 1.5 seconds
            auid: 1000,
            sessionid: 42,
            pid: 1234,
            ppid: 1,
            comm,
        }
    }

    fn header_bytes(h: &EventHeader) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(
                h as *const EventHeader as *const u8,
                EventHeader::SIZE,
            )
        }
        .to_vec()
    }

    fn payload_bytes<T>(payload: &T) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(
                payload as *const T as *const u8,
                mem::size_of::<T>(),
            )
        }
        .to_vec()
    }

    fn build_event<T>(kind: EventKind, payload: &T) -> Vec<u8> {
        let h = make_event_header(kind);
        let mut buf = header_bytes(&h);
        buf.extend_from_slice(&payload_bytes(payload));
        buf
    }

    fn build_event_with_vardata<T>(kind: EventKind, payload: &T, vardata: &[u8]) -> Vec<u8> {
        let mut buf = build_event(kind, payload);
        buf.extend_from_slice(vardata);
        buf
    }

    // ── Utility function tests (preserved from original) ────────────────

    #[test]
    fn test_comm_to_string() {
        let mut comm = [0u8; COMM_SIZE];
        comm[..4].copy_from_slice(b"bash");
        assert_eq!(comm_to_string(&comm), "bash");
    }

    #[test]
    fn test_comm_to_string_full() {
        let comm = [b'a'; COMM_SIZE];
        assert_eq!(comm_to_string(&comm).len(), COMM_SIZE);
    }

    #[test]
    fn test_comm_to_string_empty() {
        let comm = [0u8; COMM_SIZE];
        assert_eq!(comm_to_string(&comm), "");
    }

    #[test]
    fn test_extract_string() {
        assert_eq!(extract_string(b"hello\0world"), "hello");
        assert_eq!(extract_string(b"hello"), "hello");
        assert_eq!(extract_string(b""), "");
    }

    #[test]
    fn test_extract_argv() {
        let data = b"ls\0-la\0/tmp\0";
        let argv = extract_argv(data);
        assert_eq!(argv, vec!["ls", "-la", "/tmp"]);
    }

    #[test]
    fn test_extract_argv_empty() {
        assert_eq!(extract_argv(b""), Vec::<String>::new());
    }

    #[test]
    fn test_format_ipv4() {
        let addr = u32::from_be_bytes([127, 0, 0, 1]);
        assert_eq!(format_ipv4(addr), "127.0.0.1");
    }

    #[test]
    fn test_format_ipv4_zeros() {
        assert_eq!(format_ipv4(0), "0.0.0.0");
    }

    #[test]
    fn test_format_ipv6() {
        let mut addr = [0u8; 16];
        addr[15] = 1; // ::1
        assert_eq!(format_ipv6(&addr), "0000:0000:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn test_decode_open_flags() {
        let flags = decode_open_flags(0o102); // O_RDWR | O_CREAT
        assert!(flags.contains(&"O_RDWR".to_string()));
        assert!(flags.contains(&"O_CREAT".to_string()));
    }

    #[test]
    fn test_decode_open_flags_rdonly() {
        let flags = decode_open_flags(0);
        assert!(flags.contains(&"O_RDONLY".to_string()));
    }

    #[test]
    fn test_decode_clone_flags_thread() {
        // CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
        let flags = 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 | 0x00010000;
        let decoded = decode_clone_flags(flags);
        assert!(decoded.contains(&"CLONE_VM".to_string()));
        assert!(decoded.contains(&"CLONE_THREAD".to_string()));
    }

    #[test]
    fn test_decode_clone_flags_zero() {
        let decoded = decode_clone_flags(0);
        // Zero flags should produce a hex representation
        assert_eq!(decoded, vec!["0x0"]);
    }

    // ── Core contract: header fields are correctly extracted ─────────────

    /// The shared header (timestamp, auid, pid, comm) must be faithfully
    /// extracted from the binary representation for all process event types.
    #[test]
    fn header_fields_correctly_extracted() {
        let payload = RawSyscallPayload {
            syscall_nr: 1,
            args: [0; 6],
            return_code: 0,
        };
        let data = build_event(EventKind::RawSyscall, &payload);
        let event = deserialize(&data).unwrap();

        assert!((event.header.timestamp - 1.5).abs() < 0.001);
        assert_eq!(event.header.auid, 1000);
        assert_eq!(event.header.sessionid, 42);
        assert_eq!(event.header.pid, 1234);
        assert_eq!(event.header.ppid, Some(1));
        assert_eq!(event.header.comm, "test");
    }

    /// When ppid is 0, it should be serialized as None (omitted from JSON).
    #[test]
    fn header_ppid_zero_becomes_none() {
        let mut h = make_event_header(EventKind::RawSyscall);
        h.ppid = 0;
        let payload = RawSyscallPayload {
            syscall_nr: 1,
            args: [0; 6],
            return_code: 0,
        };
        let mut buf = header_bytes(&h);
        buf.extend_from_slice(&payload_bytes(&payload));
        let event = deserialize(&buf).unwrap();
        assert_eq!(event.header.ppid, None);
    }

    // ── Core contract: each event kind produces correct type/name/layer ──

    /// Every event kind must map to the correct (event_type, name, layer)
    /// triple as defined by the schema. This is the fundamental output contract.
    #[test]
    fn raw_syscall_classification() {
        let payload = RawSyscallPayload {
            syscall_nr: 100,
            args: [1, 2, 3, 4, 5, 6],
            return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::RawSyscall, &payload)).unwrap();
        assert_eq!(event.event.event_type, "SYSCALL");
        assert_eq!(event.event.name, "100"); // syscall_nr as string
        assert_eq!(event.event.layer, "behavior");
        assert_eq!(event.return_code, Some(0));
    }

    #[test]
    fn execve_classification() {
        let payload = ExecvePayload {
            filename_len: 0,
            argv_len: 0,
            return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::Execve, &payload)).unwrap();
        assert_eq!(event.event.event_type, "TRACEPOINT");
        assert_eq!(event.event.name, "execve");
        assert_eq!(event.event.layer, "tooling");
    }

    #[test]
    fn execveat_classification() {
        let payload = ExecvePayload {
            filename_len: 0,
            argv_len: 0,
            return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::Execveat, &payload)).unwrap();
        assert_eq!(event.event.event_type, "TRACEPOINT");
        assert_eq!(event.event.name, "execveat");
        assert_eq!(event.event.layer, "tooling");
    }

    #[test]
    fn tty_read_classification() {
        let payload = TtyPayload { data_len: 0, _pad: [0; 2] };
        let event = deserialize(&build_event(EventKind::TtyRead, &payload)).unwrap();
        assert_eq!(event.event.event_type, "TTY");
        assert_eq!(event.event.name, "tty_read");
        assert_eq!(event.event.layer, "intent");
    }

    #[test]
    fn tty_write_classification() {
        let payload = TtyPayload { data_len: 0, _pad: [0; 2] };
        let event = deserialize(&build_event(EventKind::TtyWrite, &payload)).unwrap();
        assert_eq!(event.event.event_type, "TTY");
        assert_eq!(event.event.name, "tty_write");
        assert_eq!(event.event.layer, "intent");
    }

    #[test]
    fn openat_classification() {
        let payload = OpenatPayload {
            flags: 0, mode: 0, filename_len: 0, _pad: [0; 2], return_code: 0,
            _pad2: [0; 4], dev: 0, ino: 0,
        };
        let event = deserialize(&build_event(EventKind::Openat, &payload)).unwrap();
        assert_eq!(event.event.event_type, "TRACEPOINT");
        assert_eq!(event.event.name, "openat");
        assert_eq!(event.event.layer, "behavior");
    }

    #[test]
    fn connect_classification() {
        let payload = ConnectBindPayload {
            family: 2, port: 80, addr_v4: 0, addr_v6: [0; 16], return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::Connect, &payload)).unwrap();
        assert_eq!(event.event.event_type, "TRACEPOINT");
        assert_eq!(event.event.name, "connect");
        assert_eq!(event.event.layer, "behavior");
    }

    #[test]
    fn bind_classification() {
        let payload = ConnectBindPayload {
            family: 2, port: 8080, addr_v4: 0, addr_v6: [0; 16], return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::Bind, &payload)).unwrap();
        assert_eq!(event.event.name, "bind");
    }

    #[test]
    fn lsm_task_kill_classification() {
        let payload = LsmTaskKillPayload {
            target_pid: 100, signal: 9, return_code: -1,
        };
        let event = deserialize(&build_event(EventKind::LsmTaskKill, &payload)).unwrap();
        assert_eq!(event.event.event_type, "LSM");
        assert_eq!(event.event.name, "task_kill");
        assert_eq!(event.event.layer, "behavior");
    }

    #[test]
    fn lsm_bpf_classification() {
        let payload = LsmBpfPayload { cmd: 5, return_code: -1 };
        let event = deserialize(&build_event(EventKind::LsmBpf, &payload)).unwrap();
        assert_eq!(event.event.event_type, "LSM");
        assert_eq!(event.event.name, "bpf");
    }

    #[test]
    fn lsm_setuid_classification() {
        let payload = LsmSetuidPayload {
            old_uid: 1000, new_uid: 0, old_gid: 1000, new_gid: 0, return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::LsmTaskFixSetuid, &payload)).unwrap();
        assert_eq!(event.event.event_type, "LSM");
        assert_eq!(event.event.name, "task_fix_setuid");
    }

    // ── Core contract: variable-length data extraction ───────────────────

    /// Execve events must correctly extract filename and argv from
    /// variable-length data appended after the fixed payload.
    #[test]
    fn execve_extracts_filename_and_argv() {
        let filename = b"/bin/ls\0";
        let argv = b"ls\0-la\0/tmp\0";
        let payload = ExecvePayload {
            filename_len: filename.len() as u16,
            argv_len: argv.len() as u16,
            return_code: 0,
        };
        let mut vardata = Vec::new();
        vardata.extend_from_slice(filename);
        vardata.extend_from_slice(argv);

        let data = build_event_with_vardata(EventKind::Execve, &payload, &vardata);
        let event = deserialize(&data).unwrap();

        let args = event.args.unwrap();
        assert_eq!(args["filename"], "/bin/ls");
        let argv_arr: Vec<String> = args["argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(argv_arr, vec!["ls", "-la", "/tmp"]);
    }

    /// Openat events must correctly extract the filename path.
    #[test]
    fn openat_extracts_filename() {
        let path = b"/etc/passwd\0";
        let payload = OpenatPayload {
            flags: 0o2, // O_RDWR
            mode: 0o644,
            filename_len: path.len() as u16,
            _pad: [0; 2],
            return_code: 3,
            _pad2: [0; 4],
            dev: 0,
            ino: 0,
        };
        let data = build_event_with_vardata(EventKind::Openat, &payload, path);
        let event = deserialize(&data).unwrap();

        let args = event.args.unwrap();
        assert_eq!(args["filename"], "/etc/passwd");
        assert_eq!(event.return_code, Some(3));
    }

    /// Openat events with non-zero (dev, ino) must surface them in args.
    #[test]
    fn openat_surfaces_dev_ino_when_present() {
        let path = b"/etc/passwd\0";
        let payload = OpenatPayload {
            flags: 0,
            mode: 0,
            filename_len: path.len() as u16,
            _pad: [0; 2],
            return_code: 3,
            _pad2: [0; 4],
            dev: 0xfd00,
            ino: 12345,
        };
        let data = build_event_with_vardata(EventKind::Openat, &payload, path);
        let event = deserialize(&data).unwrap();
        let args = event.args.unwrap();
        assert_eq!(args["dev"], 0xfd00u64);
        assert_eq!(args["ino"], 12345u64);
    }

    /// Openat events with zero (dev, ino) must omit those fields.
    #[test]
    fn openat_omits_dev_ino_when_zero() {
        let path = b"/etc/passwd\0";
        let payload = OpenatPayload {
            flags: 0,
            mode: 0,
            filename_len: path.len() as u16,
            _pad: [0; 2],
            return_code: -1,
            _pad2: [0; 4],
            dev: 0,
            ino: 0,
        };
        let data = build_event_with_vardata(EventKind::Openat, &payload, path);
        let event = deserialize(&data).unwrap();
        let args = event.args.unwrap();
        assert!(args.get("dev").is_none());
        assert!(args.get("ino").is_none());
    }

    /// Path events (chdir, mkdir, unlink, etc.) must extract the path.
    #[test]
    fn path_event_extracts_path() {
        let path = b"/tmp/testdir\0";
        let payload = PathPayload {
            path_len: path.len() as u16,
            _pad: [0; 2],
            return_code: 0,
        };
        let data = build_event_with_vardata(EventKind::Mkdir, &payload, path);
        let event = deserialize(&data).unwrap();

        let args = event.args.unwrap();
        assert_eq!(args["filename"], "/tmp/testdir");
        assert_eq!(event.event.name, "mkdir");
    }

    /// Two-path events (rename, symlink, link) must extract both paths.
    #[test]
    fn two_path_event_extracts_both_paths() {
        let old = b"/tmp/old\0";
        let new = b"/tmp/new\0";
        let payload = TwoPathPayload {
            path1_len: old.len() as u16,
            path2_len: new.len() as u16,
            return_code: 0,
        };
        let mut vardata = Vec::new();
        vardata.extend_from_slice(old);
        vardata.extend_from_slice(new);

        let data = build_event_with_vardata(EventKind::Rename, &payload, &vardata);
        let event = deserialize(&data).unwrap();

        let args = event.args.unwrap();
        assert_eq!(args["oldpath"], "/tmp/old");
        assert_eq!(args["newpath"], "/tmp/new");
    }

    /// TTY events must produce base64-encoded data in args.data.
    #[test]
    fn tty_event_produces_base64_data() {
        let tty_data = b"echo hello\r\n";
        let payload = TtyPayload {
            data_len: tty_data.len() as u16,
            _pad: [0; 2],
        };
        let data = build_event_with_vardata(EventKind::TtyWrite, &payload, tty_data);
        let event = deserialize(&data).unwrap();

        let args = event.args.unwrap();
        let encoded = args["data"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(decoded, tty_data);
    }

    // ── Core contract: structured field extraction ───────────────────────

    /// RawSyscall must faithfully reproduce all 6 arguments.
    #[test]
    fn raw_syscall_preserves_all_args() {
        let payload = RawSyscallPayload {
            syscall_nr: 257,
            args: [100, 200, 300, 400, 500, 600],
            return_code: 3,
        };
        let event = deserialize(&build_event(EventKind::RawSyscall, &payload)).unwrap();

        let args = event.args.unwrap();
        assert_eq!(args["syscall_nr"], 257);
        let raw_args: Vec<u64> = args["raw_args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(raw_args, vec![100, 200, 300, 400, 500, 600]);
        assert_eq!(event.return_code, Some(3));
    }

    /// Connect/bind must format IPv4 addresses correctly.
    #[test]
    fn connect_formats_ipv4_address() {
        let payload = ConnectBindPayload {
            family: 2, // AF_INET
            port: 443,
            addr_v4: u32::from_be_bytes([10, 0, 1, 5]),
            addr_v6: [0; 16],
            return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::Connect, &payload)).unwrap();

        let args = event.args.unwrap();
        assert_eq!(args["family"], 2);
        assert_eq!(args["port"], 443);
        assert_eq!(args["addr"], "10.0.1.5");
    }

    /// Connect/bind must format IPv6 addresses correctly.
    #[test]
    fn connect_formats_ipv6_address() {
        let mut addr_v6 = [0u8; 16];
        addr_v6[15] = 1; // ::1
        let payload = ConnectBindPayload {
            family: 10, // AF_INET6
            port: 80,
            addr_v4: 0,
            addr_v6,
            return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::Connect, &payload)).unwrap();

        let args = event.args.unwrap();
        assert_eq!(args["port"], 80);
        // Should contain "0001" at the end for ::1
        let addr_str = args["addr"].as_str().unwrap();
        assert!(addr_str.ends_with("0001"), "IPv6 ::1 not formatted correctly: {}", addr_str);
    }

    /// LSM task_kill must extract target_pid and signal.
    #[test]
    fn lsm_task_kill_extracts_fields() {
        let payload = LsmTaskKillPayload {
            target_pid: 555,
            signal: 9,
            return_code: -1,
        };
        let event = deserialize(&build_event(EventKind::LsmTaskKill, &payload)).unwrap();

        let args = event.args.unwrap();
        assert_eq!(args["target_pid"], 555);
        assert_eq!(args["signal"], 9);
        assert_eq!(event.return_code, Some(-1));
    }

    /// LSM setuid must extract all uid/gid transition fields.
    #[test]
    fn lsm_setuid_extracts_transition() {
        let payload = LsmSetuidPayload {
            old_uid: 1000,
            new_uid: 0,
            old_gid: 1000,
            new_gid: 0,
            return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::LsmTaskFixSetuid, &payload)).unwrap();

        let args = event.args.unwrap();
        assert_eq!(args["old_uid"], 1000);
        assert_eq!(args["new_uid"], 0);
    }

    /// Clone events must decode flags symbolically.
    #[test]
    fn clone_decodes_flags() {
        let payload = ClonePayload {
            flags: 0x00010000, // CLONE_THREAD
            return_code: 1234,
        };
        let event = deserialize(&build_event(EventKind::Clone, &payload)).unwrap();

        let args = event.args.unwrap();
        let flags: Vec<String> = args["flags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(flags.contains(&"CLONE_THREAD".to_string()));
    }

    // ── Core contract: packet events use separate header ─────────────────

    #[test]
    fn packet_ingress_uses_packet_header() {
        let pkt_header = PacketEventHeader {
            kind: EventKind::PacketIngress as u8,
            _pad: [0; 3],
            timestamp_ns: 2_000_000_000,
            ifindex: 1,
            data_len: 4,
        };
        let raw_pkt = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut buf = unsafe {
            std::slice::from_raw_parts(
                &pkt_header as *const PacketEventHeader as *const u8,
                PacketEventHeader::SIZE,
            )
        }
        .to_vec();
        buf.extend_from_slice(&raw_pkt);

        let event = deserialize(&buf).unwrap();
        assert_eq!(event.event.event_type, "PACKET");
        assert_eq!(event.event.name, "ingress");
        assert_eq!(event.event.layer, "behavior");

        let args = event.args.unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(args["data"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn packet_egress_classification() {
        let pkt_header = PacketEventHeader {
            kind: EventKind::PacketEgress as u8,
            _pad: [0; 3],
            timestamp_ns: 1_000_000_000,
            ifindex: 0,
            data_len: 0,
        };
        let buf = unsafe {
            std::slice::from_raw_parts(
                &pkt_header as *const PacketEventHeader as *const u8,
                PacketEventHeader::SIZE,
            )
        }
        .to_vec();

        let event = deserialize(&buf).unwrap();
        assert_eq!(event.event.name, "egress");
    }

    // ── Core contract: robustness against malformed input ─────────────────

    /// Empty input must return an error, not panic.
    #[test]
    fn empty_input_returns_error() {
        assert!(deserialize(&[]).is_err());
    }

    /// Single byte (valid kind, no payload) must return an error.
    #[test]
    fn truncated_header_returns_error() {
        assert!(deserialize(&[EventKind::RawSyscall as u8]).is_err());
    }

    /// Header without payload must return error for events that require payload.
    #[test]
    fn header_only_returns_error() {
        let h = make_event_header(EventKind::RawSyscall);
        let buf = header_bytes(&h);
        assert!(deserialize(&buf).is_err());
    }

    /// Unknown event kind must return error, not panic.
    #[test]
    fn unknown_kind_returns_error() {
        let mut h = make_event_header(EventKind::RawSyscall);
        h.kind = 255; // invalid
        let payload = RawSyscallPayload {
            syscall_nr: 1, args: [0; 6], return_code: 0,
        };
        let mut buf = header_bytes(&h);
        buf.extend_from_slice(&payload_bytes(&payload));
        assert!(deserialize(&buf).is_err());
    }

    /// Truncated payload (header OK, payload short) must return error.
    #[test]
    fn truncated_payload_returns_error() {
        let h = make_event_header(EventKind::RawSyscall);
        let mut buf = header_bytes(&h);
        buf.push(0); // Only 1 byte of payload where RawSyscallPayload::SIZE is needed
        assert!(deserialize(&buf).is_err());
    }

    // ── proc field: initially None, to be filled by enricher ─────────────

    #[test]
    fn proc_field_initially_none() {
        let payload = RawSyscallPayload {
            syscall_nr: 1, args: [0; 6], return_code: 0,
        };
        let event = deserialize(&build_event(EventKind::RawSyscall, &payload)).unwrap();
        assert!(event.proc.is_none());
    }
}

// ── Golden / Snapshot tests ──────────────────────────────────────────────────
// These tests capture the exact JSON output of each event family.
// Any change to the output schema will be caught by insta and require
// explicit review via `cargo insta review`.
//
// The snapshots serve as a contract with downstream consumers:
// "this is what each event type looks like as JSON."

#[cfg(test)]
mod golden_tests {
    use super::*;
    use insta::assert_json_snapshot;
    use std::mem;

    fn make_header(kind: EventKind) -> EventHeader {
        let mut comm = [0u8; COMM_SIZE];
        comm[..4].copy_from_slice(b"bash");
        EventHeader {
            kind: kind as u8,
            _pad: [0; 3],
            timestamp_ns: 1_709_000_000_000, // fixed value for deterministic snapshots
            auid: 1000,
            sessionid: 42,
            pid: 5678,
            ppid: 1234,
            comm,
        }
    }

    fn header_bytes(h: &EventHeader) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(
                h as *const EventHeader as *const u8,
                EventHeader::SIZE,
            )
        }
        .to_vec()
    }

    fn payload_bytes<T>(p: &T) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(
                p as *const T as *const u8,
                mem::size_of::<T>(),
            )
        }
        .to_vec()
    }

    fn build(kind: EventKind, payload_raw: &[u8]) -> Vec<u8> {
        let h = make_header(kind);
        let mut buf = header_bytes(&h);
        buf.extend_from_slice(payload_raw);
        buf
    }

    fn to_json(event: &BehaviorEvent) -> serde_json::Value {
        serde_json::to_value(event).unwrap()
    }

    // ── Layer 1: TTY ─────────────────────────────────────────────────────

    #[test]
    fn golden_tty_write() {
        let payload = TtyPayload { data_len: 12, _pad: [0; 2] };
        let tty_data = b"echo hello\r\n";
        let mut buf = build(EventKind::TtyWrite, &payload_bytes(&payload));
        buf.extend_from_slice(tty_data);

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("tty_write", to_json(&event));
    }

    #[test]
    fn golden_tty_read() {
        let payload = TtyPayload { data_len: 5, _pad: [0; 2] };
        let tty_data = b"hello";
        let mut buf = build(EventKind::TtyRead, &payload_bytes(&payload));
        buf.extend_from_slice(tty_data);

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("tty_read", to_json(&event));
    }

    // ── Layer 2: Execve ──────────────────────────────────────────────────

    #[test]
    fn golden_execve() {
        let filename = b"/usr/bin/ls\0";
        let argv = b"ls\0-la\0/home\0";
        let payload = ExecvePayload {
            filename_len: filename.len() as u16,
            argv_len: argv.len() as u16,
            return_code: 0,
        };
        let mut buf = build(EventKind::Execve, &payload_bytes(&payload));
        buf.extend_from_slice(filename);
        buf.extend_from_slice(argv);

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("execve", to_json(&event));
    }

    // ── Layer 3: Raw syscall ─────────────────────────────────────────────

    #[test]
    fn golden_raw_syscall() {
        let payload = RawSyscallPayload {
            syscall_nr: 39, // getpid
            args: [0, 0, 0, 0, 0, 0],
            return_code: 5678,
        };
        let buf = build(EventKind::RawSyscall, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("raw_syscall", to_json(&event));
    }

    // ── Layer 3: Openat ──────────────────────────────────────────────────

    #[test]
    fn golden_openat() {
        let path = b"/etc/passwd\0";
        let payload = OpenatPayload {
            flags: 0o2 | 0o100, // O_RDWR | O_CREAT
            mode: 0o644,
            filename_len: path.len() as u16,
            _pad: [0; 2],
            return_code: 3,
            _pad2: [0; 4],
            dev: 0xfd00,
            ino: 100200,
        };
        let mut buf = build(EventKind::Openat, &payload_bytes(&payload));
        buf.extend_from_slice(path);

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("openat", to_json(&event));
    }

    // ── Layer 3: Read / Write ────────────────────────────────────────────

    #[test]
    fn golden_read() {
        let payload = ReadWritePayload {
            fd: 3,
            fd_type: FD_TYPE_REGULAR,
            _pad: [0; 3],
            requested_size: 4096,
            return_code: 1024,
        };
        let buf = build(EventKind::Read, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("read", to_json(&event));
    }

    // ── Layer 3: Connect ─────────────────────────────────────────────────

    #[test]
    fn golden_connect_ipv4() {
        let payload = ConnectBindPayload {
            family: 2, // AF_INET
            port: 443,
            addr_v4: u32::from_be_bytes([93, 184, 216, 34]), // 93.184.216.34
            addr_v6: [0; 16],
            return_code: 0,
        };
        let buf = build(EventKind::Connect, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("connect_ipv4", to_json(&event));
    }

    #[test]
    fn golden_connect_ipv6() {
        let mut addr_v6 = [0u8; 16];
        // 2001:0db8::1
        addr_v6[0] = 0x20;
        addr_v6[1] = 0x01;
        addr_v6[2] = 0x0d;
        addr_v6[3] = 0xb8;
        addr_v6[15] = 0x01;
        let payload = ConnectBindPayload {
            family: 10, // AF_INET6
            port: 80,
            addr_v4: 0,
            addr_v6,
            return_code: 0,
        };
        let buf = build(EventKind::Connect, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("connect_ipv6", to_json(&event));
    }

    // ── Layer 3: Clone ───────────────────────────────────────────────────

    #[test]
    fn golden_clone() {
        let payload = ClonePayload {
            flags: 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 | 0x00010000,
            // CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
            return_code: 9999,
        };
        let buf = build(EventKind::Clone, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("clone", to_json(&event));
    }

    // ── Layer 3: Path events ─────────────────────────────────────────────

    #[test]
    fn golden_mkdir() {
        let path = b"/tmp/new_dir\0";
        let payload = PathPayload {
            path_len: path.len() as u16,
            _pad: [0; 2],
            return_code: 0,
        };
        let mut buf = build(EventKind::Mkdir, &payload_bytes(&payload));
        buf.extend_from_slice(path);

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("mkdir", to_json(&event));
    }

    // ── Layer 3: Two-path events ─────────────────────────────────────────

    #[test]
    fn golden_rename() {
        let old = b"/tmp/old_name\0";
        let new = b"/tmp/new_name\0";
        let payload = TwoPathPayload {
            path1_len: old.len() as u16,
            path2_len: new.len() as u16,
            return_code: 0,
        };
        let mut buf = build(EventKind::Rename, &payload_bytes(&payload));
        buf.extend_from_slice(old);
        buf.extend_from_slice(new);

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("rename", to_json(&event));
    }

    // ── Layer 3: Sendto ──────────────────────────────────────────────────

    #[test]
    fn golden_sendto() {
        let payload = SendtoRecvfromPayload {
            fd: 5,
            family: 2,
            port: 53,
            addr_v4: u32::from_be_bytes([8, 8, 8, 8]),
            addr_v6: [0; 16],
            size: 64,
            return_code: 64,
        };
        let buf = build(EventKind::Sendto, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("sendto", to_json(&event));
    }

    // ── LSM events ───────────────────────────────────────────────────────

    #[test]
    fn golden_lsm_task_kill() {
        let payload = LsmTaskKillPayload {
            target_pid: 100,
            signal: 9,
            return_code: -1,
        };
        let buf = build(EventKind::LsmTaskKill, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("lsm_task_kill", to_json(&event));
    }

    #[test]
    fn golden_lsm_bpf() {
        let payload = LsmBpfPayload { cmd: 5, return_code: -1 };
        let buf = build(EventKind::LsmBpf, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("lsm_bpf", to_json(&event));
    }

    #[test]
    fn golden_lsm_setuid() {
        let payload = LsmSetuidPayload {
            old_uid: 1000,
            new_uid: 0,
            old_gid: 1000,
            new_gid: 0,
            return_code: 0,
        };
        let buf = build(EventKind::LsmTaskFixSetuid, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("lsm_setuid", to_json(&event));
    }

    #[test]
    fn golden_lsm_ptrace() {
        let payload = LsmPtracePayload {
            target_pid: 999,
            return_code: -1,
        };
        let buf = build(EventKind::LsmPtraceAccessCheck, &payload_bytes(&payload));

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("lsm_ptrace", to_json(&event));
    }

    // ── Packet events ────────────────────────────────────────────────────

    #[test]
    fn golden_packet_ingress() {
        let pkt_header = PacketEventHeader {
            kind: EventKind::PacketIngress as u8,
            _pad: [0; 3],
            timestamp_ns: 1_709_000_000_000,
            ifindex: 2,
            data_len: 4,
        };
        let raw_pkt = vec![0x45, 0x00, 0x00, 0x3C]; // IP header start
        let mut buf = unsafe {
            std::slice::from_raw_parts(
                &pkt_header as *const PacketEventHeader as *const u8,
                PacketEventHeader::SIZE,
            )
        }
        .to_vec();
        buf.extend_from_slice(&raw_pkt);

        let event = deserialize(&buf).unwrap();
        assert_json_snapshot!("packet_ingress", to_json(&event));
    }

    // ── Alignment-independence regression test ───────────────────────────
    //
    // The deserializer must accept any `&[u8]` regardless of the underlying
    // pointer's alignment. The wire types contain `u64` fields and therefore
    // demand 8-byte alignment if read by reference; this test feeds them a
    // 1-byte-aligned slice to exercise the `read_unaligned` paths and pin
    // the contract. On x86_64 ordinary loads tolerate misalignment, so this
    // test passes silently under `cargo test`; its real value is under miri,
    // which flags every reference deref of an under-aligned pointer as UB.

    /// Wrap `bytes` so that the returned slice begins one byte past a
    /// glibc-malloc-aligned (≥ 8) base, guaranteeing odd alignment.
    fn unaligned(bytes: &[u8]) -> Vec<u8> {
        let mut padded = Vec::with_capacity(bytes.len() + 1);
        padded.push(0xAA); // sacrificial prefix byte
        padded.extend_from_slice(bytes);
        padded
    }

    #[test]
    fn deserialize_tolerates_unaligned_buffer_process_event() {
        let payload = RawSyscallPayload {
            syscall_nr: 100,
            args: [1, 2, 3, 4, 5, 6],
            return_code: -1,
        };
        let aligned = build(EventKind::RawSyscall, &payload_bytes(&payload));
        let padded = unaligned(&aligned);
        // sanity: the slice we pass really is 1-byte aligned
        assert_eq!((padded[1..].as_ptr() as usize) % 8, 1);

        let event = deserialize(&padded[1..]).unwrap();
        assert_eq!(event.event.event_type, "SYSCALL");
        assert_eq!(event.event.name, "100");
        assert_eq!(event.return_code, Some(-1));
        assert_eq!(event.header.pid, 5678);
    }

    #[test]
    fn deserialize_tolerates_unaligned_buffer_packet_event() {
        let pkt_header = PacketEventHeader {
            kind: EventKind::PacketEgress as u8,
            _pad: [0; 3],
            timestamp_ns: 5_000_000_000,
            ifindex: 7,
            data_len: 2,
        };
        let mut aligned = unsafe {
            std::slice::from_raw_parts(
                &pkt_header as *const PacketEventHeader as *const u8,
                PacketEventHeader::SIZE,
            )
        }
        .to_vec();
        aligned.extend_from_slice(&[0xAB, 0xCD]);

        let padded = unaligned(&aligned);
        assert_eq!((padded[1..].as_ptr() as usize) % 8, 1);

        let event = deserialize(&padded[1..]).unwrap();
        assert_eq!(event.event.event_type, "PACKET");
        assert_eq!(event.event.name, "egress");
        assert!((event.header.timestamp - 5.0).abs() < 1e-9);
    }
}
