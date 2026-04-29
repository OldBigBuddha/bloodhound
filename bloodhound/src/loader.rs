use anyhow::{Context, Result};
use aya::{
    maps::Array,
    programs::{KProbe, Lsm, SchedClassifier, TcAttachType, TracePoint},
    Btf, EbpfLoader,
};
use log::{info, warn};

use bloodhound_common::*;

use crate::cli::Cli;

pub fn load_and_attach(args: &Cli) -> Result<aya::Ebpf> {
    // Load BPF programs with global variables set BEFORE loading
    let mut bpf = EbpfLoader::new()
        .set_global("TARGET_AUID", &args.uid, true)
        .set_global("DAEMON_PID", &std::process::id(), true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/bloodhound-ebpf/bpfel-unknown-none/release/bloodhound-ebpf"
        )))?;

    info!("BPF object loaded, setting up maps...");

    // Populate exclusion bitmap
    populate_exclusion_bitmap(&mut bpf)?;

    // Populate port exclusion map
    populate_excluded_ports(&mut bpf, &args.exclude_ports)?;

    info!("Attaching Layer 2: execve tracepoints...");
    attach_tracepoint(&mut bpf, "sys_enter_execve", "syscalls", "sys_enter_execve")?;
    attach_tracepoint(&mut bpf, "sys_exit_execve", "syscalls", "sys_exit_execve")?;
    try_attach_tracepoint(&mut bpf, "sys_enter_execveat", "syscalls", "sys_enter_execveat");
    try_attach_tracepoint(&mut bpf, "sys_exit_execveat", "syscalls", "sys_exit_execveat");

    info!("Attaching Layer 3 Tier 1: raw syscalls...");
    attach_tracepoint(&mut bpf, "raw_sys_enter", "raw_syscalls", "sys_enter")?;
    attach_tracepoint(&mut bpf, "raw_sys_exit", "raw_syscalls", "sys_exit")?;

    info!("Attaching Layer 3 Tier 2: rich syscalls...");
    let tier2_syscalls: &[(&str, u64)] = &[
        ("openat", NR_OPENAT),
        ("read", NR_READ),
        ("write", NR_WRITE),
        ("connect", NR_CONNECT),
        ("bind", NR_BIND),
        ("listen", NR_LISTEN),
        ("socket", NR_SOCKET),
        ("clone", NR_CLONE),
        ("clone3", NR_CLONE3),
        ("chdir", NR_CHDIR),
        ("fchdir", NR_FCHDIR),
        ("unlink", NR_UNLINK),
        ("unlinkat", NR_UNLINKAT),
        ("rename", NR_RENAME),
        ("renameat2", NR_RENAMEAT2),
        ("mkdir", NR_MKDIR),
        ("mkdirat", NR_MKDIRAT),
        ("rmdir", NR_RMDIR),
        ("symlink", NR_SYMLINK),
        ("symlinkat", NR_SYMLINKAT),
        ("link", NR_LINK),
        ("linkat", NR_LINKAT),
        ("chmod", NR_CHMOD),
        ("fchmod", NR_FCHMOD),
        ("fchmodat", NR_FCHMODAT),
        ("chown", NR_CHOWN),
        ("fchown", NR_FCHOWN),
        ("fchownat", NR_FCHOWNAT),
        ("truncate", NR_TRUNCATE),
        ("ftruncate", NR_FTRUNCATE),
        ("mount", NR_MOUNT),
        ("umount2", NR_UMOUNT2),
        ("sendto", NR_SENDTO),
        ("recvfrom", NR_RECVFROM),
        ("dup", NR_DUP),
        ("dup2", NR_DUP2),
        ("dup3", NR_DUP3),
        ("pread64", NR_PREAD64),
        ("pwrite64", NR_PWRITE64),
        ("readv", NR_READV),
        ("writev", NR_WRITEV),
        ("mmap", NR_MMAP),
    ];

    let mut successful_syscalls = Vec::new();

    for (name, nr) in tier2_syscalls {
        let enter_prog = format!("sys_enter_{}", name);
        let exit_prog = format!("sys_exit_{}", name);
        let enter_tp = format!("sys_enter_{}", name);
        let exit_tp = format!("sys_exit_{}", name);

        let enter_ok = try_attach_tracepoint(&mut bpf, &enter_prog, "syscalls", &enter_tp);
        let exit_ok = try_attach_tracepoint(&mut bpf, &exit_prog, "syscalls", &exit_tp);

        if enter_ok && exit_ok {
            if (*nr as u32) < BITMAP_SIZE as u32 {
                successful_syscalls.push(*nr as u32);
            }
            info!("  Attached: {}", name);
        }
    }

    // fcntl rich extraction is conditional on cmd ∈ {F_DUPFD, F_DUPFD_CLOEXEC};
    // attach the tracepoints, but DO NOT register fcntl in TIER2_BITMAP, so
    // non-DUPFD fcntl commands remain visible via Tier 1 raw capture.
    let _ = try_attach_tracepoint(&mut bpf, "sys_enter_fcntl", "syscalls", "sys_enter_fcntl");
    let _ = try_attach_tracepoint(&mut bpf, "sys_exit_fcntl", "syscalls", "sys_exit_fcntl");

    // sendfile / splice rich extraction is opt-in (issue #9). When enabled,
    // attach both tracepoint pairs and register the syscall numbers in
    // TIER2_BITMAP so Tier 1 deduplicates. When disabled, the BPF programs
    // remain compiled in but unattached, and Tier 1 raw capture continues.
    if args.enable_rich_sendfile {
        let sf_ok = try_attach_tracepoint(&mut bpf, "sys_enter_sendfile", "syscalls", "sys_enter_sendfile")
            && try_attach_tracepoint(&mut bpf, "sys_exit_sendfile", "syscalls", "sys_exit_sendfile");
        if sf_ok && (NR_SENDFILE as u32) < BITMAP_SIZE as u32 {
            successful_syscalls.push(NR_SENDFILE as u32);
            info!("  Attached: sendfile (opt-in via --enable-rich-sendfile)");
        }
        let sp_ok = try_attach_tracepoint(&mut bpf, "sys_enter_splice", "syscalls", "sys_enter_splice")
            && try_attach_tracepoint(&mut bpf, "sys_exit_splice", "syscalls", "sys_exit_splice");
        if sp_ok && (NR_SPLICE as u32) < BITMAP_SIZE as u32 {
            successful_syscalls.push(NR_SPLICE as u32);
            info!("  Attached: splice (opt-in via --enable-rich-sendfile)");
        }
    }

    let mut tier2_bitmap: Array<_, u32> =
        Array::try_from(bpf.map_mut("TIER2_BITMAP").unwrap())?;

    for nr in successful_syscalls {
        tier2_bitmap.set(nr, 1, 0)?;
    }

    info!("Attaching Layer 1: TTY kprobes...");
    // ⚠️  Kernel 6.8+ changed `tty_write` to VFS `.write_iter` signature:
    //     tty_write(struct kiocb *iocb, struct iov_iter *from)
    //   The BPF code expects the old signature:
    //     (struct tty_struct *tty, const u8 *buf, size_t count)
    //   `pty_write` retains the old signature and is called for PTY writes,
    //   which is what SSH sessions use. For serial consoles, consider
    //   hooking `n_tty_write` instead.
    //   Similarly, `tty_read` → `n_tty_read` for the read path.
    try_attach_kprobe(&mut bpf, "tty_write_probe", "pty_write");
    try_attach_kprobe(&mut bpf, "tty_read_probe", "n_tty_read");
    // kretprobe on n_tty_read: captures the bytes that were actually
    // written into the userspace buffer during the call. Without this
    // attach, only metadata (no `data` field) is emitted for tty_read.
    // Aya's KProbe wrapper handles both kprobe and kretprobe via the
    // `kind` discriminator set by the `#[kretprobe]` macro.
    try_attach_kprobe(&mut bpf, "tty_read_ret_probe", "n_tty_read");

    info!("Attaching TC hooks...");
    if let Err(e) = attach_tc_hooks(&mut bpf) {
        warn!("Failed to attach TC hooks: {}", e);
    }

    info!("Attaching LSM hooks...");
    let btf = Btf::from_sys_fs()?;
    let lsm_hooks = [
        ("task_kill", "task_kill"),
        ("bpf_hook", "bpf"),
        ("ptrace_access_check", "ptrace_access_check"),
        ("file_open", "file_open"),
        ("inode_unlink", "inode_unlink"),
        ("inode_rename", "inode_rename"),
        ("task_fix_setuid", "task_fix_setuid"),
    ];
    for (prog_name, hook_name) in &lsm_hooks {
        if let Err(e) = attach_lsm(&mut bpf, prog_name, hook_name, &btf) {
            warn!("Failed to attach LSM hook {}: {}", hook_name, e);
        } else {
            info!("  Attached LSM: {}", hook_name);
        }
    }

    info!("All BPF programs attached successfully");
    Ok(bpf)
}

fn populate_exclusion_bitmap(bpf: &mut aya::Ebpf) -> Result<()> {
    let mut bitmap: Array<_, u32> =
        Array::try_from(bpf.map_mut("EXCLUSION_BITMAP").unwrap())?;
    for nr in EXCLUDED_SYSCALLS {
        if (*nr as u32) < BITMAP_SIZE as u32 {
            bitmap.set(*nr as u32, 1, 0)?;
        }
    }
    Ok(())
}

fn populate_excluded_ports(bpf: &mut aya::Ebpf, ports: &[u16]) -> Result<()> {
    let mut map: aya::maps::HashMap<_, u16, u8> =
        aya::maps::HashMap::try_from(bpf.map_mut("EXCLUDED_PORTS").unwrap())?;
    for port in ports {
        map.insert(port, &1u8, 0)?;
    }
    Ok(())
}

fn attach_tracepoint(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(prog_name)
        .context(format!("program {} not found", prog_name))?
        .try_into()?;
    program.load()?;
    program.attach(category, name)?;
    Ok(())
}

fn try_attach_tracepoint(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
) -> bool {
    match attach_tracepoint(bpf, prog_name, category, name) {
        Ok(()) => true,
        Err(e) => {
            warn!("Failed to attach tracepoint {}/{}: {}", category, name, e);
            false
        }
    }
}

fn try_attach_kprobe(bpf: &mut aya::Ebpf, prog_name: &str, fn_name: &str) -> bool {
    let result: Result<()> = (|| {
        let program: &mut KProbe = bpf
            .program_mut(prog_name)
            .context(format!("program {} not found", prog_name))?
            .try_into()?;
        program.load()?;
        program.attach(fn_name, 0)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            info!("  Attached kprobe: {}", fn_name);
            true
        }
        Err(e) => {
            warn!("Failed to attach kprobe {}: {}", fn_name, e);
            false
        }
    }
}

fn attach_tc_hooks(bpf: &mut aya::Ebpf) -> Result<()> {
    let interfaces = get_network_interfaces()?;

    // Load TC programs ONCE before the interface loop.
    //
    // # Why load outside the loop?
    //
    // `SchedClassifier::load()` can only be called once per BPF program.
    // If called inside the loop, the first interface succeeds but subsequent
    // interfaces fail with "the program is already loaded" and get skipped.
    // This caused eth0 to miss TC hooks entirely, meaning only loopback
    // traffic (lo) was captured — no real network PACKET events.

    // Add clsact qdisc to all interfaces first.
    // aya's qdisc_add_clsact uses netlink which may fail with "No such file
    // or directory" on some kernel configurations. Fall back to `tc` command.
    for iface in &interfaces {
        if let Err(_) = aya::programs::tc::qdisc_add_clsact(iface) {
            // Fallback: use tc command
            let status = std::process::Command::new("tc")
                .args(["qdisc", "add", "dev", iface, "clsact"])
                .status();
            match status {
                Ok(s) if s.success() => info!("  clsact qdisc added on {} (via tc command)", iface),
                Ok(s) => warn!("tc qdisc add clsact on {}: exit code {:?} (may already exist)", iface, s.code()),
                Err(e) => warn!("tc command failed on {}: {}", iface, e),
            }
        }
    }

    // Ingress: load once, attach to all interfaces.
    // Scoped block to drop the &mut borrow before borrowing for egress.
    {
        let ingress: &mut SchedClassifier = bpf
            .program_mut("tc_ingress")
            .context("tc_ingress program not found")?
            .try_into()?;
        ingress.load()?;

        for iface in &interfaces {
            if let Err(e) = ingress.attach(iface, TcAttachType::Ingress) {
                warn!("TC ingress attach on {}: {}", iface, e);
            } else {
                info!("  TC ingress attached on {}", iface);
            }
        }
    }

    // Egress: load once, attach to all interfaces.
    {
        let egress: &mut SchedClassifier = bpf
            .program_mut("tc_egress")
            .context("tc_egress program not found")?
            .try_into()?;
        egress.load()?;

        for iface in &interfaces {
            if let Err(e) = egress.attach(iface, TcAttachType::Egress) {
                warn!("TC egress attach on {}: {}", iface, e);
            } else {
                info!("  TC egress attached on {}", iface);
            }
        }
    }

    Ok(())
}

fn attach_lsm(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    hook_name: &str,
    btf: &Btf,
) -> Result<()> {
    let program: &mut Lsm = bpf
        .program_mut(prog_name)
        .context(format!("LSM program {} not found", prog_name))?
        .try_into()?;
    program.load(hook_name, btf)?;
    program.attach()?;
    Ok(())
}

fn get_network_interfaces() -> Result<Vec<String>> {
    let mut interfaces = Vec::new();
    let entries = std::fs::read_dir("/sys/class/net")?;
    for entry in entries {
        if let Ok(entry) = entry {
            if let Ok(name) = entry.file_name().into_string() {
                interfaces.push(name);
            }
        }
    }
    Ok(interfaces)
}
