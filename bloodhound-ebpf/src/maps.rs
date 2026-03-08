#![allow(unused)]
use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
};
use bloodhound_common::*;

// ── Ring Buffer ──────────────────────────────────────────────────────────────

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUFFER_DEFAULT, 0);

// ── Syscall Entry Maps (enter/exit correlation) ──────────────────────────────

/// Keyed by pid_tgid (u64). Stores execve entry data for sys_exit correlation.
#[map]
pub static EXECVE_ENTRY_MAP: HashMap<u64, ExecveEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, 0);

/// Keyed by pid_tgid (u64). Stores raw syscall entry data.
#[map]
pub static SYSCALL_ENTRY_MAP: HashMap<u64, SyscallEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, 0);

/// Keyed by pid_tgid (u64). Stores rich syscall entry data.
#[map]
pub static RICH_ENTRY_MAP: HashMap<u64, RichSyscallEntry> =
    HashMap::with_max_entries(SYSCALL_ENTRY_MAP_SIZE, 0);

// ── Per-CPU Scratch Buffers ──────────────────────────────────────────────────

/// Scratch buffer for reading variable-length data in BPF programs.
/// Slot allocation:
///   Index 0 = filename buffer (used by layer2_exec read_filename)
///   Index 1 = argv buffer (used by layer2_exec read_argv, accumulated output)
///   Index 2 = TTY data buffer (used by layer1_tty)
///   Index 3 = temp buffer for read_argv (BPF verifier workaround:
///             each arg is read into slot 3 at offset 0, then copied to slot 1
///             at a variable offset, because the verifier rejects variable-offset
///             helper calls directly into slot 1)
#[repr(C)]
pub struct ScratchBuf {
    pub buf: [u8; MAX_PATH_SIZE],
}

#[map]
pub static SCRATCH_BUF: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(4, 0);

/// Larger assembly buffer for constructing events with variable-length data.
/// Used by execve (header + payload + filename + argv can exceed 4KB).
pub const ASSEMBLY_BUF_SIZE: usize = 2 * MAX_PATH_SIZE + 256; // ~8.5 KB

#[repr(C)]
pub struct AssemblyBuf {
    pub buf: [u8; ASSEMBLY_BUF_SIZE],
}

#[map]
pub static ASSEMBLY_BUF: PerCpuArray<AssemblyBuf> = PerCpuArray::with_max_entries(1, 0);

/// Scratch buffer for constructing SyscallEntry without hitting BPF stack limit
#[map]
pub static SYSCALL_TMP_BUF: PerCpuArray<RichSyscallEntry> = PerCpuArray::with_max_entries(1, 0);

/// Scratch buffer for constructing ExecveEntry without hitting BPF stack limit
#[map]
pub static EXECVE_TMP_BUF: PerCpuArray<ExecveEntry> = PerCpuArray::with_max_entries(1, 0);

// ── Bitmaps ──────────────────────────────────────────────────────────────────

/// Exclusion bitmap: syscall NR → 1 means excluded from Tier 1
#[map]
pub static EXCLUSION_BITMAP: Array<u32> = Array::with_max_entries(BITMAP_SIZE as u32, 0);

/// Tier 2 bitmap: syscall NR → 1 means handled by Tier 2 (skip in Tier 1)
#[map]
pub static TIER2_BITMAP: Array<u32> = Array::with_max_entries(BITMAP_SIZE as u32, 0);

// ── TC Port Exclusion ────────────────────────────────────────────────────────

/// Port exclusion map: port → 1 means excluded from packet capture
#[map]
pub static EXCLUDED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

// ── Socket Table (BPF side, for secondary lookup) ────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketInfo {
    pub pid: u32,
    pub auid: u32,
    pub comm: [u8; COMM_SIZE],
}

/// Keyed by a hash of the 5-tuple. Populated by connect/bind handlers.
#[map]
pub static SOCKET_TABLE: HashMap<u64, SocketInfo> =
    HashMap::with_max_entries(SOCKET_TABLE_SIZE, 0);

// ── Daemon Path (for LSM hooks) ─────────────────────────────────────────────

#[repr(C)]
pub struct DaemonPath {
    pub len: u16,
    pub path: [u8; 256],
}

#[map]
pub static DAEMON_PATH: Array<DaemonPath> = Array::with_max_entries(1, 0);
