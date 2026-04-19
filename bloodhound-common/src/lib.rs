#![no_std]

// ── Constants ────────────────────────────────────────────────────────────────

pub const MAX_ARGV_SIZE: usize = 4096;
pub const MAX_PATH_SIZE: usize = 4096;
pub const MAX_TTY_DATA: usize = 4096;
pub const MAX_PACKET_SIZE: usize = 4096;
pub const RING_BUFFER_DEFAULT: u32 = 4 * 1024 * 1024; // 4 MB
pub const COMM_SIZE: usize = 16;
pub const MAX_ARGV_COUNT: usize = 128;
pub const SYSCALL_ENTRY_MAP_SIZE: u32 = 10240;
pub const SOCKET_TABLE_SIZE: u32 = 4096;

// ── EventKind ────────────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    // Layer 1: Intent (TTY)
    TtyRead = 0,
    TtyWrite = 1,

    // Layer 2: Tooling (Execution)
    Execve = 2,
    Execveat = 3,

    // Layer 3 Tier 1: Raw syscall
    RawSyscall = 10,

    // Layer 3 Tier 2: Rich extraction
    Openat = 20,
    Read = 21,
    Write = 22,
    Connect = 23,
    Bind = 24,
    Listen = 25,
    Socket = 26,
    Clone = 27,
    Clone3 = 28,
    Chdir = 29,
    Fchdir = 30,
    Unlink = 31,
    Unlinkat = 32,
    Rename = 33,
    Renameat2 = 34,
    Mkdir = 35,
    Mkdirat = 36,
    Rmdir = 37,
    Symlink = 38,
    Symlinkat = 39,
    Link = 40,
    Linkat = 41,
    Chmod = 42,
    Fchmod = 43,
    Fchmodat = 44,
    Chown = 45,
    Fchown = 46,
    Fchownat = 47,
    Truncate = 48,
    Ftruncate = 49,
    Mount = 50,
    Umount2 = 51,
    Sendto = 52,
    Recvfrom = 53,
    Dup = 54,
    Dup2 = 55,
    Dup3 = 56,
    Fcntl = 57,
    Pread64 = 58,
    Pwrite64 = 59,
    Readv = 60,
    Writev = 61,
    Mmap = 62,
    Sendfile = 63,
    Splice = 64,

    // Packet capture (TC)
    PacketIngress = 100,
    PacketEgress = 101,

    // LSM hooks
    LsmFileOpen = 200,
    LsmTaskKill = 201,
    LsmBpf = 202,
    LsmPtraceAccessCheck = 203,
    LsmInodeUnlink = 204,
    LsmInodeRename = 205,
    LsmTaskFixSetuid = 206,
}

impl EventKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::TtyRead),
            1 => Some(Self::TtyWrite),
            2 => Some(Self::Execve),
            3 => Some(Self::Execveat),
            10 => Some(Self::RawSyscall),
            20 => Some(Self::Openat),
            21 => Some(Self::Read),
            22 => Some(Self::Write),
            23 => Some(Self::Connect),
            24 => Some(Self::Bind),
            25 => Some(Self::Listen),
            26 => Some(Self::Socket),
            27 => Some(Self::Clone),
            28 => Some(Self::Clone3),
            29 => Some(Self::Chdir),
            30 => Some(Self::Fchdir),
            31 => Some(Self::Unlink),
            32 => Some(Self::Unlinkat),
            33 => Some(Self::Rename),
            34 => Some(Self::Renameat2),
            35 => Some(Self::Mkdir),
            36 => Some(Self::Mkdirat),
            37 => Some(Self::Rmdir),
            38 => Some(Self::Symlink),
            39 => Some(Self::Symlinkat),
            40 => Some(Self::Link),
            41 => Some(Self::Linkat),
            42 => Some(Self::Chmod),
            43 => Some(Self::Fchmod),
            44 => Some(Self::Fchmodat),
            45 => Some(Self::Chown),
            46 => Some(Self::Fchown),
            47 => Some(Self::Fchownat),
            48 => Some(Self::Truncate),
            49 => Some(Self::Ftruncate),
            50 => Some(Self::Mount),
            51 => Some(Self::Umount2),
            52 => Some(Self::Sendto),
            53 => Some(Self::Recvfrom),
            54 => Some(Self::Dup),
            55 => Some(Self::Dup2),
            56 => Some(Self::Dup3),
            57 => Some(Self::Fcntl),
            58 => Some(Self::Pread64),
            59 => Some(Self::Pwrite64),
            60 => Some(Self::Readv),
            61 => Some(Self::Writev),
            62 => Some(Self::Mmap),
            63 => Some(Self::Sendfile),
            64 => Some(Self::Splice),
            100 => Some(Self::PacketIngress),
            101 => Some(Self::PacketEgress),
            200 => Some(Self::LsmFileOpen),
            201 => Some(Self::LsmTaskKill),
            202 => Some(Self::LsmBpf),
            203 => Some(Self::LsmPtraceAccessCheck),
            204 => Some(Self::LsmInodeUnlink),
            205 => Some(Self::LsmInodeRename),
            206 => Some(Self::LsmTaskFixSetuid),
            _ => None,
        }
    }
}

// ── Event Headers ────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventHeader {
    pub kind: u8,
    pub _pad: [u8; 3],
    pub timestamp_ns: u64,
    pub auid: u32,
    pub sessionid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub comm: [u8; COMM_SIZE],
}

impl EventHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketEventHeader {
    pub kind: u8,
    pub _pad: [u8; 3],
    pub timestamp_ns: u64,
    pub ifindex: u32,
    pub data_len: u32,
}

impl PacketEventHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── Event Payloads ───────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecvePayload {
    pub filename_len: u16,
    pub argv_len: u16,
    pub return_code: i32,
    // Followed by: filename bytes (filename_len), then argv bytes (argv_len)
    // argv is null-separated
}

impl ExecvePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawSyscallPayload {
    pub syscall_nr: u64,
    pub args: [u64; 6],
    pub return_code: i64,
}

impl RawSyscallPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TtyPayload {
    pub data_len: u16,
    pub _pad: [u8; 2],
    // Followed by: data bytes (data_len)
}

impl TtyPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── Tier 2 Rich Payloads ─────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OpenatPayload {
    pub flags: u32,
    pub mode: u32,
    pub filename_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    pub _pad2: [u8; 4],
    /// Device of the underlying inode (kernel `s_dev`, encoded as `MKDEV(major, minor)`).
    /// Zero when the open failed or identity resolution did not succeed.
    pub dev: u64,
    /// Inode number of the opened file. Zero when the open failed or
    /// identity resolution did not succeed.
    pub ino: u64,
    // Followed by: filename bytes
}

impl OpenatPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReadWritePayload {
    pub fd: u32,
    pub fd_type: u8,
    pub _pad: [u8; 3],
    pub requested_size: u64,
    pub return_code: i64,
}

impl ReadWritePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// fd_type constants
pub const FD_TYPE_REGULAR: u8 = 0;
pub const FD_TYPE_PIPE: u8 = 1;
pub const FD_TYPE_SOCKET: u8 = 2;
pub const FD_TYPE_TTY: u8 = 3;
pub const FD_TYPE_OTHER: u8 = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectBindPayload {
    pub family: u16,
    pub port: u16,
    pub addr_v4: u32,
    pub addr_v6: [u8; 16],
    pub return_code: i32,
}

impl ConnectBindPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SocketPayload {
    pub domain: u32,
    pub sock_type: u32,
    pub protocol: u32,
    pub return_code: i32,
}

impl SocketPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ClonePayload {
    pub flags: u64,
    pub return_code: i64,
}

impl ClonePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PathPayload {
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes (path_len)
}

impl PathPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TwoPathPayload {
    pub path1_len: u16,
    pub path2_len: u16,
    pub return_code: i32,
    // Followed by: path1 bytes, then path2 bytes
}

impl TwoPathPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ChmodPayload {
    pub mode: u32,
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes (path_len)
}

impl ChmodPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FchmodPayload {
    pub fd: u32,
    pub mode: u32,
    pub return_code: i32,
}

impl FchmodPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ChownPayload {
    pub uid: u32,
    pub gid: u32,
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl ChownPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FchownPayload {
    pub fd: u32,
    pub uid: u32,
    pub gid: u32,
    pub return_code: i32,
}

impl FchownPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TruncatePayload {
    pub length: u64,
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl TruncatePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FtruncatePayload {
    pub fd: u32,
    pub _pad2: [u8; 4],
    pub length: u64,
    pub return_code: i64,
}

impl FtruncatePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MountPayload {
    pub source_len: u16,
    pub target_len: u16,
    pub fstype_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    pub _pad2: [u8; 4],
    // Followed by: source, target, fstype bytes
}

impl MountPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SendtoRecvfromPayload {
    pub fd: u32,
    pub family: u16,
    pub port: u16,
    pub addr_v4: u32,
    pub addr_v6: [u8; 16],
    pub size: u64,
    pub return_code: i64,
}

impl SendtoRecvfromPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FdPayload {
    pub fd: u32,
    pub return_code: i32,
}

impl FdPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ListenPayload {
    pub fd: u32,
    pub backlog: u32,
    pub return_code: i32,
}

impl ListenPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Umount2Payload {
    pub flags: u32,
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl Umount2Payload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── New Tier 2 Payloads (dup/fcntl, pread/pwrite, readv/writev, mmap, sendfile/splice) ─

/// Payload for `dup`, `dup2`, `dup3`, and `fcntl(F_DUPFD*)` events.
///
/// `oldfd` is the source fd from `args[0]`. `newfd` is the destination fd
/// from the syscall return value (negative on error). `cloexec` reflects
/// whether the new fd has FD_CLOEXEC set: true for `dup3` with `O_CLOEXEC`
/// and for `fcntl(F_DUPFD_CLOEXEC)`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DupPayload {
    pub oldfd: u32,
    pub newfd: i32,
    pub cloexec: u8,
    pub _pad: [u8; 3],
    pub return_code: i64,
}

impl DupPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Payload for `pread64` and `pwrite64` events.
///
/// Mirrors `ReadWritePayload` plus the explicit `offset` argument.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PreadPwritePayload {
    pub fd: u32,
    pub fd_type: u8,
    pub _pad: [u8; 3],
    pub requested_size: u64,
    pub offset: i64,
    pub return_code: i64,
}

impl PreadPwritePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Payload for `readv` and `writev` events.
///
/// `requested_size` is the sum of `iov_len` across the first
/// `MAX_IOV_TRAVERSE` iov entries. If `iov_count > MAX_IOV_TRAVERSE`,
/// `iov_truncated` is 1 and `requested_size` underestimates the true total.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReadvWritevPayload {
    pub fd: u32,
    pub fd_type: u8,
    pub iov_truncated: u8,
    pub _pad: [u8; 2],
    pub iov_count: u32,
    pub _pad2: [u8; 4],
    pub requested_size: u64,
    pub return_code: i64,
}

impl ReadvWritevPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Maximum number of `iovec` entries traversed in BPF for `readv`/`writev`.
///
/// This bound exists for the BPF verifier: each iov entry costs one
/// `bpf_probe_read_user` call, and the verifier rejects unbounded loops.
/// Eight covers the overwhelming majority of real-world vectored I/O.
pub const MAX_IOV_TRAVERSE: u32 = 8;

/// Payload for `mmap` events (file-backed only).
///
/// Anonymous mappings are filtered in BPF and never reach userspace.
/// `dev` and `ino` identify the underlying file via the same fd-table
/// traversal used by `openat`. They are zero when identity resolution
/// failed or the file backing was not resolvable.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MmapPayload {
    pub fd: i32,
    pub prot: u32,
    pub flags: u32,
    pub _pad: [u8; 4],
    pub length: u64,
    pub offset: u64,
    pub dev: u64,
    pub ino: u64,
    pub return_code: i64,
}

impl MmapPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// Payload for `sendfile` and `splice` events (opt-in).
///
/// Both syscalls move data between two fds; this payload surfaces both
/// fds and their classified types alongside the requested and actual
/// transferred byte counts.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SendfileSplicePayload {
    pub in_fd: u32,
    pub out_fd: u32,
    pub in_fd_type: u8,
    pub out_fd_type: u8,
    pub _pad: [u8; 6],
    pub size: u64,
    pub return_code: i64,
}

impl SendfileSplicePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── LSM Payloads ─────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmFileOpenPayload {
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl LsmFileOpenPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmTaskKillPayload {
    pub target_pid: u32,
    pub signal: u32,
    pub return_code: i32,
}

impl LsmTaskKillPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmBpfPayload {
    pub cmd: u32,
    pub return_code: i32,
}

impl LsmBpfPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmPtracePayload {
    pub target_pid: u32,
    pub return_code: i32,
}

impl LsmPtracePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmInodePayload {
    pub path_len: u16,
    pub _pad: [u8; 2],
    pub return_code: i32,
    // Followed by: path bytes
}

impl LsmInodePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmInodeRenamePayload {
    pub old_path_len: u16,
    pub new_path_len: u16,
    pub return_code: i32,
    // Followed by: old_path, new_path bytes
}

impl LsmInodeRenamePayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LsmSetuidPayload {
    pub old_uid: u32,
    pub new_uid: u32,
    pub old_gid: u32,
    pub new_gid: u32,
    pub return_code: i32,
}

impl LsmSetuidPayload {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// ── BPF Entry Map Structs (for enter/exit correlation) ───────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEntry {
    pub header: EventHeader,
    pub filename_len: u16,
    pub argv_len: u16,
    pub filename_buf: [u8; MAX_PATH_SIZE],
    pub argv_buf: [u8; MAX_ARGV_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEntry {
    pub header: EventHeader,
    pub syscall_nr: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RichSyscallEntry {
    pub header: EventHeader,
    pub data: [u8; 256],
    pub data_len: u16,
}

// ── Excluded Syscall Numbers (x86_64) ────────────────────────────────────────

pub const NR_FUTEX: u64 = 202;
pub const NR_CLOCK_GETTIME: u64 = 228;
pub const NR_CLOCK_NANOSLEEP: u64 = 230;
pub const NR_GETTIMEOFDAY: u64 = 96;
pub const NR_NANOSLEEP: u64 = 35;
pub const NR_EPOLL_WAIT: u64 = 232;
pub const NR_EPOLL_PWAIT: u64 = 281;
pub const NR_POLL: u64 = 7;
pub const NR_PPOLL: u64 = 271;
pub const NR_SELECT: u64 = 23;
pub const NR_PSELECT6: u64 = 270;
pub const NR_SCHED_YIELD: u64 = 24;
pub const NR_RESTART_SYSCALL: u64 = 219;

pub const EXCLUDED_SYSCALLS: &[u64] = &[
    NR_FUTEX,
    NR_CLOCK_GETTIME,
    NR_CLOCK_NANOSLEEP,
    NR_GETTIMEOFDAY,
    NR_NANOSLEEP,
    NR_EPOLL_WAIT,
    NR_EPOLL_PWAIT,
    NR_POLL,
    NR_PPOLL,
    NR_SELECT,
    NR_PSELECT6,
    NR_SCHED_YIELD,
    NR_RESTART_SYSCALL,
];

// Tier 2 syscall numbers (x86_64) for dedup bitmap
pub const NR_EXECVE: u64 = 59;
pub const NR_EXECVEAT: u64 = 322;
pub const NR_OPENAT: u64 = 257;
pub const NR_READ: u64 = 0;
pub const NR_WRITE: u64 = 1;
pub const NR_CONNECT: u64 = 42;
pub const NR_BIND: u64 = 49;
pub const NR_LISTEN: u64 = 50;
pub const NR_SOCKET: u64 = 41;
pub const NR_CLONE: u64 = 56;
pub const NR_CLONE3: u64 = 435;
pub const NR_CHDIR: u64 = 80;
pub const NR_FCHDIR: u64 = 81;
pub const NR_UNLINK: u64 = 87;
pub const NR_UNLINKAT: u64 = 263;
pub const NR_RENAME: u64 = 82;
pub const NR_RENAMEAT2: u64 = 316;
pub const NR_MKDIR: u64 = 83;
pub const NR_MKDIRAT: u64 = 258;
pub const NR_RMDIR: u64 = 84;
pub const NR_SYMLINK: u64 = 88;
pub const NR_SYMLINKAT: u64 = 266;
pub const NR_LINK: u64 = 86;
pub const NR_LINKAT: u64 = 265;
pub const NR_CHMOD: u64 = 90;
pub const NR_FCHMOD: u64 = 91;
pub const NR_FCHMODAT: u64 = 268;
pub const NR_CHOWN: u64 = 92;
pub const NR_FCHOWN: u64 = 93;
pub const NR_FCHOWNAT: u64 = 260;
pub const NR_TRUNCATE: u64 = 76;
pub const NR_FTRUNCATE: u64 = 77;
pub const NR_MOUNT: u64 = 165;
pub const NR_UMOUNT2: u64 = 166;
pub const NR_SENDTO: u64 = 44;
pub const NR_RECVFROM: u64 = 45;
pub const NR_DUP: u64 = 32;
pub const NR_DUP2: u64 = 33;
pub const NR_DUP3: u64 = 292;
pub const NR_FCNTL: u64 = 72;
pub const NR_PREAD64: u64 = 17;
pub const NR_PWRITE64: u64 = 18;
pub const NR_READV: u64 = 19;
pub const NR_WRITEV: u64 = 20;
pub const NR_MMAP: u64 = 9;
pub const NR_SENDFILE: u64 = 40;
pub const NR_SPLICE: u64 = 275;

/// `exit_group` — emitted at sys_enter by Tier 1 raw capture because the
/// matching sys_exit tracepoint never fires (the task is gone by then). See
/// `layer3_raw::try_raw_sys_enter` and the `process_exit` contract in
/// `docs/output-schema.md`.
pub const NR_EXIT_GROUP: u64 = 231;

/// `fcntl` `cmd` values that perform fd duplication.
///
/// `F_DUPFD` and `F_DUPFD_CLOEXEC` are the only `fcntl` commands rich-extracted
/// by Bloodhound; all other commands fall through to Tier 1 raw capture.
pub const F_DUPFD: u32 = 0;
pub const F_DUPFD_CLOEXEC: u32 = 1030;

/// `mmap` `flags` bit indicating an anonymous mapping (no file backing).
pub const MAP_ANONYMOUS: u32 = 0x20;

/// `dup3` `flags` bit setting `FD_CLOEXEC` on the new fd.
pub const O_CLOEXEC: u32 = 0o2000000;

pub const TIER2_SYSCALLS: &[u64] = &[
    NR_EXECVE, NR_EXECVEAT, NR_OPENAT, NR_READ, NR_WRITE, NR_CONNECT,
    NR_BIND, NR_LISTEN, NR_SOCKET, NR_CLONE, NR_CLONE3, NR_CHDIR, NR_FCHDIR,
    NR_UNLINK, NR_UNLINKAT, NR_RENAME, NR_RENAMEAT2, NR_MKDIR, NR_MKDIRAT,
    NR_RMDIR, NR_SYMLINK, NR_SYMLINKAT, NR_LINK, NR_LINKAT, NR_CHMOD,
    NR_FCHMOD, NR_FCHMODAT, NR_CHOWN, NR_FCHOWN, NR_FCHOWNAT,
    NR_TRUNCATE, NR_FTRUNCATE, NR_MOUNT, NR_UMOUNT2, NR_SENDTO, NR_RECVFROM,
    NR_DUP, NR_DUP2, NR_DUP3,
    NR_PREAD64, NR_PWRITE64, NR_READV, NR_WRITEV, NR_MMAP,
    // NR_FCNTL is intentionally omitted: rich extraction only fires for the
    // F_DUPFD command family (see `try_enter_fcntl` in `layer3_rich.rs`).
    // All other fcntl commands must remain visible via Tier 1 raw capture.
    //
    // NR_SENDFILE, NR_SPLICE are also intentionally omitted: they are opt-in
    // via `--enable-rich-sendfile` and added to the bitmap at runtime only
    // when the flag is set (see bloodhound::loader).
];

// Bitmap size: 512 entries covers all syscalls on x86_64 (max ~450)
pub const BITMAP_SIZE: usize = 512;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    // ── EventKind: bijective u8 mapping ──────────────────────────────────

    /// Every EventKind variant must survive a u8 roundtrip.
    /// This guarantees the BPF-side kind byte and userspace parser agree.
    #[test]
    fn event_kind_roundtrip_all_variants() {
        let all_variants = [
            EventKind::TtyRead,
            EventKind::TtyWrite,
            EventKind::Execve,
            EventKind::Execveat,
            EventKind::RawSyscall,
            EventKind::Openat,
            EventKind::Read,
            EventKind::Write,
            EventKind::Connect,
            EventKind::Bind,
            EventKind::Listen,
            EventKind::Socket,
            EventKind::Clone,
            EventKind::Clone3,
            EventKind::Chdir,
            EventKind::Fchdir,
            EventKind::Unlink,
            EventKind::Unlinkat,
            EventKind::Rename,
            EventKind::Renameat2,
            EventKind::Mkdir,
            EventKind::Mkdirat,
            EventKind::Rmdir,
            EventKind::Symlink,
            EventKind::Symlinkat,
            EventKind::Link,
            EventKind::Linkat,
            EventKind::Chmod,
            EventKind::Fchmod,
            EventKind::Fchmodat,
            EventKind::Chown,
            EventKind::Fchown,
            EventKind::Fchownat,
            EventKind::Truncate,
            EventKind::Ftruncate,
            EventKind::Mount,
            EventKind::Umount2,
            EventKind::Sendto,
            EventKind::Recvfrom,
            EventKind::Dup,
            EventKind::Dup2,
            EventKind::Dup3,
            EventKind::Fcntl,
            EventKind::Pread64,
            EventKind::Pwrite64,
            EventKind::Readv,
            EventKind::Writev,
            EventKind::Mmap,
            EventKind::Sendfile,
            EventKind::Splice,
            EventKind::PacketIngress,
            EventKind::PacketEgress,
            EventKind::LsmFileOpen,
            EventKind::LsmTaskKill,
            EventKind::LsmBpf,
            EventKind::LsmPtraceAccessCheck,
            EventKind::LsmInodeUnlink,
            EventKind::LsmInodeRename,
            EventKind::LsmTaskFixSetuid,
        ];

        for variant in &all_variants {
            let byte = *variant as u8;
            let recovered = EventKind::from_u8(byte);
            assert_eq!(
                recovered,
                Some(*variant),
                "EventKind::{:?} (u8={}) did not roundtrip",
                variant,
                byte,
            );
        }
    }

    /// Unknown u8 values must return None, not panic.
    #[test]
    fn event_kind_unknown_returns_none() {
        // Test values that are not assigned to any variant
        for byte in [4, 5, 9, 11, 19, 65, 99, 102, 150, 199, 207, 255] {
            assert_eq!(
                EventKind::from_u8(byte),
                None,
                "Expected None for unassigned kind byte {}",
                byte,
            );
        }
    }

    /// All variant discriminants must be unique (no collisions).
    #[test]
    fn event_kind_discriminants_unique() {
        let all_variants = [
            EventKind::TtyRead,
            EventKind::TtyWrite,
            EventKind::Execve,
            EventKind::Execveat,
            EventKind::RawSyscall,
            EventKind::Openat,
            EventKind::Read,
            EventKind::Write,
            EventKind::Connect,
            EventKind::Bind,
            EventKind::Listen,
            EventKind::Socket,
            EventKind::Clone,
            EventKind::Clone3,
            EventKind::Chdir,
            EventKind::Fchdir,
            EventKind::Unlink,
            EventKind::Unlinkat,
            EventKind::Rename,
            EventKind::Renameat2,
            EventKind::Mkdir,
            EventKind::Mkdirat,
            EventKind::Rmdir,
            EventKind::Symlink,
            EventKind::Symlinkat,
            EventKind::Link,
            EventKind::Linkat,
            EventKind::Chmod,
            EventKind::Fchmod,
            EventKind::Fchmodat,
            EventKind::Chown,
            EventKind::Fchown,
            EventKind::Fchownat,
            EventKind::Truncate,
            EventKind::Ftruncate,
            EventKind::Mount,
            EventKind::Umount2,
            EventKind::Sendto,
            EventKind::Recvfrom,
            EventKind::Dup,
            EventKind::Dup2,
            EventKind::Dup3,
            EventKind::Fcntl,
            EventKind::Pread64,
            EventKind::Pwrite64,
            EventKind::Readv,
            EventKind::Writev,
            EventKind::Mmap,
            EventKind::Sendfile,
            EventKind::Splice,
            EventKind::PacketIngress,
            EventKind::PacketEgress,
            EventKind::LsmFileOpen,
            EventKind::LsmTaskKill,
            EventKind::LsmBpf,
            EventKind::LsmPtraceAccessCheck,
            EventKind::LsmInodeUnlink,
            EventKind::LsmInodeRename,
            EventKind::LsmTaskFixSetuid,
        ];
        let mut seen = [false; 256];
        for v in &all_variants {
            let b = *v as u8;
            assert!(!seen[b as usize], "Duplicate discriminant: {}", b);
            seen[b as usize] = true;
        }
    }

    // ── Struct sizes: binary protocol stability ──────────────────────────
    // These sizes are part of the BPF↔userspace wire protocol.
    // If any size changes, the deserializer will produce garbage.

    #[test]
    fn event_header_size_is_stable() {
        // repr(C) layout: kind(1) + _pad(3) + 4 bytes alignment padding
        // + timestamp_ns(8) + auid(4) + sessionid(4)
        // + pid(4) + ppid(4) + comm(16) = 48
        assert_eq!(EventHeader::SIZE, mem::size_of::<EventHeader>());
    }

    #[test]
    fn packet_event_header_size_is_stable() {
        // repr(C) layout: kind(1) + _pad(3) + 4 bytes alignment padding
        // + timestamp_ns(8) + ifindex(4) + data_len(4) = 24
        assert_eq!(PacketEventHeader::SIZE, mem::size_of::<PacketEventHeader>());
    }

    #[test]
    fn payload_sizes_match_mem_size() {
        assert_eq!(ExecvePayload::SIZE, mem::size_of::<ExecvePayload>());
        assert_eq!(RawSyscallPayload::SIZE, mem::size_of::<RawSyscallPayload>());
        assert_eq!(TtyPayload::SIZE, mem::size_of::<TtyPayload>());
        assert_eq!(OpenatPayload::SIZE, mem::size_of::<OpenatPayload>());
        assert_eq!(ReadWritePayload::SIZE, mem::size_of::<ReadWritePayload>());
        assert_eq!(ConnectBindPayload::SIZE, mem::size_of::<ConnectBindPayload>());
        assert_eq!(SocketPayload::SIZE, mem::size_of::<SocketPayload>());
        assert_eq!(ClonePayload::SIZE, mem::size_of::<ClonePayload>());
        assert_eq!(PathPayload::SIZE, mem::size_of::<PathPayload>());
        assert_eq!(TwoPathPayload::SIZE, mem::size_of::<TwoPathPayload>());
        assert_eq!(ChmodPayload::SIZE, mem::size_of::<ChmodPayload>());
        assert_eq!(FchmodPayload::SIZE, mem::size_of::<FchmodPayload>());
        assert_eq!(ChownPayload::SIZE, mem::size_of::<ChownPayload>());
        assert_eq!(FchownPayload::SIZE, mem::size_of::<FchownPayload>());
        assert_eq!(TruncatePayload::SIZE, mem::size_of::<TruncatePayload>());
        assert_eq!(FtruncatePayload::SIZE, mem::size_of::<FtruncatePayload>());
        assert_eq!(MountPayload::SIZE, mem::size_of::<MountPayload>());
        assert_eq!(Umount2Payload::SIZE, mem::size_of::<Umount2Payload>());
        assert_eq!(
            SendtoRecvfromPayload::SIZE,
            mem::size_of::<SendtoRecvfromPayload>()
        );
        assert_eq!(FdPayload::SIZE, mem::size_of::<FdPayload>());
        assert_eq!(ListenPayload::SIZE, mem::size_of::<ListenPayload>());
        assert_eq!(
            LsmFileOpenPayload::SIZE,
            mem::size_of::<LsmFileOpenPayload>()
        );
        assert_eq!(
            LsmTaskKillPayload::SIZE,
            mem::size_of::<LsmTaskKillPayload>()
        );
        assert_eq!(LsmBpfPayload::SIZE, mem::size_of::<LsmBpfPayload>());
        assert_eq!(LsmPtracePayload::SIZE, mem::size_of::<LsmPtracePayload>());
        assert_eq!(LsmInodePayload::SIZE, mem::size_of::<LsmInodePayload>());
        assert_eq!(
            LsmInodeRenamePayload::SIZE,
            mem::size_of::<LsmInodeRenamePayload>()
        );
        assert_eq!(LsmSetuidPayload::SIZE, mem::size_of::<LsmSetuidPayload>());
        assert_eq!(DupPayload::SIZE, mem::size_of::<DupPayload>());
        assert_eq!(PreadPwritePayload::SIZE, mem::size_of::<PreadPwritePayload>());
        assert_eq!(ReadvWritevPayload::SIZE, mem::size_of::<ReadvWritevPayload>());
        assert_eq!(MmapPayload::SIZE, mem::size_of::<MmapPayload>());
        assert_eq!(
            SendfileSplicePayload::SIZE,
            mem::size_of::<SendfileSplicePayload>()
        );
    }

    // ── Syscall metadata correctness ─────────────────────────────────────

    /// Excluded and Tier2 sets must be disjoint.
    /// A syscall cannot be both excluded and handled by rich extraction.
    #[test]
    fn excluded_and_tier2_are_disjoint() {
        for nr in EXCLUDED_SYSCALLS {
            assert!(
                !TIER2_SYSCALLS.contains(nr),
                "Syscall NR {} is in both EXCLUDED and TIER2",
                nr,
            );
        }
    }

    /// All referenced syscall NRs must fit within the bitmap.
    #[test]
    fn all_syscall_nrs_fit_in_bitmap() {
        for nr in EXCLUDED_SYSCALLS.iter().chain(TIER2_SYSCALLS.iter()) {
            assert!(
                (*nr as usize) < BITMAP_SIZE,
                "Syscall NR {} exceeds BITMAP_SIZE {}",
                nr,
                BITMAP_SIZE,
            );
        }
    }

    /// Spot-check a few well-known x86_64 syscall numbers.
    #[test]
    fn well_known_syscall_numbers() {
        assert_eq!(NR_READ, 0);
        assert_eq!(NR_WRITE, 1);
        assert_eq!(NR_OPENAT, 257);
        assert_eq!(NR_EXECVE, 59);
        assert_eq!(NR_CLONE, 56);
        assert_eq!(NR_CONNECT, 42);
        assert_eq!(NR_SOCKET, 41);
        assert_eq!(NR_FUTEX, 202);
    }
}
