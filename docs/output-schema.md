# Output Schema: BehaviorEvent

The output schema is defined in `schema.json`. All events emitted by
Bloodhound conform to this structure.


## Structure Overview

```
BehaviorEvent
|
+-- header (REQUIRED)
|   +-- timestamp    : f64    (seconds since epoch)
|   +-- auid         : u32    (audit login UID)
|   +-- sessionid    : u32    (audit session ID)
|   +-- pid          : u32
|   +-- ppid         : u32    (optional in schema, but always populated)
|   +-- comm         : string (max 16 bytes)
|
+-- event (REQUIRED)
|   +-- type         : enum [SYSCALL, TTY, PACKET, KPROBE, TRACEPOINT, LSM]
|   +-- name         : string (hook point name, e.g. "openat", "tty_read")
|   +-- layer        : enum [intent, tooling, behavior]
|
+-- proc (OPTIONAL)
|   +-- main_executable : string (absolute path)
|   +-- cwd             : string
|   +-- tty             : string (device path)
|
+-- args (OPTIONAL, additionalProperties: true)
|   +-- filename : string
|   +-- argv     : [string]
|   +-- flags    : [string]   (human-readable, e.g. ["O_RDONLY", "O_SYNC"])
|   +-- data     : string     (raw TTY data, Base64 encoded)
|   +-- fd_type  : string     (regular, pipe, socket, tty, other)
|   +-- dev      : u64        (openat/mmap: encoded MKDEV(major, minor); omitted when 0)
|   +-- ino      : u64        (openat/mmap: inode number; omitted when 0)
|   +-- oldfd    : u32        (dup/dup2/dup3/fcntl-DUPFD: source fd)
|   +-- newfd    : i32        (dup family: destination fd, == return value)
|   +-- cloexec  : bool       (dup3 with O_CLOEXEC, fcntl(F_DUPFD_CLOEXEC))
|   +-- offset   : i64        (pread64/pwrite64: file offset; mmap: file offset)
|   +-- iov_count   : u32     (readv/writev: caller-supplied iov array length)
|   +-- iov_truncated : bool  (readv/writev: true ⇒ args.size is a lower bound)
|   +-- prot     : [string]   (mmap: ["PROT_READ", "PROT_WRITE", "PROT_EXEC"])
|   +-- length   : u64        (mmap: requested mapping length in bytes)
|   +-- in_fd, out_fd, in_fd_type, out_fd_type, size : sendfile/splice
|   +-- ...      : (extensible per event type)
|
+-- return_code (OPTIONAL) : i32
```


## Layer-to-Event-Type Mapping

| Layer    | event.type   | event.name examples                    |
|----------|--------------|----------------------------------------|
| intent   | TTY          | tty_read, tty_write                    |
| tooling  | TRACEPOINT   | execve, execveat                       |
| behavior | TRACEPOINT   | openat, read, write, connect, mkdir... |
| behavior | SYSCALL      | (Tier 1 raw: syscall NR as name)       |
| behavior | PACKET       | ingress, egress                        |
| behavior | LSM          | file_open, task_kill, bpf, ...         |


## Implementation Notes

### proc.main_executable and proc.cwd

These fields cannot be reliably obtained from within tracepoint BPF programs.
`bpf_d_path()` is only available in LSM and sleepable program types.

DECIDED approach: populate `proc` fields in userspace by reading
`/proc/<pid>/exe` and `/proc/<pid>/cwd` upon event receipt. For short-lived
processes, this is best-effort (the process may have exited). The `proc`
section is optional in the schema specifically to accommodate this.

### event.type PACKET

DECIDED: In scope. Raw packet capture via TC hooks. See
[tracing.md](tracing.md) for design details. PACKET events use
`event.layer = "behavior"`. `event.name` is `"ingress"` or `"egress"`.

### event.type LSM

DECIDED: LSM events use `event.layer = "behavior"`. LSM hooks both block
operations and emit BehaviorEvents, recording tamper attempts as
observable events.

### event.type SYSCALL

DECIDED: Used for Tier 1 raw_syscalls events. These carry `syscall_nr`
(integer) and `raw_args` (array of 6 integers) in `args`. The
`event.name` is the syscall number as a string (e.g., "83" for mkdir).
`event.layer` is always `"behavior"`.

### event.type KPROBE

DECIDED: Reserved for future use. Not used in the current design. Kept
in the schema for forward compatibility.
