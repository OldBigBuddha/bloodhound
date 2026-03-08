# bloodhound-common

Shared type definitions between `bloodhound-ebpf` (kernel) and `bloodhound` (userspace).

## Overview

This crate defines the binary wire format for all events passed through the BPF ring buffer. Both the eBPF programs and the userspace daemon depend on these types to ensure consistent serialization.

## Key Types

| Type | Description |
|------|-------------|
| `EventHeader` | Common header: timestamp, auid, sessionid, pid, comm |
| `EventKind` | Enum discriminant for all event types |
| `ExecvePayload` | execve/execveat: argc, return_code, filename + argv |
| `SyscallPayload` | Raw syscall: nr, return_code |
| `TtyPayload` | TTY read/write: device, data length, raw bytes |
| `PacketPayload` | Network packet: direction, protocol, length, header bytes |
| `OpenatPayload` | openat: flags, mode, filename |
| `ReadWritePayload` | read/write: fd, count, fd_type |
| `ConnectPayload` | connect: addr_family, port, address |
| `Lsm*Payload` | LSM event payloads (task_kill, bpf, ptrace, etc.) |

## Feature Flags

| Feature | Description |
|---------|-------------|
| `user` | Enables userspace-only dependencies (e.g., `serde` derives) |

Without the `user` feature, the crate compiles in `no_std` mode for the eBPF target.

## Constants

Includes syscall number constants (`NR_READ`, `NR_WRITE`, etc.), exclusion bitmaps, and shared configuration values like `BITMAP_SIZE`.
