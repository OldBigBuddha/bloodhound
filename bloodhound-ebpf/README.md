# bloodhound-ebpf

eBPF programs that run inside the kernel to trace user behavior. Compiled as `no_std` Rust targeting `bpfel-unknown-none` via the [Aya](https://aya-rs.dev/) framework.

## Program Layers

```mermaid
graph TD
    subgraph "Layer 1 — TTY"
        TTY["layer1_tty.rs<br/>kprobe: pty_write, n_tty_read"]
    end
    subgraph "Layer 2 — Exec"
        EXEC["layer2_exec.rs<br/>tracepoint: execve, execveat"]
    end
    subgraph "Layer 3 — Syscalls"
        RAW["layer3_raw.rs<br/>raw_syscalls: sys_enter/exit"]
        RICH["layer3_rich.rs<br/>30+ rich syscall extractors"]
    end
    subgraph "Packet Capture"
        TC["packet_tc.rs<br/>TC sched_cls: ingress/egress"]
    end
    subgraph "Tamper Resistance"
        LSM["lsm_hooks.rs<br/>7 LSM hooks"]
    end
    subgraph "Shared"
        FILTER["filter.rs<br/>auid filtering"]
        MAPS["maps.rs<br/>Ring buffer, per-CPU maps"]
        HELPERS["helpers.rs<br/>Event emission"]
    end

    TTY & EXEC & RAW & RICH & TC & LSM --> FILTER
    FILTER --> MAPS
    MAPS --> HELPERS
```

## Modules

| Module | Hook Type | Description |
|--------|-----------|-------------|
| `layer1_tty.rs` | kprobe | `pty_write` / `n_tty_read` — raw terminal I/O capture |
| `layer2_exec.rs` | tracepoint | `execve` / `execveat` — process execution with argv |
| `layer3_raw.rs` | tracepoint | `raw_syscalls` — generic syscall number + return code |
| `layer3_rich.rs` | tracepoint | 30+ syscall-specific extractors (openat, read, write, connect, bind, mkdir, etc.) |
| `packet_tc.rs` | sched_cls | TC ingress/egress — Ethernet header + first 34 bytes |
| `lsm_hooks.rs` | LSM | 7 hooks: task_kill, bpf, ptrace, file_open, inode_unlink, inode_rename, task_fix_setuid |
| `filter.rs` | — | `should_trace()` — auid-based event filtering |
| `maps.rs` | — | BPF map definitions (ring buffer, per-CPU arrays, hash maps) |
| `helpers.rs` | — | `emit_event()`, `bpf_memcpy()`, drop counter |

## Kernel Struct Offsets

This crate uses hardcoded `task_struct` byte offsets. See [docs/ebpf-offsets.md](../docs/ebpf-offsets.md) for the offset table and verification procedure.

> ⚠️ Always verify offsets on the **target VM kernel**, not the build host.
