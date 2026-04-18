# Bloodhound: Technical Specification

> eBPF-based behavioral tracing daemon for isolated VMs.
> All design decisions have been finalized.


## Primary Goal

Trace ALL user-originated actions and their resulting effects within a VM,
and correlate them as a single unified stream of "user behavior." Memory
overhead is acceptable; completeness of observation is the top priority.

## Overview

Bloodhound is a resident daemon that traces user behavior inside isolated
VMs (QEMU/KVM). It captures every kernel-level event attributable to
the target user -- syscalls, TTY I/O, network packets, and process
lifecycle -- correlates them via `auid`, and emits structured events as
NDJSON to stdout.

```
+---------------------------------------------------------------+
|                      Guest VM (Ubuntu)                         |
|                                                               |
|  +------------+     +--------------------------------------+  |
|  | Target user|---->|            Kernel (eBPF)             |  |
|  | (fixed UID)|     |  +-------+ +------+ +------+ +----+ |  |
|  +------------+     |  |Layer 1| |Layer2| |Layer3| | TC | |  |
|                     |  | (TTY) | |(exec)| |(sys) | |(pkt)| |  |
|                     |  +---+---+ +--+---+ +--+---+ +--+-+ |  |
|                     |      |        |        |        |    |  |
|                     |  [auid filter: early return]  [port] |  |
|                     |      |        |        |      [excl] |  |
|                     |      +--------+--------+--------+    |  |
|                     |               |                      |  |
|                     |         ring buffer   LSM hooks      |  |
|                     +---------------|---+-----------+       |  |
|                                     |                       |  |
|                     +---------------v-----------------------+  |
|                     |       Bloodhound (userspace)          |  |
|                     |  +----------+  +--------------------+ |  |
|                     |  | 5-tuple  |  | /proc enrichment   | |  |
|                     |  | pkt join |  | + JSON serialize   | |  |
|                     |  +----------+  +--------------------+ |  |
|                     |  drop counter poll -> stderr          |  |
|                     |               |                       |  |
|                     +---------------v-----------------------+  |
|                                     |                          |
|                                  stdout (NDJSON)               |
|                           (future: virtio-serial)              |
+---------------------------------------------------------------+
```


## Environment and Constraints

| Item                | Status  | Value                                          |
|---------------------|---------|-------------------------------------------------|
| Host platform       | DECIDED | QEMU/KVM guest VM                               |
| OS                  | DECIDED | Ubuntu (LTS)                                    |
| Kernel version      | DECIDED | 6.8 (Ubuntu 24.04 LTS); pinned per VM image     |
| BTF support         | DECIDED | Required (CONFIG_DEBUG_INFO_BTF=y)              |
| BPF LSM support     | DECIDED | Required (boot param: lsm=...,bpf)             |
| Language            | DECIDED | Rust (Aya framework)                            |
| BPF-to-user pipe    | DECIDED | BPF ring buffer (BPF_MAP_TYPE_RINGBUF)          |
| Output destination  | DECIDED | stdout (future: virtio-serial)                  |
| Target user privs   | DECIDED | root with restricted capabilities               |
| Target user model   | DECIDED | Single fixed user per VM                        |
| Filtering strategy  | DECIDED | auid + sessionid (audit login UID + session ID) |
| Performance budget  | DECIDED | Qualitative: must not degrade user UX            |
| Output schema       | DECIDED | BehaviorEvent (see docs/schema.json)             |


## Known Limitations

| Limitation              | Scope    | Notes                                           |
|-------------------------|----------|-------------------------------------------------|
| io_uring I/O coverage   | DEFERRED | I/O submitted via io_uring rings bypasses syscall tracepoints. `io_uring_setup`/`enter`/`register` remain visible via Tier 1 raw_syscalls; submitted operations are not. See `docs/tracing.md` §Known Limitations §io_uring observation gap. |
| Protocol semantic parse | OUT OF SCOPE | DNS, TLS SNI, HTTP, etc. are emitted as raw packet bytes; downstream consumers parse. See `docs/tracing.md` §Protocol semantic extraction is out of scope. |


## Detailed Specifications

| Document                                           | Contents                              |
|----------------------------------------------------|---------------------------------------|
| [docs/filtering.md](docs/filtering.md)             | auid/sessionid filtering, target injection |
| [docs/tracing.md](docs/tracing.md)                 | 3-layer model, TTY, execve, syscalls, TC  |
| [docs/tamper-resistance.md](docs/tamper-resistance.md) | CAP restrictions, LSM hooks        |
| [docs/data-pipeline.md](docs/data-pipeline.md)     | Ring buffer, event format, timestamps |
| [docs/output-schema.md](docs/output-schema.md)     | BehaviorEvent JSON schema             |
| [docs/userspace.md](docs/userspace.md)             | Userspace architecture                |
| [docs/lifecycle.md](docs/lifecycle.md)             | Startup, shutdown, crash recovery, scope |
| [docs/testing.md](docs/testing.md)                 | Build environment, E2E test pipeline  |


## Technology Stack

| Component          | Choice          | Notes                              |
|--------------------|-----------------|------------------------------------|
| Language (BPF)     | Rust (no_std)   | Via aya-bpf                        |
| Language (user)    | Rust            | Via aya + tokio                    |
| BPF framework      | Aya             | Pure Rust, CO-RE support           |
| Async runtime      | tokio           | Ring buffer polling                |
| Kernel features    | BTF, BPF LSM   | Must be enabled in VM image        |
| Min kernel version | 6.8             | Ubuntu 24.04 LTS                   |


## Implementation Roadmap

```
Phase 1: Foundation
  +-- Project scaffold (Aya + Rust workspace)
  +-- auid/sessionid reading from task_struct (shared BPF logic)
  +-- Layer 2: execve tracing (simplest, validates filtering)
  +-- Userspace: ring buffer consumer + NDJSON output

Phase 2: Core Tracing
  +-- Layer 3: raw_syscalls generic capture + rich extraction
  +-- Layer 3: clone/clone3 process tree tracking
  +-- Layer 1: TTY capture (kprobe, raw bytes to ring buffer)
  +-- Userspace: /proc enrichment pipeline

Phase 3: Network + Tamper Resistance
  +-- Packet capture: TC hooks (all interfaces, full payload)
  +-- Userspace: socket-to-packet correlation (4096-entry table)
  +-- LSM hooks: 7 hooks (defense + event emission)
  +-- Daemon identification: PID + bpf_d_path

Phase 4: Integration
  +-- End-to-end testing in VM environment (Ubuntu 24.04, kernel 6.8)
  +-- Performance profiling and tuning
  +-- Output validation against schema.json
```


## Revision Log

| Date       | Change                                              |
|------------|-----------------------------------------------------|
| 2026-02-25 | Initial specification drafted from design discussion |
| 2026-02-25 | Added schema.json integration (BehaviorEvent output) |
| 2026-02-25 | Added sessionid to filtering; clarified scope boundary |
| 2026-02-25 | Documented Layer 1 justification (from original design doc) |
| 2026-02-25 | Decided timestamp strategy: bpf_ktime_get_real_ns() |
| 2026-02-25 | Decided proc field strategy: userspace /proc enrichment |
| 2026-02-25 | Added PACKET capture via TC hooks                    |
| 2026-02-25 | Decided LSM events: layer=behavior, dual defense+observe |
| 2026-02-25 | Non-interactive SSH declared out of scope             |
| 2026-02-25 | Decided read/write: metadata only, no buffer content |
| 2026-02-25 | Decided argv: per-CPU map scratch buffer (~4KB)      |
| 2026-02-25 | Added dev/test environment: QEMU E2E pipeline        |
| 2026-02-25 | Decided auid = uid (pam_loginuid); startup via --uid |
| 2026-02-25 | Decided TTY: both tty_read + tty_write from start    |
| 2026-02-25 | Decided TTY data encoding: Base64 in args.data       |
| 2026-02-25 | Decided TC port exclusion: --exclude-ports, default 22 |
| 2026-02-25 | Decided overflow: drop + BPF global drop counter     |
| 2026-02-25 | Decided event.type SYSCALL/KPROBE: reserved for future |
| 2026-02-25 | Added daemon lifecycle: startup, shutdown, crash recovery |
| 2026-02-25 | Decided enter/exit correlation for return_code       |
| 2026-02-25 | Decided per-CPU array map for argv/filename          |
| 2026-02-25 | Decided operational logs: stderr                     |
| 2026-02-25 | Decided TTY filter: auid + pts/* device check        |
| 2026-02-26 | Added fd type classification for read/write          |
| 2026-02-26 | Added chdir/fchdir to Layer 3 syscall list           |
| 2026-02-26 | Added CAP_SYS_TIME and CAP_SYS_MODULE to drop list  |
| 2026-02-26 | Decided E2E output: file redirect + scp retrieval    |
| 2026-02-26 | Decided crash recovery: systemd Restart=always       |
| 2026-02-26 | Decided ring buffer size: configurable, default 4MB  |
| 2026-02-26 | Decided nohup processes: continue tracing after logout |
| 2026-02-26 | Decided TTY privacy: capture passwords as-is         |
| 2026-02-26 | Split spec into docs/ directory by concern           |
| 2026-02-26 | Decided E2E TTY test: expect for interactive SSH (PTY required) |
| 2026-04-18 | Codified protocol semantic extraction (DNS/TLS/HTTP) as downstream responsibility |
| 2026-04-18 | Documented io_uring as known observation blind spot                |
