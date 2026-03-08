# Development and Testing


## Build Environment

Development is done on macOS; BPF programs target Linux. Cross-compilation
is required.

```
+------------------+       +----------------------------+
| macOS (host)     |       | QEMU VM (target)           |
|                  |       |                            |
| Rust toolchain   |       | Ubuntu 24.04 + kernel 6.8  |
| cross-compile    |------>| BTF, BPF LSM enabled       |
| target: x86_64-  |  scp  | Bloodhound binary runs     |
| unknown-linux-   |  scp  | with BPF programs loaded   |
| gnu              |       |                            |
+------------------+       +----------------------------+
```


## E2E Test Infrastructure

DECIDED: Automated E2E tests using a QEMU-based pipeline.

```
+----------------+     +------------------+     +------------------+
| Dockerfile     |---->| docker build     |---->| rootfs tarball   |
| (Ubuntu base + |     | (install deps,   |     | (filesystem      |
|  test fixtures)|     |  configure user) |     |  image)          |
+----------------+     +------------------+     +--------+---------+
                                                         |
                                                         v
                                                +--------+---------+
                                                | Create block     |
                                                | device image     |
                                                | (ext4 raw img)   |
                                                +--------+---------+
                                                         |
                                                         v
                                                +--------+---------+
                                                | QEMU VM boot     |
                                                | - mount rootfs   |
                                                | - start sshd     |
                                                | - run bloodhound |
                                                +--------+---------+
                                                         |
                                                         v
                                                +--------+---------+
                                                | Test harness     |
                                                | - expect (PTY)   |
                                                | - interactive SSH|
                                                | - capture stdout |
                                                | - assert events  |
                                                +--------+---------+
```

The test harness:

1. Builds the rootfs from a Dockerfile (Ubuntu base, test user, sshd, fixtures).
2. Converts the Docker filesystem to a raw ext4 block device image.
3. Boots a QEMU VM with the block device as rootfs and Ubuntu 24.04 kernel.
4. Starts Bloodhound inside the VM with stdout redirected to a file.
5. Drives interactive SSH sessions via `expect` (see below).
6. Retrieves the output file via scp.
7. Validates output events against expected patterns and schema.json.

### TTY test requirement

DECIDED: TTY capture (Layer 1: `tty_read` / `tty_write` kprobes) requires a
PTY-allocated interactive session. Non-interactive SSH (`ssh user@host "cmd"`)
does NOT allocate a PTY, so TTY events will not fire.

All E2E tests that verify Layer 1 events MUST use `expect` (or Python
`pexpect`) to drive an interactive SSH session. This ensures:

- PTY is allocated (pts/* device)
- `tty_write` fires on user keystrokes sent to the terminal
- `tty_read` fires on terminal output returned to the user
- auid + pts/* filtering is exercised end-to-end

Non-interactive SSH (`ssh user@host "cmd"`) MAY be used for tests that only
verify Layer 2/3 events (execve, syscalls, etc.), where TTY is not involved.

### Kernel image

DECIDED: Use Ubuntu 24.04 official `linux-image-generic` package. BTF
is included. BPF LSM is enabled via boot parameter:
`lsm=landlock,lockdown,yama,apparmor,bpf`.

### Test communication

DECIDED: SSH for test orchestration, scp for file retrieval. No 9p or
virtio-serial.
