# Bloodhound Build Guide

## Docker Build (`Dockerfile.build`)

The production binary is built inside Docker for reproducibility:

```bash
cd e2e && bash scripts/deploy.sh          # build + deploy to VM
cd e2e && bash scripts/deploy.sh --no-cache  # force full rebuild
```

### Architecture

```
Dockerfile.build (multi-stage)
├── Stage 1: toolchain (Ubuntu 24.04 + Rust nightly + bpf-linker)
├── Stage 2: build
│   ├── cargo fetch --locked        # resolve workspace
│   ├── aya_build::build_ebpf()     # cross-compile eBPF → bpfel-unknown-none (via build.rs)
│   └── cargo build --package bloodhound --release --target x86_64-unknown-linux-musl
└── Stage 3: output (scratch → /bloodhound)
```

### Key Points

1. **eBPF code is compiled by `build.rs`** via `aya_build::build_ebpf()`, then embedded in the userspace binary via `include_bytes_aligned!`. The eBPF bytecode file lives at `$OUT_DIR/bloodhound-ebpf/bpfel-unknown-none/release/bloodhound-ebpf`.

2. **All workspace members must be present in Dockerfile.build**, even if only `bloodhound` is built. `cargo fetch --locked` resolves the entire workspace, so missing members cause a silent failure when Docker layer cache is present (the cached layer from a previous successful build is served, masking the error).

3. **`--no-cache` is required** when you suspect stale binaries. Docker layer cache hashes are based on the `COPY` context — if a file outside the copied directories changes (e.g., `Cargo.lock` changes without source changes), the build step may be cached.

4. **`build.rs` silently ignores eBPF build failures** (`eprintln!` on error, no `panic!`). If `aya_build::build_ebpf()` fails, the binary uses whatever bytecode was previously in `OUT_DIR` — potentially stale or missing entirely (compile error).

## E2E VM Setup

### Kernel Modules

The VM boots with `e2e/vmlinuz` (kernel `6.8.0-49-generic` from Ubuntu 22.04 HWE). The rootfs is built from `e2e/Dockerfile` (Ubuntu 24.04).

**Critical:** The kernel modules package must match the kernel's vermagic exactly:
- Kernel: `6.8.0-49-generic #49~22.04.1-Ubuntu` (22.04 HWE)
- Modules: `linux-modules-6.8.0-49-generic=6.8.0-49.49~22.04.1` (from `jammy-updates`)

The Ubuntu 24.04 native modules (`6.8.0-49.49`) have different modversions CRCs → `modprobe` fails with "Invalid argument".

### TC Hooks (sch_ingress)

TC hooks require `sch_ingress` kernel module for `clsact` qdisc. The systemd service includes:
```
ExecStartPre=-/sbin/modprobe sch_ingress
ExecStartPre=-/bin/sh -c 'for iface in $(ls /sys/class/net); do tc qdisc add dev $iface clsact 2>/dev/null; done'
```

## BPF Verifier Gotchas

### `bpf_skb_load_bytes` zero-size read
aya's `SkBuff::load_bytes()` computes length at runtime → verifier sees possible zero in the length arg → rejected. Use raw `bpf_skb_load_bytes` with a **compile-time constant** for the length parameter.

### `SchedClassifier::load()` is one-shot
`load()` can only be called once per program. Call it **outside** any per-interface loop, then `attach()` to each interface.

## `task_struct` Hardcoded Offsets

The eBPF code reads `task_struct` fields (loginuid, sessionid, tgid) using hardcoded byte offsets. These offsets are **kernel-version-specific**.

> **⚠️ Critical:** The build host (WSL2) and target VM run **different kernels** with different `task_struct` layouts. Always verify offsets on the **target VM kernel**, never on the host.

See [ebpf-offsets.md](ebpf-offsets.md) for the full offset table, verification script, and troubleshooting guide.
