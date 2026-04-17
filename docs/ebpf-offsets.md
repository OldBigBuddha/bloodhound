# eBPF `task_struct` Field Access

Bloodhound reads kernel `task_struct` fields (`loginuid`, `sessionid`,
`tgid`, `pid`) to identify and filter traced processes. These fields
are accessed via typed struct definitions in `bloodhound-ebpf/src/vmlinux.rs`.

## How It Works

The `vmlinux.rs` module defines a minimal `task_struct` with only the
fields bloodhound accesses:

```rust
#[repr(C)]
pub struct task_struct {
    _pad0: [u8; 0x9a0],         // padding → pid
    pub pid: i32,                // offset 0x9a0
    pub tgid: i32,               // offset 0x9a4
    _pad1: [u8; 0xc88 - 0x9a8], // padding → loginuid
    pub loginuid: kuid_t,        // offset 0xc88
    pub sessionid: u32,          // offset 0xc8c
}
```

Field access uses `core::ptr::addr_of!` to compute offsets from the
struct layout, then `bpf_probe_read_kernel` to safely read the value:

```rust
let task_ptr = bpf_get_current_task() as *const task_struct;
let loginuid_ptr = core::ptr::addr_of!((*task_ptr).loginuid);
let auid = bpf_probe_read_kernel(loginuid_ptr)
    .map(|kuid| kuid.val)
    .unwrap_or(u32::MAX);
```

## CO-RE Status

> **Note:** As of 2026-04, the Rust compiler does not emit
> `preserve_access_index` BTF relocation markers. The field offsets
> are fixed at compile time to the target kernel. When rustc gains
> CO-RE support, the existing code will work as-is — only a recompile
> is needed.

## Current Offsets (kernel `6.8.0-49-generic`, Ubuntu 22.04 HWE)

| Field       | Byte Offset | Hex    | Source File      | Used For            |
|-------------|-------------|--------|------------------|---------------------|
| `pid`       | 2464        | 0x9a0  | `vmlinux.rs`     | (reference only)    |
| `tgid`      | 2468        | 0x9a4  | `vmlinux.rs`     | LSM target PID check|
| `loginuid`  | 3208        | 0xc88  | `vmlinux.rs`     | `should_trace()`    |
| `sessionid` | 3212        | 0xc8c  | `vmlinux.rs`     | Event header        |

## How to Verify Offsets

### Method 1: BTF dump on the target VM (recommended)

SSH into the VM and run:

```bash
python3 << 'EOF'
import struct

with open('/sys/kernel/btf/vmlinux', 'rb') as f:
    data = f.read()

magic, version, flags, hdr_len = struct.unpack_from('<HBBI', data, 0)
type_off, type_len, str_off, str_len = struct.unpack_from('<IIII', data, 8)
str_data = data[hdr_len + str_off : hdr_len + str_off + str_len]
type_data = data[hdr_len + type_off : hdr_len + type_off + type_len]

def get_str(off):
    end = str_data.index(b'\x00', off)
    return str_data[off:end].decode()

target_strs = {}
idx = 0
while idx < len(str_data):
    null_pos = str_data.find(b'\x00', idx)
    if null_pos == -1: break
    s = str_data[idx:null_pos].decode('utf-8', errors='replace')
    if s in ('pid', 'tgid', 'task_struct', 'loginuid', 'sessionid'):
        target_strs[s] = idx
    idx = null_pos + 1

BTF_KIND_STRUCT = 4
pos = 0
type_id = 1
while pos < len(type_data):
    name_off, info, size_or_type = struct.unpack_from('<III', type_data, pos)
    kind = (info >> 24) & 0x1f
    vlen = info & 0xffff
    pos += 12
    is_ts = (kind == BTF_KIND_STRUCT and name_off == target_strs.get('task_struct', -1))
    if kind in (BTF_KIND_STRUCT, 3):
        for i in range(vlen):
            m_name_off, m_type, m_offset = struct.unpack_from('<III', type_data, pos)
            if is_ts:
                mname = get_str(m_name_off)
                if mname in ('pid','tgid','loginuid','sessionid'):
                    print(f'{mname}: offset=0x{m_offset//8:x} ({m_offset//8})')
            pos += 12
    elif kind == 1: pos += 4
    elif kind == 7: pos += 12
    elif kind == 10:
        for _ in range(vlen): pos += 8
    elif kind == 11: pos += 4
    elif kind == 12:
        for _ in range(vlen): pos += 12
    elif kind == 14: pos += 4
    elif kind == 16:
        for _ in range(vlen): pos += 12
    type_id += 1
EOF
```

### Method 2: `pahole` (if installed)

```bash
pahole -C task_struct /sys/kernel/btf/vmlinux | grep -E 'pid|tgid|loginuid|sessionid'
```

> **Note:** `pahole` is provided by the `dwarves` package (`apt install dwarves`).

## ⚠️  Critical Pitfall: Host ≠ VM Kernel

The **build host** (e.g., WSL2 `6.6.87.2-microsoft-standard`) and the
**target VM** (e.g., `6.8.0-49-generic`) run **different kernels** with
**different `task_struct` layouts**.

Running `pahole` on the host gives host offsets, which are WRONG for the VM:

| Field  | Host (WSL2 6.6) | VM (6.8 HWE)  |
|--------|-----------------|----------------|
| `tgid` | 0x974 (2420)    | 0x9a4 (2468)   |

**Always run the verification script on the target VM**, not the build host.

If the wrong offset is used:
- `loginuid`: `should_trace()` reads garbage → returns `false` → **0 events**
- `tgid`: LSM `task_kill` reads garbage → never matches `DAEMON_PID` → **kill not blocked**

## When to Re-verify

Re-run the offset verification script whenever:
1. The VM kernel is upgraded (even minor patch versions can change layout)
2. Kernel config changes (e.g., enabling/disabling `CONFIG_AUDIT`)
3. Moving to a different distribution or kernel branch

Then update the struct definition in `bloodhound-ebpf/src/vmlinux.rs`.

## DAC vs LSM Permission Ordering

Linux `check_kill_permission()` checks standard Unix permissions (DAC)
**before** calling the LSM `security_task_kill()` hook:

```c
// kernel/signal.c — simplified
int check_kill_permission(int sig, struct task_struct *t) {
    if (!kill_ok_by_cred(t))
        return -EPERM;          // ← DAC blocks here
    return security_task_kill(t, ...);  // ← LSM only runs if DAC allows
}
```

This means:
- testuser (uid 1000) → root daemon: DAC returns `-EPERM`, **LSM never fires**
- If testuser had `CAP_KILL`: DAC allows, **LSM would fire and block**

The LSM hook is a **secondary defense layer** — it blocks kills that bypass
DAC (e.g., via capabilities or setuid binaries). Both layers work together
to protect the daemon.
