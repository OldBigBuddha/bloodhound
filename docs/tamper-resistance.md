# Tamper Resistance

Defense is implemented in two complementary layers: capability restriction
(primary) and BPF LSM hooks (secondary, defense in depth).


## Capability Restriction (Primary Defense)

The target user has root UID but restricted Linux capabilities. This is
the primary defense mechanism.

| Capability to DROP   | Effect                                         |
|----------------------|------------------------------------------------|
| CAP_BPF              | Cannot load BPF programs                       |
| CAP_PERFMON          | Cannot attach BPF to perf events               |
| CAP_SYS_PTRACE       | Cannot ptrace the daemon                       |
| CAP_SYS_BOOT         | Cannot reboot to bypass monitoring             |
| CAP_SYS_ADMIN        | Broad restriction on privileged operations     |
| CAP_SYS_TIME         | Cannot change system clock (protects timestamps)|
| CAP_SYS_MODULE       | Cannot load kernel modules (protects BPF hooks)|

DECIDED: The above list is the recommended set. [ACCEPTANCE] Actual
enforcement is the operator's responsibility during VM provisioning.
Some deployment contexts may need capabilities that conflict with
tamper resistance (e.g., CAP_NET_RAW for network exercises).


## BPF LSM Hooks (Defense in Depth)

Even with CAP restrictions, LSM hooks provide a second layer of protection.

LSM hooks serve a dual purpose:
1. **Defense:** Block the operation (return -EPERM).
2. **Observation:** Emit a BehaviorEvent recording the attempt.

LSM events use `event.type = "LSM"` and `event.layer = "behavior"`, since
a tamper attempt is an observable side effect of the target user's actions. The
blocked operation and its denial are captured in `args` and `return_code`.

**Hooks:**
- `lsm/file_open` -- block writes to daemon binary and systemd units
- `lsm/task_kill` -- block signals (SIGKILL, SIGSTOP, SIGTERM) to daemon PID
- `lsm/bpf` -- block BPF program load/unload by non-daemon processes
- `lsm/ptrace_access_check` -- block ptrace on daemon (defense in depth with CAP_SYS_PTRACE drop)
- `lsm/inode_unlink` -- prevent deletion of daemon binary and systemd units
- `lsm/inode_rename` -- prevent renaming of daemon binary and systemd units
- `lsm/task_fix_setuid` -- observe privilege transitions (setuid/setgid changes)


## Daemon Identification Strategy

DECIDED: Two-layer identification for LSM hook whitelisting.

1. **Primary (fast):** Daemon PID stored in a BPF global variable at
   startup. All LSM hooks first check `bpf_get_current_pid_tgid()`
   against the stored PID for fast-path filtering.

2. **Secondary (robust):** LSM hooks that support `bpf_d_path()` (e.g.,
   `file_open`, `inode_unlink`) additionally verify the target binary
   path. This guards against PID recycling: if the daemon crashes and
   the PID is reused by another process, path verification prevents
   the impersonator from being whitelisted.

The daemon PID global variable is updated on restart (systemd
`Restart=always`). During the brief window between crash and restart,
no daemon PID is active and LSM hooks block all matching operations.
