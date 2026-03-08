# Filtering: auid + sessionid Based Process Selection

All BPF programs share a common filtering strategy based on two audit
subsystem fields: the login UID (`auid`) and the session ID (`sessionid`).

- `auid` is set at login time and persists through `su`, `sudo`, and
  `setuid` transitions, making it reliable for tracking a user who
  escalates to root.
- `sessionid` is assigned per login session, allowing disambiguation when
  the same user has multiple concurrent sessions.


## Reading auid and sessionid in BPF

Neither field is exposed through BPF helper functions. Both must be read
directly from `task_struct` via BTF-assisted kernel memory access:

```
current_task -> task_struct.loginuid.val   (kuid_t, u32)  -> auid
current_task -> task_struct.sessionid      (u32)          -> sessionid
```

This requires:
- BTF enabled in the kernel
- CO-RE (Compile Once, Run Everywhere) via Aya's BTF support


## Target auid Injection

DECIDED: auid = uid. On Ubuntu with default PAM configuration,
`pam_loginuid.so` sets `auid` to the user's UID at SSH login time.
Since the VM uses default PAM and SSH is the only login method,
`auid` is always equal to the target user's UID. The VM image
build process should verify that `pam_loginuid.so` is enabled.

The target `auid` value is injected at runtime:

1. Bloodhound receives the target UID as a startup argument (`--uid <N>`).
2. The UID value is used directly as the target `auid`.
3. The value is written to a BPF global variable (`TARGET_AUID`).
4. Every BPF program reads `TARGET_AUID` and performs early return on mismatch.
5. `sessionid` is not filtered in BPF -- it is captured and included in
   every event for userspace-level correlation.

```
                 +-------------------+
                 | CLI arg: --uid N  |
                 +---------+---------+
                           |
                           v
              +------------+-------------+
              | Write to BPF global var  |
              | TARGET_AUID = N          |
              +------------+-------------+
                           |
              +------------+-------------+
              | All BPF programs:        |
              |  1. Filter on auid       |
              |  2. Capture sessionid    |
              +--------------------------+
```
