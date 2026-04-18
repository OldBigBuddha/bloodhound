# Daemon Lifecycle


## Startup

1. Parse CLI arguments (`--uid <N>`, `--exclude-ports <ports>`,
   `--ring-buffer-size <bytes>`, etc.)
2. Write `TARGET_AUID` to BPF global variable
3. Load and attach all BPF programs (tracepoints, kprobes, TC, LSM)
4. Begin polling ring buffer and emitting NDJSON to stdout
5. BPF programs are active immediately; events before target user login
   are filtered out by the auid check (auid will be AUDIT_UID_UNSET
   = 4294967295 for non-logged-in processes)


## Shutdown

DECIDED: Graceful shutdown on SIGTERM.

1. Receive SIGTERM
2. Detach all BPF programs (stops new events from being produced)
3. Drain remaining events from ring buffer
4. Flush all pending NDJSON to stdout
5. Exit with code 0

A timeout (e.g., 5 seconds) guards against infinite drain loops.
If the timeout expires, remaining events are dropped and the process
exits.


## Crash Recovery

DECIDED: systemd `Restart=always`. If Bloodhound crashes, systemd
restarts it automatically. [ACCEPTANCE] Events during the restart gap
are lost. The systemd unit should include `RestartSec=1` for fast
recovery.


## Nohup / Orphan Processes

DECIDED: Processes that outlive the SSH session (e.g., via `nohup`)
retain the target user's `auid` and continue to be traced. This is
intentional -- the target user's background processes are part of their
observable behavior.


## Scope Boundary

Bloodhound is responsible for:
- Loading and managing BPF programs
- Filtering events by auid
- Enriching events with proc metadata
- Serializing BehaviorEvents as NDJSON to stdout

Bloodhound is NOT responsible for:
- Event evaluation / matching logic
- Scenario task definitions
- Signaling task completion (virtio-serial)
- Hint generation
- Protocol-level packet parsing (DNS, TLS SNI, HTTP, etc.); see
  `docs/tracing.md` §Protocol semantic extraction is out of scope

Downstream consumers read Bloodhound's stdout stream. This separation
keeps Bloodhound focused and testable.
