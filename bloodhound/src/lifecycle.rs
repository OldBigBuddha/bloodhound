//! Userspace synthesis of process-lifecycle events.
//!
//! Kernel-level capture emits clone/clone3 (rich) and exit_group (raw
//! syscall, NR 231) but does not expose first-class "the process just
//! forked / the process just exited / this pid was first seen" events.
//! Downstream consumers — especially the DSL pattern matcher — need
//! these lifecycle signals to scope per-pid state and to defeat pid
//! recycling within a single session.
//!
//! Rather than grow the BPF surface, this module observes the decoded
//! event stream in userspace and synthesises three `LIFECYCLE` events:
//!
//! - `process_start` — emitted *before* the first event we see from a
//!   previously-unseen pid. Carries `start_time_ns` (from
//!   `/proc/<pid>/stat` field 22, converted to wall-clock ns using the
//!   system boot time) so that `(pid, start_time_ns)` can be used as a
//!   stable identity across pid reuse.
//!
//! - `process_fork` — emitted *after* a successful `clone` / `clone3`
//!   event (return ≥ 0) when the clone did not set `CLONE_THREAD`.
//!   Carries `parent_pid`, `child_pid`, and the decoded clone flags.
//!
//! - `process_exit` — emitted *after* the raw `exit_group` syscall
//!   (NR 231). Carries the originating pid and exit code. Also removes
//!   the pid from the first-seen set so that a subsequent reuse of
//!   that pid number produces a fresh `process_start` with a new
//!   `start_time_ns`.
//!
//! None of this requires BPF changes. The shape and timing contract is
//! documented in `docs/output-schema.md` under the `LIFECYCLE` event
//! type.

use std::collections::HashSet;
use std::fs;

use serde_json::json;

use crate::deserializer::{BehaviorEvent, EventHeaderJson, EventTypeJson};

/// Syscall number for `exit_group` on x86_64. Used to detect process
/// termination in Tier 1 raw-syscall events (where `event.name` is the
/// syscall number rendered as a string).
const SYS_EXIT_GROUP: &str = "231";

/// State carried across events. Kept intentionally small: only the set
/// of pids we've already seen (for `process_start` gating) and the
/// conversion factors for `/proc/<pid>/stat` → wall-clock ns.
pub struct LifecycleSynthesizer {
    seen_pids: HashSet<u32>,
    /// Monotonic boot time expressed as wall-clock nanoseconds since
    /// epoch. Cached once at startup; `/proc/<pid>/stat` field 22
    /// (starttime) is boot-relative in clock ticks, so the absolute
    /// wall-clock start time is `boot_time_ns_epoch + starttime * ns_per_tick`.
    boot_time_ns_epoch: u64,
    /// Nanoseconds per clock tick (`1e9 / sysconf(_SC_CLK_TCK)`).
    /// Typically 10_000_000 (100 Hz) on Linux.
    ns_per_tick: u64,
}

impl LifecycleSynthesizer {
    pub fn new() -> Self {
        Self {
            seen_pids: HashSet::new(),
            boot_time_ns_epoch: read_boot_time_ns_epoch(),
            ns_per_tick: read_ns_per_tick(),
        }
    }

    /// Events to emit *before* the given original event.
    ///
    /// Currently returns at most one `process_start` event — the first
    /// time we observe a pid. The caller is expected to serialize these
    /// ahead of the triggering event so that downstream consumers see
    /// the identity anchor before any behavioural event from that pid.
    pub fn before(&mut self, event: &BehaviorEvent) -> Vec<BehaviorEvent> {
        let pid = event.header.pid;
        // Don't gate on pid 0 — that's kernel-owned and never legitimate
        // for a target user. We still record it as "seen" so we don't
        // try again on every event.
        if pid == 0 {
            self.seen_pids.insert(pid);
            return Vec::new();
        }
        if !self.seen_pids.insert(pid) {
            return Vec::new();
        }
        vec![self.make_process_start(event)]
    }

    /// Events to emit *after* the given original event.
    ///
    /// Returns `process_fork` for successful non-thread clones and
    /// `process_exit` for `exit_group` raw syscalls. All other events
    /// produce an empty vector.
    pub fn after(&mut self, event: &BehaviorEvent) -> Vec<BehaviorEvent> {
        match (
            event.event.event_type.as_str(),
            event.event.name.as_str(),
            event.return_code,
        ) {
            ("TRACEPOINT", "clone", Some(ret)) | ("TRACEPOINT", "clone3", Some(ret))
                if ret >= 0 && !has_clone_thread_flag(&event.args) =>
            {
                vec![self.make_process_fork(event, ret as u32)]
            }
            ("SYSCALL", SYS_EXIT_GROUP, _) => {
                let out = vec![self.make_process_exit(event)];
                // Remove from seen-set so a pid reuse produces a fresh
                // process_start with the new start_time_ns.
                self.seen_pids.remove(&event.header.pid);
                out
            }
            _ => Vec::new(),
        }
    }

    fn make_process_start(&self, triggering: &BehaviorEvent) -> BehaviorEvent {
        let pid = triggering.header.pid;
        let (start_time_ns, partial) = self.read_start_time_ns(pid);

        let mut args = serde_json::Map::new();
        args.insert("start_time_ns".into(), json!(start_time_ns));
        if partial {
            args.insert("partial".into(), json!(true));
        }
        // Best-effort exe / cwd: reuse /proc the same way the enricher
        // does. The process may already be gone; if so we simply omit
        // these fields and flag `partial`.
        let proc_path = format!("/proc/{}", pid);
        if let Ok(exe) = fs::read_link(format!("{}/exe", proc_path)) {
            args.insert(
                "main_executable".into(),
                json!(exe.to_string_lossy().to_string()),
            );
        }
        if let Ok(cwd) = fs::read_link(format!("{}/cwd", proc_path)) {
            args.insert("cwd".into(), json!(cwd.to_string_lossy().to_string()));
        }

        BehaviorEvent {
            header: clone_header(&triggering.header),
            event: EventTypeJson {
                event_type: "LIFECYCLE".into(),
                name: "process_start".into(),
                layer: "behavior".into(),
            },
            proc: None,
            args: Some(serde_json::Value::Object(args)),
            return_code: None,
        }
    }

    fn make_process_fork(&self, triggering: &BehaviorEvent, child_pid: u32) -> BehaviorEvent {
        let parent_pid = triggering.header.pid;
        let clone_flags = triggering
            .args
            .as_ref()
            .and_then(|v| v.get("flags"))
            .cloned()
            .unwrap_or(serde_json::Value::Array(Vec::new()));

        BehaviorEvent {
            header: clone_header(&triggering.header),
            event: EventTypeJson {
                event_type: "LIFECYCLE".into(),
                name: "process_fork".into(),
                layer: "behavior".into(),
            },
            proc: None,
            args: Some(json!({
                "parent_pid": parent_pid,
                "child_pid": child_pid,
                "clone_flags": clone_flags,
            })),
            return_code: None,
        }
    }

    fn make_process_exit(&self, triggering: &BehaviorEvent) -> BehaviorEvent {
        let pid = triggering.header.pid;
        // Raw syscall events carry raw_args[0] which for exit_group is
        // the exit status. We coerce to i32 because the spec exposes
        // exit codes as signed.
        let exit_code = triggering
            .args
            .as_ref()
            .and_then(|v| v.get("raw_args"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_u64())
            .map(|n| n as i32)
            .unwrap_or(0);

        BehaviorEvent {
            header: clone_header(&triggering.header),
            event: EventTypeJson {
                event_type: "LIFECYCLE".into(),
                name: "process_exit".into(),
                layer: "behavior".into(),
            },
            proc: None,
            args: Some(json!({
                "pid": pid,
                "exit_code": exit_code,
            })),
            return_code: None,
        }
    }

    /// Read `/proc/<pid>/stat` field 22 (starttime in clock ticks since
    /// boot) and convert to wall-clock ns. Returns `(ns, partial)`; if
    /// the process is already gone we return `(0, true)` so downstream
    /// consumers can see the data is incomplete.
    fn read_start_time_ns(&self, pid: u32) -> (u64, bool) {
        let stat = match fs::read_to_string(format!("/proc/{}/stat", pid)) {
            Ok(s) => s,
            Err(_) => return (0, true),
        };
        // Format: `pid (comm) state ppid pgrp session tty_nr tpgid flags
        //          minflt cminflt majflt cmajflt utime stime cutime cstime
        //          priority nice num_threads itrealvalue starttime ...`
        // comm may contain spaces and parentheses, so we split on the
        // final `)` and count fields from there. Field 22 is starttime,
        // which is the 20th field *after* the closing paren (the split
        // yields state as field 0 of the tail).
        let Some(close_paren) = stat.rfind(')') else {
            return (0, true);
        };
        let after: Vec<&str> = stat[close_paren + 1..].split_whitespace().collect();
        // Tail index for starttime: the full stat fields are
        //   1 pid, 2 comm, 3 state, 4 ppid, ..., 22 starttime
        // So within the tail (starting at state = tail[0]), starttime
        // is at tail[19].
        let Some(starttime_str) = after.get(19) else {
            return (0, true);
        };
        let Ok(starttime_ticks) = starttime_str.parse::<u64>() else {
            return (0, true);
        };
        let ns = self
            .boot_time_ns_epoch
            .saturating_add(starttime_ticks.saturating_mul(self.ns_per_tick));
        (ns, false)
    }
}

fn clone_header(h: &EventHeaderJson) -> EventHeaderJson {
    EventHeaderJson {
        timestamp: h.timestamp,
        auid: h.auid,
        sessionid: h.sessionid,
        pid: h.pid,
        ppid: h.ppid,
        comm: h.comm.clone(),
    }
}

/// Check whether the decoded `args.flags` array contains
/// `"CLONE_THREAD"`. Thread clones should not emit `process_fork`
/// because they do not create a new process identity.
fn has_clone_thread_flag(args: &Option<serde_json::Value>) -> bool {
    let Some(v) = args.as_ref().and_then(|a| a.get("flags")) else {
        return false;
    };
    let Some(arr) = v.as_array() else {
        return false;
    };
    arr.iter()
        .any(|f| f.as_str().is_some_and(|s| s == "CLONE_THREAD"))
}

/// Resolve wall-clock nanoseconds at boot time (t=0 on
/// `CLOCK_MONOTONIC`). Read once at startup. Derived from
/// `/proc/stat`'s `btime` line (seconds since epoch) for portability;
/// we lose nanosecond precision on the boot instant itself, which is
/// acceptable because `starttime` ticks are only ~10 ms apart.
fn read_boot_time_ns_epoch() -> u64 {
    let stat = fs::read_to_string("/proc/stat").unwrap_or_default();
    for line in stat.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            if let Ok(secs) = rest.trim().parse::<u64>() {
                return secs.saturating_mul(1_000_000_000);
            }
        }
    }
    0
}

/// Return nanoseconds per clock tick.
///
/// `sysconf(_SC_CLK_TCK)` is the portable way to query this, but
/// requires a `libc` dependency we otherwise avoid. On every supported
/// Linux x86_64 target (kernel 6.8, Ubuntu 24.04) `CLK_TCK` is 100 Hz,
/// making each tick exactly 10 ms. We hardcode that value here; if a
/// future target kernel uses a different `CONFIG_HZ`, the
/// `start_time_ns` field will skew proportionally and this constant
/// needs revisiting. The skew affects identity-precision but not
/// correctness of the `(pid, start_time_ns)` anchor since both the
/// computed and observed times use the same tick rate.
fn read_ns_per_tick() -> u64 {
    10_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(pid: u32) -> EventHeaderJson {
        EventHeaderJson {
            timestamp: 1.0,
            auid: 1000,
            sessionid: 1,
            pid,
            ppid: None,
            comm: "t".to_string(),
        }
    }

    fn event(event_type: &str, name: &str) -> BehaviorEvent {
        BehaviorEvent {
            header: header(100),
            event: EventTypeJson {
                event_type: event_type.to_string(),
                name: name.to_string(),
                layer: "behavior".to_string(),
            },
            proc: None,
            args: None,
            return_code: None,
        }
    }

    // ── process_start gating ─────────────────────────────────────────────

    #[test]
    fn first_event_from_pid_emits_process_start() {
        let mut life = LifecycleSynthesizer::new();
        let ev = event("TRACEPOINT", "openat");
        let pre = life.before(&ev);
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0].event.event_type, "LIFECYCLE");
        assert_eq!(pre[0].event.name, "process_start");
    }

    #[test]
    fn second_event_from_same_pid_is_not_re_announced() {
        let mut life = LifecycleSynthesizer::new();
        let ev = event("TRACEPOINT", "openat");
        life.before(&ev);
        assert!(life.before(&ev).is_empty());
    }

    #[test]
    fn pid_zero_is_never_announced() {
        let mut life = LifecycleSynthesizer::new();
        let mut ev = event("TRACEPOINT", "openat");
        ev.header.pid = 0;
        assert!(life.before(&ev).is_empty());
    }

    // ── process_exit triggers and GCs ────────────────────────────────────

    #[test]
    fn exit_group_raw_syscall_emits_process_exit() {
        let mut life = LifecycleSynthesizer::new();
        let mut ev = event("SYSCALL", SYS_EXIT_GROUP);
        ev.args = Some(json!({ "syscall_nr": 231, "raw_args": [42, 0, 0, 0, 0, 0] }));

        let post = life.after(&ev);
        assert_eq!(post.len(), 1);
        assert_eq!(post[0].event.name, "process_exit");
        assert_eq!(post[0].args.as_ref().unwrap()["exit_code"], 42);
        assert_eq!(post[0].args.as_ref().unwrap()["pid"], ev.header.pid);
    }

    #[test]
    fn exit_group_gc_allows_pid_reannouncement() {
        let mut life = LifecycleSynthesizer::new();
        let ev_first = event("TRACEPOINT", "openat");
        assert_eq!(life.before(&ev_first).len(), 1);
        // Same pid sees the exit
        let mut exit = event("SYSCALL", SYS_EXIT_GROUP);
        exit.args = Some(json!({ "syscall_nr": 231, "raw_args": [0, 0, 0, 0, 0, 0] }));
        life.after(&exit);
        // A new process with the same pid number should re-announce
        let ev_second = event("TRACEPOINT", "openat");
        assert_eq!(life.before(&ev_second).len(), 1);
    }

    // ── process_fork triggers ────────────────────────────────────────────

    #[test]
    fn successful_clone_emits_process_fork() {
        let mut life = LifecycleSynthesizer::new();
        let mut ev = event("TRACEPOINT", "clone");
        ev.args = Some(json!({ "flags": ["CLONE_VM", "CLONE_FILES"] }));
        ev.return_code = Some(12345);
        let post = life.after(&ev);
        assert_eq!(post.len(), 1);
        assert_eq!(post[0].event.name, "process_fork");
        let args = post[0].args.as_ref().unwrap();
        assert_eq!(args["parent_pid"], ev.header.pid);
        assert_eq!(args["child_pid"], 12345);
    }

    #[test]
    fn thread_clone_does_not_emit_process_fork() {
        let mut life = LifecycleSynthesizer::new();
        let mut ev = event("TRACEPOINT", "clone");
        ev.args = Some(json!({ "flags": ["CLONE_VM", "CLONE_THREAD"] }));
        ev.return_code = Some(12345);
        assert!(life.after(&ev).is_empty());
    }

    #[test]
    fn failed_clone_does_not_emit_process_fork() {
        let mut life = LifecycleSynthesizer::new();
        let mut ev = event("TRACEPOINT", "clone");
        ev.args = Some(json!({ "flags": [] }));
        ev.return_code = Some(-1);
        assert!(life.after(&ev).is_empty());
    }

    #[test]
    fn clone3_same_path_as_clone() {
        let mut life = LifecycleSynthesizer::new();
        let mut ev = event("TRACEPOINT", "clone3");
        ev.args = Some(json!({ "flags": [] }));
        ev.return_code = Some(99);
        let post = life.after(&ev);
        assert_eq!(post.len(), 1);
        assert_eq!(post[0].event.name, "process_fork");
    }

    #[test]
    fn non_lifecycle_events_pass_through_untouched() {
        let mut life = LifecycleSynthesizer::new();
        let ev = event("TRACEPOINT", "openat");
        assert!(life.after(&ev).is_empty());
    }

    // ── start_time_ns resolution (best-effort) ───────────────────────────

    #[test]
    fn process_start_for_own_pid_carries_start_time_ns() {
        let mut life = LifecycleSynthesizer::new();
        let my_pid = std::process::id();
        let mut ev = event("TRACEPOINT", "openat");
        ev.header.pid = my_pid;
        let pre = life.before(&ev);
        assert_eq!(pre.len(), 1);
        let args = pre[0].args.as_ref().unwrap();
        let ns = args["start_time_ns"].as_u64().unwrap();
        // Live process: start_time_ns should be non-zero and in the
        // past. We don't compare against now() to avoid flakiness from
        // clock skew between btime and CLOCK_REALTIME.
        assert!(ns > 0, "start_time_ns should be populated for a live pid");
        // `partial` should not be set for a live process.
        assert!(args.get("partial").is_none());
    }

    #[test]
    fn process_start_for_dead_pid_is_marked_partial() {
        let mut life = LifecycleSynthesizer::new();
        let mut ev = event("TRACEPOINT", "openat");
        ev.header.pid = 999_999_999; // Very unlikely to exist.
        let pre = life.before(&ev);
        assert_eq!(pre.len(), 1);
        let args = pre[0].args.as_ref().unwrap();
        assert_eq!(args["partial"], true);
        assert_eq!(args["start_time_ns"], 0);
    }
}
