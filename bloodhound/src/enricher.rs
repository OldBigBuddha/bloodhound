use crate::deserializer::{BehaviorEvent, ProcInfo};
use std::fs;
use std::path::Path;

/// Enrich a BehaviorEvent with /proc/<pid> information.
/// Best-effort: short-lived processes may have already exited.
pub fn enrich(event: &mut BehaviorEvent) {
    let pid = event.header.pid;
    if pid == 0 {
        return;
    }

    let proc_path = format!("/proc/{}", pid);
    if !Path::new(&proc_path).exists() {
        return;
    }

    let main_executable = fs::read_link(format!("{}/exe", proc_path))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    let cwd = fs::read_link(format!("{}/cwd", proc_path))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    // Check for TTY by reading /proc/<pid>/fd/0
    let tty = fs::read_link(format!("{}/fd/0", proc_path))
        .ok()
        .and_then(|p| {
            let s = p.to_string_lossy().to_string();
            if s.contains("/dev/pts/") {
                Some(s)
            } else {
                None
            }
        });

    // Also try to get ppid from /proc/<pid>/stat
    if event.header.ppid.is_none() {
        if let Ok(stat) = fs::read_to_string(format!("{}/stat", proc_path)) {
            // Format: pid (comm) state ppid ...
            // Find the closing parenthesis to handle comm with spaces
            if let Some(close_paren) = stat.rfind(')') {
                let after = &stat[close_paren + 2..];
                let fields: Vec<&str> = after.split_whitespace().collect();
                if fields.len() >= 2 {
                    if let Ok(ppid) = fields[1].parse::<u32>() {
                        event.header.ppid = Some(ppid);
                    }
                }
            }
        }
    }

    if main_executable.is_some() || cwd.is_some() || tty.is_some() {
        event.proc = Some(ProcInfo {
            main_executable,
            cwd,
            tty,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deserializer::{BehaviorEvent, EventHeaderJson, EventTypeJson};

    fn make_test_event(pid: u32) -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeaderJson {
                timestamp: 1.0,
                auid: 1000,
                sessionid: 1,
                pid,
                ppid: None,
                comm: "test".to_string(),
            },
            event: EventTypeJson {
                event_type: "TRACEPOINT".to_string(),
                name: "openat".to_string(),
                layer: "behavior".to_string(),
            },
            proc: None,
            args: None,
            return_code: None,
        }
    }

    // ── Contract: best-effort, never panics ──────────────────────────────

    /// PID 0 (kernel/swapper) must never be enriched.
    /// This is a fundamental guard: /proc/0 has special semantics.
    #[test]
    fn pid_zero_is_not_enriched() {
        let mut event = make_test_event(0);
        enrich(&mut event);
        assert!(event.proc.is_none());
    }

    /// A non-existent PID must not cause an error or panic.
    /// This is critical because traced processes may exit before
    /// the enricher reads /proc.
    #[test]
    fn nonexistent_pid_does_not_panic() {
        let mut event = make_test_event(999_999_999);
        enrich(&mut event);
        assert!(event.proc.is_none());
    }

    /// Our own process (always alive) should be enrichable.
    #[test]
    fn own_process_is_enriched() {
        let my_pid = std::process::id();
        let mut event = make_test_event(my_pid);
        enrich(&mut event);

        // Our own process has /proc/self/exe and /proc/self/cwd
        let proc_info = event.proc.as_ref().expect("Own process should be enrichable");
        assert!(proc_info.main_executable.is_some());
        assert!(proc_info.cwd.is_some());
    }

    /// ppid should be filled from /proc if not already present.
    #[test]
    fn ppid_is_filled_from_proc() {
        let my_pid = std::process::id();
        let mut event = make_test_event(my_pid);
        assert!(event.header.ppid.is_none());

        enrich(&mut event);

        // After enrichment, ppid should be populated with our parent PID
        assert!(
            event.header.ppid.is_some(),
            "ppid should be filled from /proc/{}/stat",
            my_pid,
        );
        assert!(
            event.header.ppid.unwrap() > 0,
            "ppid should be a valid PID",
        );
    }

    /// If ppid is already set, enrichment must not overwrite it.
    /// The BPF-provided ppid is authoritative.
    #[test]
    fn existing_ppid_is_preserved() {
        let my_pid = std::process::id();
        let mut event = make_test_event(my_pid);
        event.header.ppid = Some(12345);

        enrich(&mut event);

        assert_eq!(event.header.ppid, Some(12345));
    }

    /// Enrichment must be idempotent: calling it twice should not corrupt state.
    #[test]
    fn enrichment_is_idempotent() {
        let my_pid = std::process::id();
        let mut event = make_test_event(my_pid);
        enrich(&mut event);
        let first_exe = event
            .proc
            .as_ref()
            .and_then(|p| p.main_executable.clone());

        enrich(&mut event);
        let second_exe = event
            .proc
            .as_ref()
            .and_then(|p| p.main_executable.clone());

        assert_eq!(first_exe, second_exe);
    }
}

