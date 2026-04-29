mod app;
mod command_reconstructor;
mod correlator;
mod event_model;
mod keybinds;
mod ui;

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, FixedOffset, Utc};
use clap::Parser;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use app::{App, ExecChild};
use command_reconstructor::reconstruct_commands;
use correlator::{correlate, CommandGroup};
use event_model::BehaviorEvent;

#[cfg(test)]
mod render_tests;

const FILE_SIZE_WARNING_BYTES: u64 = 50 * 1024 * 1024; // 50 MB

#[derive(Parser)]
#[command(name = "bloodhound-tui")]
#[command(about = "TUI viewer for Bloodhound NDJSON trace logs")]
struct Cli {
    /// Path to the Bloodhound NDJSON file
    file: String,

    /// Timezone for timestamp display (e.g. "+09:00", "-05:00").
    /// Default: "+00:00" (UTC)
    #[arg(long, default_value = "+00:00")]
    timezone: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check file size
    let metadata = fs::metadata(&cli.file)
        .with_context(|| format!("Cannot read file: {}", cli.file))?;

    if metadata.len() > FILE_SIZE_WARNING_BYTES {
        let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
        eprintln!(
            "⚠ Warning: File is {:.1} MB. Loading large files may use significant memory.",
            size_mb
        );
        eprintln!("Continue? [y/N] ");

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let tz_offset = FixedOffset::east_opt(parse_tz_offset(&cli.timezone)?)
        .ok_or_else(|| anyhow::anyhow!("Invalid timezone offset: {}", cli.timezone))?;

    let app = build_app_from_path(Path::new(&cli.file), tz_offset, None)?;

    run_tui(app)
}

/// Build an [`App`] by parsing an NDJSON trace file.
///
/// Shared between the CLI entry point and render-level tests:
/// `main()` uses this after handling the interactive size-warning prompt;
/// snapshot tests call it directly with a pinned `boot_time_override`
/// so wall-clock timestamps stay deterministic across checkouts.
pub(crate) fn build_app_from_path(
    path: &Path,
    tz_offset: FixedOffset,
    boot_time_override: Option<DateTime<Utc>>,
) -> Result<App> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Cannot read file: {}", path.display()))?;

    let mut events: Vec<BehaviorEvent> = Vec::new();
    let mut parse_errors = 0;
    let mut tier1_duplicates = 0;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<BehaviorEvent>(line) {
            // Defensive dedup: when the daemon's TIER2_BITMAP is
            // mis-configured (e.g. old binary against a newer schema)
            // a Tier 1 raw `SYSCALL` event can accompany its Tier 2
            // rich counterpart. Drop the Tier 1 copy here so the
            // detail pane doesn't double-count the same syscall.
            Ok(event) if event.is_redundant_tier1() => {
                tier1_duplicates += 1;
            }
            Ok(event) => events.push(event),
            Err(e) => {
                parse_errors += 1;
                if parse_errors <= 5 {
                    eprintln!("Warning: parse error on line {}: {}", line_num + 1, e);
                }
            }
        }
    }

    if events.is_empty() {
        bail!("No valid events found in {}", path.display());
    }

    if parse_errors > 0 {
        eprintln!(
            "Loaded {} events ({} lines failed to parse)",
            events.len(),
            parse_errors,
        );
    }

    if tier1_duplicates > 0 {
        eprintln!(
            "Dropped {} Tier 1 raw-syscall events that are already covered by Tier 2 rich extraction",
            tier1_duplicates,
        );
    }

    events.sort_by(|a, b| {
        a.header
            .timestamp
            .partial_cmp(&b.header.timestamp)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Extract tty_write data for command reconstruction.
    //
    // Why tty_write and not tty_read?
    //   - tty_read hooks n_tty_read (kprobe at entry), but the user buffer has
    //     NOT been filled yet at that point, so the captured data is null
    //     bytes / residual garbage.
    //   - tty_write hooks pty_write, which captures ALL terminal I/O including
    //     the echoed user commands (from comm="bash") and program output.
    //     The command_reconstructor handles the mixed data by parsing newlines
    //     and stripping ANSI escapes.
    let tty_writes: Vec<(f64, String, String)> = events
        .iter()
        .filter(|e| e.is_tty_write())
        .filter_map(|e| {
            let data = e.args.as_ref()?.get("data")?.as_str()?;
            Some((e.header.timestamp, data.to_string(), e.header.comm.clone()))
        })
        .collect();

    let commands = reconstruct_commands(&tty_writes);

    // Filter out empty commands: the \r\n double-flush and bracketed paste
    // mode sequences produce empty entries that would steal events from
    // the preceding real command.
    let commands: Vec<_> = commands
        .into_iter()
        .filter(|c| !c.command.trim().is_empty())
        .collect();

    let groups = correlate(&commands, &events);
    let tty_output = build_tty_output(&groups, &events);
    let exec_trees = build_exec_trees(&groups, &events);

    let file_display = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());

    // Compute boot time anchor.
    //
    // The eBPF timestamps are monotonic (bpf_ktime_get_ns / 1e9 = seconds since boot).
    // To show wall-clock time, we anchor the last event's monotonic timestamp to the
    // file's modification time (= roughly when the daemon last wrote), then derive
    // the boot instant.  This gives approximate wall-clock timestamps for all events.
    //
    // Tests override this to pin wall-clock output across checkouts.
    let boot_time_utc = match boot_time_override {
        Some(t) => t,
        None => {
            let file_mtime: DateTime<Utc> = fs::metadata(path)?.modified()?.into();
            let last_mono = events.last().map(|e| e.header.timestamp).unwrap_or(0.0);
            file_mtime - chrono::Duration::milliseconds((last_mono * 1000.0) as i64)
        }
    };

    let fd_table = build_fd_table(&events);

    Ok(App::new(crate::app::AppInit {
        commands: groups,
        events,
        tty_output,
        exec_trees,
        file_path: file_display,
        boot_time_utc,
        tz_offset,
        fd_table,
    }))
}

/// Build (pid, fd) → filename mapping from successful `openat` events.
/// Consumed by `summary_line` to resolve `read`/`write` fds back to paths.
fn build_fd_table(events: &[BehaviorEvent]) -> std::collections::HashMap<(u32, u32), String> {
    let mut table = std::collections::HashMap::new();
    for event in events {
        if event.event.name != "openat" {
            continue;
        }
        let fd = match event.return_code {
            Some(rc) if rc >= 0 => rc as u32,
            _ => continue,
        };
        let filename = event
            .args
            .as_ref()
            .and_then(|a| a.get("filename"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !filename.is_empty() {
            table.insert((event.header.pid, fd), filename);
        }
    }
    table
}

fn run_tui(mut app: App) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    let result = loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        // Poll for events with 250ms timeout
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                keybinds::handle_key(&mut app, key);
            }
        }

        if app.should_quit {
            break Ok(());
        }
    };

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

// ── Exec tree builder ────────────────────────────────────────────────────────

/// Composite process identity: `(pid, start_time_ns)`.
///
/// `start_time_ns == 0` means no `LIFECYCLE/process_start` was seen
/// for this pid (older daemon, or event lost), so identity collapses
/// to pid-only — two pid-reused processes would merge, matching the
/// pre-#18 behaviour as a graceful fallback.
type ProcId = (u32, u64);

/// Build execve process trees per command group.
///
/// Parent attribution prefers explicit `LIFECYCLE/process_fork` edges
/// (PR #18) when available: the most recent fork whose `child_pid`
/// matches the execve's pid, bounded by the execve's timestamp, wins.
/// That gives the matcher the clone → execve parent edge directly,
/// instead of inferring it from the `ppid` header (which points at
/// whatever is *currently* attached to the pid and can be wrong after
/// reparenting).
///
/// Node identity is `(pid, start_time_ns)` so that pid reuse within a
/// session produces two distinct tree nodes instead of collapsing two
/// unrelated processes together. `start_time_ns` comes from the
/// `LIFECYCLE/process_start` event that preceded each pid's first
/// observation; falls back to `ppid`-only when lifecycle events are
/// absent.
fn build_exec_trees(
    groups: &[CommandGroup],
    events: &[BehaviorEvent],
) -> Vec<Vec<ExecChild>> {
    use std::collections::{HashMap, HashSet};

    // Global pass: for every event index, compute the `start_time_ns`
    // of its `header.pid` at that moment. We update a live `pid → ns`
    // map on `process_start`, clear on `process_exit`. The recorded
    // value for each non-lifecycle event is the identity anchor valid
    // at that timestamp — so a pid-reused process gets its own ns.
    let mut live_start: HashMap<u32, u64> = HashMap::new();
    let mut start_time_per_event: Vec<u64> = vec![0; events.len()];
    for (i, e) in events.iter().enumerate() {
        match (e.event.event_type.as_str(), e.event.name.as_str()) {
            ("LIFECYCLE", "process_start") => {
                if let Some(ns) = e
                    .args
                    .as_ref()
                    .and_then(|a| a.get("start_time_ns"))
                    .and_then(|v| v.as_u64())
                {
                    live_start.insert(e.header.pid, ns);
                }
            }
            ("LIFECYCLE", "process_exit") => {
                live_start.remove(&e.header.pid);
            }
            _ => {}
        }
        start_time_per_event[i] = live_start.get(&e.header.pid).copied().unwrap_or(0);
    }

    groups
        .iter()
        .map(|group| {
            // Collect execve events in this group, paired with their
            // resolved `start_time_ns`.
            let execves: Vec<(usize, &BehaviorEvent, u64)> = group
                .event_indices
                .iter()
                .filter_map(|&idx| events.get(idx).map(|e| (idx, e, start_time_per_event[idx])))
                .filter(|(_, e, _)| e.event.name == "execve" || e.event.name == "execveat")
                .collect();

            if execves.is_empty() {
                return vec![];
            }

            // Collect fork edges observed in the same time window as
            // this group. The correlator strips LIFECYCLE events from
            // the group, so look them up directly against the group's
            // [start_ts, end_ts) window.
            let window_start = group.timestamp;
            let window_end = group
                .event_indices
                .iter()
                .filter_map(|&idx| events.get(idx))
                .map(|e| e.header.timestamp)
                .fold(window_start, f64::max);
            let forks: Vec<(u32, u32, f64)> = events
                .iter()
                .filter(|e| e.event.event_type == "LIFECYCLE" && e.event.name == "process_fork")
                .filter(|e| {
                    e.header.timestamp >= window_start && e.header.timestamp <= window_end
                })
                .filter_map(|e| {
                    let args = e.args.as_ref()?;
                    let parent = args.get("parent_pid").and_then(|v| v.as_u64())? as u32;
                    let child = args.get("child_pid").and_then(|v| v.as_u64())? as u32;
                    Some((parent, child, e.header.timestamp))
                })
                .collect();

            // Resolve the parent pid for an execve at (pid, ts):
            // most-recent fork with child == pid and fork_ts <= ts;
            // fall back to the `ppid` header.
            let resolve_parent_pid = |pid: u32, ts: f64, ppid_fallback: u32| -> u32 {
                forks
                    .iter()
                    .filter(|(_, child, fts)| *child == pid && *fts <= ts)
                    .max_by(|(_, _, a), (_, _, b)| {
                        a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(parent, _, _)| *parent)
                    .unwrap_or(ppid_fallback)
            };

            // Set of execve identities in this group. Root iff the
            // execve's parent identity is not in this set.
            let execve_ids: HashSet<ProcId> =
                execves.iter().map(|(_, e, ns)| (e.header.pid, *ns)).collect();

            let mut children_of: HashMap<ProcId, Vec<(usize, &BehaviorEvent, u64)>> =
                HashMap::new();
            let mut roots: Vec<(usize, &BehaviorEvent, u64)> = Vec::new();

            for &(idx, ev, ns) in &execves {
                let ppid = ev.header.ppid.unwrap_or(0);
                let parent_pid = resolve_parent_pid(ev.header.pid, ev.header.timestamp, ppid);
                // Parent's identity: its start_time_ns at this execve's
                // moment. Walk back from this event to the nearest
                // prior event emitted by parent_pid; its resolved
                // start_time_ns is the parent's anchor. If the parent
                // never appears before the child, fall back to 0 — the
                // tree degrades to pid-only identity for that edge.
                let parent_ns = events[..=idx]
                    .iter()
                    .enumerate()
                    .rev()
                    .find(|(_, e)| e.header.pid == parent_pid)
                    .map(|(pi, _)| start_time_per_event[pi])
                    .unwrap_or(0);
                let parent_id: ProcId = (parent_pid, parent_ns);

                if execve_ids.contains(&parent_id) {
                    children_of.entry(parent_id).or_default().push((idx, ev, ns));
                } else {
                    roots.push((idx, ev, ns));
                }
            }

            let by_timestamp = |a: &(usize, &BehaviorEvent, u64),
                                b: &(usize, &BehaviorEvent, u64)| {
                a.1.header
                    .timestamp
                    .partial_cmp(&b.1.header.timestamp)
                    .unwrap_or(std::cmp::Ordering::Equal)
            };
            roots.sort_by(by_timestamp);
            for v in children_of.values_mut() {
                v.sort_by(by_timestamp);
            }

            let mut result = Vec::new();
            let root_count = roots.len();
            for (ri, (idx, ev, ns)) in roots.into_iter().enumerate() {
                exec_tree_dfs(
                    (ev.header.pid, ns),
                    1,
                    idx,
                    ev,
                    ri == root_count - 1,
                    &children_of,
                    &mut result,
                );
            }

            result
        })
        .collect()
}

/// DFS helper: emit the current node, then recurse into children.
fn exec_tree_dfs(
    id: ProcId,
    depth: usize,
    idx: usize,
    ev: &BehaviorEvent,
    is_last: bool,
    children_of: &std::collections::HashMap<ProcId, Vec<(usize, &BehaviorEvent, u64)>>,
    result: &mut Vec<ExecChild>,
) {
    let label = build_exec_label(ev);
    let (pid, start_time_ns) = id;
    result.push(ExecChild {
        label,
        pid,
        start_time_ns,
        depth,
        event_index: idx,
        is_last,
    });

    if let Some(children) = children_of.get(&id) {
        let child_count = children.len();
        for (ci, &(child_idx, child_ev, child_ns)) in children.iter().enumerate() {
            exec_tree_dfs(
                (child_ev.header.pid, child_ns),
                depth + 1,
                child_idx,
                child_ev,
                ci == child_count - 1,
                children_of,
                result,
            );
        }
    }
}

/// Build a display label from an execve event's args.
fn build_exec_label(ev: &BehaviorEvent) -> String {
    if let Some(args) = &ev.args {
        // Try to reconstruct from argv
        if let Some(argv) = args.get("argv").and_then(|v| v.as_array()) {
            let parts: Vec<&str> = argv.iter().filter_map(|v| v.as_str()).collect();
            if !parts.is_empty() {
                return parts.join(" ");
            }
        }
        // Fallback to filename
        if let Some(filename) = args.get("filename").and_then(|v| v.as_str()) {
            return filename.to_string();
        }
    }
    ev.header.comm.clone()
}

/// Build decoded TTY output text per command group.
///
/// For each command group, find tty_write events in its time window,
/// decode the base64 data, strip ANSI escape sequences, and split
/// into lines for display in the Output tab.
fn build_tty_output(
    groups: &[correlator::CommandGroup],
    events: &[BehaviorEvent],
) -> Vec<Vec<String>> {
    use base64::Engine;

    // Process names whose tty_write events are NOT command output:
    // - shells: prompt + command echo
    // - sshd: relays user keystrokes to PTY (leaks into previous command's window)
    const OUTPUT_EXCLUDE: &[&str] = &[
        "bash", "sh", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "sshd",
    ];

    // Collect non-shell tty_write events with timestamps and decoded data.
    // Shell processes emit prompt + command echo (shown in the left pane),
    // while non-shell processes emit actual command output (ls, cat, etc.).
    let tty_writes: Vec<(f64, Vec<u8>)> = events
        .iter()
        .filter(|e| e.is_tty_write() && !OUTPUT_EXCLUDE.contains(&e.header.comm.as_str()))
        .filter_map(|e| {
            let data_b64 = e.args.as_ref()?.get("data")?.as_str()?;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(data_b64)
                .ok()?;
            Some((e.header.timestamp, raw))
        })
        .collect();

    groups
        .iter()
        .enumerate()
        .map(|(gi, group)| {
            // Determine the time window for this group
            let window_start = group.timestamp;
            let window_end = if gi + 1 < groups.len() {
                groups[gi + 1].timestamp
            } else {
                f64::MAX
            };

            // Collect raw bytes in this window
            let mut raw_bytes = Vec::new();
            for (ts, data) in &tty_writes {
                if *ts >= window_start && *ts < window_end {
                    raw_bytes.extend_from_slice(data);
                }
            }

            // Strip ANSI/OSC escapes and convert to text lines
            let text = strip_ansi_escapes(&raw_bytes);
            text.lines()
                .map(|l| l.to_string())
                .collect()
        })
        .collect()
}

/// Strip ANSI CSI and OSC escape sequences from raw bytes,
/// returning a clean UTF-8 string.
fn strip_ansi_escapes(raw: &[u8]) -> String {
    let mut out = String::new();
    let mut in_escape = false;
    let mut in_osc = false;

    for &byte in raw {
        if in_osc {
            if byte == 0x07 {
                in_osc = false;
            }
            continue;
        }

        if in_escape {
            if byte == b']' {
                in_escape = false;
                in_osc = true;
                continue;
            }
            if byte.is_ascii_alphabetic() || byte == b'~' {
                in_escape = false;
            }
            continue;
        }

        match byte {
            0x1b => {
                in_escape = true;
            }
            b'\r' => {
                // Skip \r, let \n handle line breaks
            }
            b if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\t' => {
                out.push(byte as char);
            }
            _ => {}
        }
    }

    out
}

/// Parse a timezone offset string like "+09:00" or "-05:00" to seconds.
fn parse_tz_offset(s: &str) -> Result<i32> {
    let s = s.trim();
    if s == "UTC" || s == "utc" {
        return Ok(0);
    }
    let (sign, rest) = match s.as_bytes().first() {
        Some(b'+') => (1i32, &s[1..]),
        Some(b'-') => (-1i32, &s[1..]),
        _ => bail!("Timezone must start with '+' or '-' (e.g. +09:00), got: {}", s),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 2 {
        bail!("Timezone format must be ±HH:MM (e.g. +09:00), got: {}", s);
    }
    let hours: i32 = parts[0].parse().with_context(|| format!("Invalid hours in timezone: {}", s))?;
    let minutes: i32 = parts[1].parse().with_context(|| format!("Invalid minutes in timezone: {}", s))?;
    Ok(sign * (hours * 3600 + minutes * 60))
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_model::{EventHeader, EventType};
    use serde_json::json;

    fn mk_event(
        ts: f64,
        pid: u32,
        ppid: u32,
        event_type: &str,
        name: &str,
        args: serde_json::Value,
    ) -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeader {
                timestamp: ts,
                auid: 1000,
                sessionid: 1,
                pid,
                ppid: Some(ppid),
                comm: "bash".to_string(),
            },
            event: EventType {
                event_type: event_type.to_string(),
                name: name.to_string(),
                layer: "behavior".to_string(),
            },
            proc: None,
            args: Some(args),
            return_code: Some(0),
        }
    }

    fn execve(ts: f64, pid: u32, ppid: u32, cmd: &str) -> BehaviorEvent {
        mk_event(
            ts,
            pid,
            ppid,
            "TRACEPOINT",
            "execve",
            json!({ "filename": cmd, "argv": [cmd] }),
        )
    }

    fn process_start(ts: f64, pid: u32, start_ns: u64) -> BehaviorEvent {
        mk_event(
            ts,
            pid,
            0,
            "LIFECYCLE",
            "process_start",
            json!({ "start_time_ns": start_ns }),
        )
    }

    fn process_fork(ts: f64, parent: u32, child: u32) -> BehaviorEvent {
        mk_event(
            ts,
            parent,
            0,
            "LIFECYCLE",
            "process_fork",
            json!({ "parent_pid": parent, "child_pid": child }),
        )
    }

    fn process_exit(ts: f64, pid: u32) -> BehaviorEvent {
        mk_event(
            ts,
            pid,
            0,
            "LIFECYCLE",
            "process_exit",
            json!({ "pid": pid, "exit_code": 0 }),
        )
    }

    fn group_covering(events: &[BehaviorEvent]) -> CommandGroup {
        CommandGroup {
            command: "ls".to_string(),
            timestamp: events.first().map(|e| e.header.timestamp).unwrap_or(0.0),
            event_indices: events
                .iter()
                .enumerate()
                .filter(|(_, e)| e.event.event_type == "TRACEPOINT")
                .map(|(i, _)| i)
                .collect(),
        }
    }

    /// Baseline: no lifecycle events → tree falls back to ppid heuristic.
    /// This preserves the pre-#18 shape so older captures keep working.
    #[test]
    fn exec_tree_falls_back_to_ppid_without_lifecycle() {
        let events = vec![
            execve(1.0, 100, 1, "/bin/bash"),
            execve(1.1, 200, 100, "/bin/ls"),
        ];
        let groups = vec![group_covering(&events)];
        let trees = build_exec_trees(&groups, &events);
        let t = &trees[0];
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].pid, 100);
        assert_eq!(t[0].depth, 1);
        assert_eq!(t[1].pid, 200);
        assert_eq!(t[1].depth, 2);
    }

    /// process_fork overrides ppid: even if the ppid header is stale
    /// (for instance after a reparent-to-init), the fork edge provides
    /// the actual spawn relationship.
    #[test]
    fn exec_tree_uses_process_fork_when_ppid_is_wrong() {
        let events = vec![
            process_start(0.9, 100, 1_000_000),
            execve(1.0, 100, 1, "/bin/bash"),
            process_fork(1.05, 100, 200),
            process_start(1.06, 200, 2_000_000),
            // ppid header says "1" (init) — stale — but process_fork
            // at 1.05 says 100 is the real parent.
            execve(1.1, 200, 1, "/bin/ls"),
        ];
        let groups = vec![group_covering(&events)];
        let trees = build_exec_trees(&groups, &events);
        let t = &trees[0];
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].pid, 100);
        assert_eq!(t[0].depth, 1);
        assert_eq!(t[1].pid, 200);
        assert_eq!(
            t[1].depth, 2,
            "process_fork edge should attach 200 under 100 despite ppid=1"
        );
        assert_eq!(t[1].start_time_ns, 2_000_000);
    }

    /// Pid reuse within one command must not merge the two identities.
    /// Before #18 both execves would have lived under the same tree key
    /// (pid=200) and the second child would have been mis-attached as
    /// a sibling/descendant of the first.
    #[test]
    fn exec_tree_disambiguates_pid_reuse_via_start_time_ns() {
        let events = vec![
            process_start(0.9, 100, 1_000_000),
            execve(1.0, 100, 1, "/bin/bash"),
            // First child lifecycle
            process_start(1.05, 200, 2_000_000),
            execve(1.1, 200, 100, "/bin/ls"),
            process_exit(1.2, 200),
            // Same pid reused after the exit. start_time_ns differs.
            process_start(1.3, 200, 3_000_000),
            execve(1.4, 200, 100, "/bin/pwd"),
        ];
        let groups = vec![group_covering(&events)];
        let trees = build_exec_trees(&groups, &events);
        let t = &trees[0];
        // bash + ls + pwd — three separate nodes.
        assert_eq!(t.len(), 3, "pid reuse must yield two distinct children");
        let bash = &t[0];
        let ls = &t[1];
        let pwd = &t[2];
        assert_eq!(bash.pid, 100);
        assert_eq!(ls.pid, 200);
        assert_eq!(ls.start_time_ns, 2_000_000);
        assert_eq!(pwd.pid, 200);
        assert_eq!(pwd.start_time_ns, 3_000_000);
        // Both children of bash at depth 2 — neither nested under the other.
        assert_eq!(ls.depth, 2);
        assert_eq!(pwd.depth, 2);
    }
}
