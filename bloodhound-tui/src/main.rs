mod app;
mod command_reconstructor;
mod correlator;
mod event_model;
mod keybinds;
mod ui;

use std::fs;
use std::io;
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

    // Parse NDJSON
    let content = fs::read_to_string(&cli.file)
        .with_context(|| format!("Cannot read file: {}", cli.file))?;

    let mut events: Vec<BehaviorEvent> = Vec::new();
    let mut parse_errors = 0;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<BehaviorEvent>(line) {
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
        bail!("No valid events found in {}", cli.file);
    }

    if parse_errors > 0 {
        eprintln!(
            "Loaded {} events ({} lines failed to parse)",
            events.len(),
            parse_errors,
        );
    }

    // Sort events by timestamp
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

    // Reconstruct commands
    let commands = reconstruct_commands(&tty_writes);

    // Filter out empty commands: the \r\n double-flush and bracketed paste
    // mode sequences produce empty entries that would steal events from
    // the preceding real command.
    let commands: Vec<_> = commands
        .into_iter()
        .filter(|c| !c.command.trim().is_empty())
        .collect();

    // Correlate events to commands
    let groups = correlate(&commands, &events);

    // Build decoded TTY output per command group.
    // For each group, collect tty_write data in the group's time window
    // and decode it into printable text lines.
    let tty_output = build_tty_output(&groups, &events);

    // Build execve process trees per command group.
    let exec_trees = build_exec_trees(&groups, &events);

    // Extract file basename for display
    let file_display = std::path::Path::new(&cli.file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&cli.file)
        .to_string();

    // Parse timezone offset
    let tz_offset = FixedOffset::east_opt(parse_tz_offset(&cli.timezone)?)
        .ok_or_else(|| anyhow::anyhow!("Invalid timezone offset: {}", cli.timezone))?;

    // Compute boot time anchor.
    //
    // The eBPF timestamps are monotonic (bpf_ktime_get_ns / 1e9 = seconds since boot).
    // To show wall-clock time, we anchor the last event's monotonic timestamp to the
    // file's modification time (= roughly when the daemon last wrote), then derive
    // the boot instant.  This gives approximate wall-clock timestamps for all events.
    let file_mtime: DateTime<Utc> = fs::metadata(&cli.file)?
        .modified()?
        .into();
    let last_mono = events.last().map(|e| e.header.timestamp).unwrap_or(0.0);
    let boot_time_utc = file_mtime - chrono::Duration::milliseconds((last_mono * 1000.0) as i64);

    let app = App::new(groups, events, tty_output, exec_trees, file_display, boot_time_utc, tz_offset);

    // Run TUI
    run_tui(app)
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

/// Build execve process trees per command group using ppid chains.
///
/// For each CommandGroup, extract execve/execveat events, then organise
/// them into a depth-first tree based on ppid relationships. An execve
/// is considered a "root" (depth 1) if its ppid does not match any other
/// execve's pid within the same group.
fn build_exec_trees(
    groups: &[CommandGroup],
    events: &[BehaviorEvent],
) -> Vec<Vec<ExecChild>> {
    use std::collections::{HashMap, HashSet};

    groups
        .iter()
        .map(|group| {
            // Collect execve events in this group
            let execves: Vec<(usize, &BehaviorEvent)> = group
                .event_indices
                .iter()
                .filter_map(|&idx| events.get(idx).map(|e| (idx, e)))
                .filter(|(_, e)| e.event.name == "execve" || e.event.name == "execveat")
                .collect();

            if execves.is_empty() {
                return vec![];
            }

            // Build set of pids that have an execve in this group
            let execve_pids: HashSet<u32> =
                execves.iter().map(|(_, e)| e.header.pid).collect();

            // Partition into roots vs children based on ppid
            let mut children_of: HashMap<u32, Vec<(usize, &BehaviorEvent)>> = HashMap::new();
            let mut roots: Vec<(usize, &BehaviorEvent)> = Vec::new();

            for &(idx, ev) in &execves {
                let ppid = ev.header.ppid.unwrap_or(0);
                if execve_pids.contains(&ppid) {
                    children_of.entry(ppid).or_default().push((idx, ev));
                } else {
                    roots.push((idx, ev));
                }
            }

            // Sort roots by timestamp
            roots.sort_by(|a, b| {
                a.1.header
                    .timestamp
                    .partial_cmp(&b.1.header.timestamp)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            // Sort children within each parent by timestamp
            for children in children_of.values_mut() {
                children.sort_by(|a, b| {
                    a.1.header
                        .timestamp
                        .partial_cmp(&b.1.header.timestamp)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }

            // DFS to build flat tree
            let mut result = Vec::new();
            let root_count = roots.len();
            for (ri, (idx, ev)) in roots.into_iter().enumerate() {
                exec_tree_dfs(
                    ev.header.pid,
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
    pid: u32,
    depth: usize,
    idx: usize,
    ev: &BehaviorEvent,
    is_last: bool,
    children_of: &std::collections::HashMap<u32, Vec<(usize, &BehaviorEvent)>>,
    result: &mut Vec<ExecChild>,
) {
    let label = build_exec_label(ev);
    result.push(ExecChild {
        label,
        pid,
        depth,
        event_index: idx,
        is_last,
    });

    if let Some(children) = children_of.get(&pid) {
        let child_count = children.len();
        for (ci, &(child_idx, child_ev)) in children.iter().enumerate() {
            exec_tree_dfs(
                child_ev.header.pid,
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
