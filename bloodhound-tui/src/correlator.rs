use crate::command_reconstructor::CommandEntry;
use crate::event_model::BehaviorEvent;

/// A group of events correlated to a single user command.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CommandGroup {
    /// The reconstructed command string.
    pub command: String,
    /// Timestamp when the command was entered.
    pub timestamp: f64,
    /// Indices into the global event list that belong to this command.
    pub event_indices: Vec<usize>,
}

/// Correlate events to commands based on timestamp windows.
///
/// Each command defines a time window: from its end_timestamp to the
/// next command's end_timestamp. All behavioural events falling in
/// that window are assigned to the command.
///
/// TTY events (rendered separately as the command + output panes) and
/// userspace-synthesised meta events (`LIFECYCLE`, `HEARTBEAT`) are
/// excluded — they are not user-attributable and would inflate the
/// detail pane's per-command event counts.
///
/// Events before the first command go to a synthetic "[pre-session]" group.
pub fn correlate(
    commands: &[CommandEntry],
    events: &[BehaviorEvent],
) -> Vec<CommandGroup> {
    let is_correlated = |e: &BehaviorEvent| !e.is_tty() && !e.is_synthetic();

    if commands.is_empty() {
        // No commands found: put all correlated events in a single group
        let event_indices: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| is_correlated(e))
            .map(|(i, _)| i)
            .collect();
        return vec![CommandGroup {
            command: "[no commands detected]".to_string(),
            timestamp: events.first().map(|e| e.header.timestamp).unwrap_or(0.0),
            event_indices,
        }];
    }

    let mut groups: Vec<CommandGroup> = Vec::with_capacity(commands.len() + 1);

    // Collect correlated event indices sorted by timestamp (they should already be)
    let non_tty: Vec<(usize, f64)> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| is_correlated(e))
        .map(|(i, e)| (i, e.header.timestamp))
        .collect();

    // Build time boundaries from commands
    // boundary[i] = commands[i].end_timestamp
    let boundaries: Vec<f64> = commands.iter().map(|c| c.end_timestamp).collect();

    // Pre-session: events before first command
    let first_boundary = boundaries[0];
    let pre_indices: Vec<usize> = non_tty
        .iter()
        .filter(|(_, ts)| *ts < first_boundary)
        .map(|(i, _)| *i)
        .collect();

    if !pre_indices.is_empty() {
        groups.push(CommandGroup {
            command: "[pre-session]".to_string(),
            timestamp: non_tty.first().map(|(_, ts)| *ts).unwrap_or(0.0),
            event_indices: pre_indices,
        });
    }

    // For each command, assign events in [command_N.end_ts, command_N+1.end_ts)
    for (ci, cmd) in commands.iter().enumerate() {
        let window_start = cmd.end_timestamp;
        let window_end = if ci + 1 < boundaries.len() {
            boundaries[ci + 1]
        } else {
            f64::MAX
        };

        let event_indices: Vec<usize> = non_tty
            .iter()
            .filter(|(_, ts)| *ts >= window_start && *ts < window_end)
            .map(|(i, _)| *i)
            .collect();

        groups.push(CommandGroup {
            command: cmd.command.clone(),
            timestamp: cmd.end_timestamp,
            event_indices,
        });
    }

    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_model::*;

    fn make_cmd(command: &str, end_ts: f64) -> CommandEntry {
        CommandEntry {
            command: command.to_string(),
            start_timestamp: end_ts - 0.5,
            end_timestamp: end_ts,
        }
    }

    fn make_event_at(name: &str, ts: f64) -> BehaviorEvent {
        make_typed_event_at("TRACEPOINT", name, ts)
    }

    fn make_typed_event_at(event_type: &str, name: &str, ts: f64) -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeader {
                timestamp: ts,
                auid: 1000,
                sessionid: 1,
                pid: 42,
                ppid: Some(1),
                comm: "bash".to_string(),
            },
            event: EventType {
                event_type: event_type.to_string(),
                name: name.to_string(),
                layer: "behavior".to_string(),
            },
            proc: None,
            args: None,
            return_code: Some(0),
        }
    }

    #[test]
    fn test_basic_correlation() {
        let commands = vec![make_cmd("ls", 1.0), make_cmd("pwd", 3.0)];
        let events = vec![
            make_event_at("execve", 1.5),  // after "ls", before "pwd"
            make_event_at("openat", 2.0),  // after "ls", before "pwd"
            make_event_at("execve", 3.5),  // after "pwd"
        ];

        let groups = correlate(&commands, &events);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].command, "ls");
        assert_eq!(groups[0].event_indices, vec![0, 1]);
        assert_eq!(groups[1].command, "pwd");
        assert_eq!(groups[1].event_indices, vec![2]);
    }

    #[test]
    fn test_pre_session_events() {
        let commands = vec![make_cmd("ls", 5.0)];
        let events = vec![
            make_event_at("openat", 1.0), // before any command
            make_event_at("execve", 6.0), // after "ls"
        ];

        let groups = correlate(&commands, &events);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].command, "[pre-session]");
        assert_eq!(groups[0].event_indices, vec![0]);
        assert_eq!(groups[1].command, "ls");
        assert_eq!(groups[1].event_indices, vec![1]);
    }

    #[test]
    fn test_no_commands() {
        let commands = vec![];
        let events = vec![
            make_event_at("openat", 1.0),
            make_event_at("execve", 2.0),
        ];

        let groups = correlate(&commands, &events);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].command, "[no commands detected]");
        assert_eq!(groups[0].event_indices, vec![0, 1]);
    }

    #[test]
    fn test_tty_events_excluded() {
        let commands = vec![make_cmd("ls", 1.0)];
        let events = vec![
            make_event_at("tty_read", 0.5),
            make_event_at("tty_write", 1.5),
            make_event_at("execve", 1.5),
        ];

        let groups = correlate(&commands, &events);
        // tty events should be excluded from all groups
        let all_indices: Vec<usize> = groups.iter().flat_map(|g| &g.event_indices).copied().collect();
        assert!(!all_indices.contains(&0)); // tty_read
        assert!(!all_indices.contains(&1)); // tty_write
        assert!(all_indices.contains(&2));  // execve
    }

    #[test]
    fn test_synthetic_events_excluded() {
        let commands = vec![make_cmd("ls", 1.0)];
        let events = vec![
            make_typed_event_at("LIFECYCLE", "process_start", 1.4),
            make_typed_event_at("LIFECYCLE", "process_fork", 1.45),
            make_typed_event_at("LIFECYCLE", "process_exit", 1.6),
            make_typed_event_at("HEARTBEAT", "heartbeat", 1.7),
            make_event_at("execve", 1.5),
        ];

        let groups = correlate(&commands, &events);
        let all_indices: Vec<usize> = groups
            .iter()
            .flat_map(|g| &g.event_indices)
            .copied()
            .collect();
        // LIFECYCLE / HEARTBEAT must not be counted per-command.
        for i in 0..=3 {
            assert!(
                !all_indices.contains(&i),
                "synthetic event at idx {} leaked into a group",
                i
            );
        }
        assert!(all_indices.contains(&4)); // execve
    }
}
