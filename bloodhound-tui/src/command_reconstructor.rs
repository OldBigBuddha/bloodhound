use base64::Engine;

/// A single reconstructed command from tty_write events.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CommandEntry {
    /// The reconstructed command string (after control char processing).
    pub command: String,
    /// Timestamp of the first tty byte that contributed.
    pub start_timestamp: f64,
    /// Timestamp of the Enter keystroke (or last byte if no Enter).
    pub end_timestamp: f64,
}

/// Shell process names to filter for command reconstruction.
const SHELL_COMMS: &[&str] = &["bash", "sh", "zsh", "fish", "dash", "ksh", "tcsh", "csh"];

/// Reconstruct user commands from a sequence of tty_write events.
///
/// Each tty_write event contains base64-encoded raw bytes of terminal I/O.
/// We filter to events from shell processes (comm = bash/sh/zsh/etc.),
/// process control characters and ANSI escapes, split on newlines,
/// and strip the shell prompt prefix to extract the actual command.
pub fn reconstruct_commands(tty_write_events: &[(f64, String, String)]) -> Vec<CommandEntry> {
    let mut commands = Vec::new();
    let mut buf = String::new();
    let mut start_ts = 0.0_f64;
    let mut has_start = false;
    let mut in_escape = false;
    // Track OSC (Operating System Command) escape sequences: ESC ] ... BEL/ST
    let mut in_osc = false;

    for (timestamp, data_b64, comm) in tty_write_events {
        // Only process events from shell processes
        if !SHELL_COMMS.contains(&comm.as_str()) {
            continue;
        }

        let raw = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if !has_start {
            start_ts = *timestamp;
            has_start = true;
        }

        for &byte in &raw {
            // Handle OSC sequences: ESC ] ... BEL(0x07) or ESC \
            if in_osc {
                if byte == 0x07 {
                    // BEL terminates OSC
                    in_osc = false;
                }
                // Also terminated by ST (ESC \), but we handle ESC separately
                continue;
            }

            if in_escape {
                if byte == b']' {
                    // Start of OSC sequence
                    in_escape = false;
                    in_osc = true;
                    continue;
                }
                // Consuming a CSI escape sequence: ESC [ ... <letter>
                if byte.is_ascii_alphabetic() || byte == b'~' {
                    in_escape = false;
                }
                continue;
            }

            match byte {
                b'\r' | b'\n' => {
                    // Flush command, stripping prompt prefix
                    let cmd = strip_prompt(&buf);
                    commands.push(CommandEntry {
                        command: cmd,
                        start_timestamp: start_ts,
                        end_timestamp: *timestamp,
                    });
                    buf.clear();
                    has_start = false;
                }
                0x7f => {
                    // Backspace (DEL)
                    buf.pop();
                }
                0x03 => {
                    // Ctrl-C: flush with ^C marker
                    buf.push_str("^C");
                    let cmd = strip_prompt(&buf);
                    commands.push(CommandEntry {
                        command: cmd,
                        start_timestamp: start_ts,
                        end_timestamp: *timestamp,
                    });
                    buf.clear();
                    has_start = false;
                }
                0x04 => {
                    // Ctrl-D: flush with ^D marker
                    buf.push_str("^D");
                    let cmd = strip_prompt(&buf);
                    commands.push(CommandEntry {
                        command: cmd,
                        start_timestamp: start_ts,
                        end_timestamp: *timestamp,
                    });
                    buf.clear();
                    has_start = false;
                }
                0x1b => {
                    // Start of escape sequence
                    in_escape = true;
                }
                0x09 => {
                    // Tab - likely tab completion
                    buf.push('\t');
                }
                0x15 => {
                    // Ctrl-U: clear line
                    buf.clear();
                }
                0x17 => {
                    // Ctrl-W: delete last word
                    let trimmed = buf.trim_end();
                    if let Some(pos) = trimmed.rfind(' ') {
                        buf.truncate(pos + 1);
                    } else {
                        buf.clear();
                    }
                }
                b if b.is_ascii_graphic() || b == b' ' => {
                    buf.push(byte as char);
                }
                _ => {
                    // Ignore other control characters
                }
            }
        }
    }

    // Flush remaining buffer if non-empty
    if !buf.is_empty() {
        let last_ts = tty_write_events
            .last()
            .map(|(ts, _, _)| *ts)
            .unwrap_or(start_ts);
        let cmd = strip_prompt(&buf);
        commands.push(CommandEntry {
            command: cmd,
            start_timestamp: start_ts,
            end_timestamp: last_ts,
        });
    }

    commands
}

/// Strip the shell prompt prefix from a reconstructed line.
///
/// After ANSI escape stripping, a typical bash prompt+command looks like:
///   `testuser@localhost:~$ ls -la /etc/`
///
/// We detect `$ ` or `# ` as the prompt delimiter and extract whatever
/// follows. If no prompt is found, the line is returned as-is.
fn strip_prompt(line: &str) -> String {
    // Look for the last occurrence of "$ " or "# " which marks the end of the prompt.
    // Use rfind to handle edge cases like commands that contain "$ ".
    if let Some(pos) = line.rfind("$ ") {
        return line[pos + 2..].to_string();
    }
    if let Some(pos) = line.rfind("# ") {
        return line[pos + 2..].to_string();
    }
    // No prompt found, return as-is
    line.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    /// Helper: create events with comm="bash" (shell process)
    fn events_from(items: &[(f64, &str)]) -> Vec<(f64, String, String)> {
        items
            .iter()
            .map(|(ts, s)| (*ts, b64(s), "bash".to_string()))
            .collect()
    }

    /// Helper: create events with an arbitrary comm
    fn events_with_comm(items: &[(f64, &str, &str)]) -> Vec<(f64, String, String)> {
        items
            .iter()
            .map(|(ts, s, comm)| (*ts, b64(s), comm.to_string()))
            .collect()
    }

    #[test]
    fn test_simple_command() {
        let events = events_from(&[(1.0, "l"), (1.1, "s"), (1.2, "\r")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "ls");
    }

    #[test]
    fn test_backspace() {
        let events = events_from(&[(1.0, "l"), (1.1, "x"), (1.2, "\x7f"), (1.3, "s"), (1.4, "\r")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "ls");
    }

    #[test]
    fn test_ctrl_c() {
        let events = events_from(&[(1.0, "f"), (1.1, "o"), (1.2, "o"), (1.3, "\x03")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "foo^C");
    }

    #[test]
    fn test_ctrl_d() {
        let events = events_from(&[(1.0, "e"), (1.1, "x"), (1.2, "\x04")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "ex^D");
    }

    #[test]
    fn test_multi_command() {
        let events = events_from(&[
            (1.0, "ls"),
            (1.1, "\r"),
            (2.0, "cd /tmp"),
            (2.1, "\r"),
        ]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].command, "ls");
        assert_eq!(cmds[1].command, "cd /tmp");
    }

    #[test]
    fn test_ansi_escape_stripped() {
        // "ls" then ESC [ 3 2 m (color code) then "\r"
        let events = events_from(&[(1.0, "ls\x1b[32m"), (1.1, "\r")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "ls");
    }

    #[test]
    fn test_empty_enter() {
        let events = events_from(&[(1.0, "\r")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "");
    }

    #[test]
    fn test_ctrl_u_clears_line() {
        let events = events_from(&[(1.0, "hello"), (1.1, "\x15"), (1.2, "world"), (1.3, "\r")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "world");
    }

    #[test]
    fn test_ctrl_w_deletes_word() {
        let events = events_from(&[(1.0, "git add"), (1.1, "\x17"), (1.2, "status"), (1.3, "\r")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "git status");
    }

    #[test]
    fn test_backspace_on_empty_buffer() {
        let events = events_from(&[(1.0, "\x7f"), (1.1, "ls"), (1.2, "\r")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "ls");
    }

    #[test]
    fn test_remaining_buffer_flushed() {
        let events = events_from(&[(1.0, "vim")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "vim");
    }

    #[test]
    fn test_timestamps_correct() {
        let events = events_from(&[(1.0, "l"), (1.5, "s"), (2.0, "\r")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds[0].start_timestamp, 1.0);
        assert_eq!(cmds[0].end_timestamp, 2.0);
    }

    #[test]
    fn test_multi_byte_event() {
        // Single tty_write event with full command + enter
        let events = events_from(&[(1.0, "ls -la\r")]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "ls -la");
    }

    #[test]
    fn test_non_shell_events_filtered_out() {
        // Events from non-shell processes should be ignored
        let events = events_with_comm(&[
            (1.0, "output from ls\r\n", "ls"),
            (2.0, "cat data\r\n", "cat"),
            (3.0, "echo hello\r", "bash"),
        ]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "echo hello");
    }

    #[test]
    fn test_prompt_stripping() {
        // Simulate bash echoing prompt + command
        let events = events_from(&[
            (1.0, "user@host:~$ ls -la"),
            (1.1, "\r"),
        ]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "ls -la");
    }

    #[test]
    fn test_root_prompt_stripping() {
        // Root prompt uses # instead of $
        let events = events_from(&[
            (1.0, "root@host:~# cat /etc/passwd"),
            (1.1, "\r"),
        ]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "cat /etc/passwd");
    }

    #[test]
    fn test_osc_sequence_stripped() {
        // OSC: ESC ] 0 ; title BEL  (terminal title setting)
        let events = events_from(&[
            (1.0, "\x1b]0;user@host: ~\x07"),  // OSC title
            (1.1, "$ pwd"),
            (1.2, "\r"),
        ]);
        let cmds = reconstruct_commands(&events);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "pwd");
    }

    #[test]
    fn test_realistic_bash_cycle() {
        // Simulate the real bash tty_write pattern:
        // 1. Bracketed paste mode on
        // 2. OSC title + prompt with ANSI colors
        // 3. Echoed command
        // 4. \r\n
        // 5. Bracketed paste mode off
        let events = events_from(&[
            (1.0, "\x1b[?2004h"),                      // bracketed paste mode on
            (1.0, "\x1b]0;user@host: ~\x07"),           // OSC title
            (1.0, "\x1b[01;32muser@host\x1b[00m:"),     // colored user@host
            (1.0, "\x1b[01;34m~\x1b[00m$ "),             // colored ~ and prompt
            (1.1, "cat /etc/hostname"),                   // echoed command
            (1.1, "\r\n"),                                // newline
            (1.1, "\x1b[?2004l\r"),                      // bracketed paste mode off
        ]);
        let cmds = reconstruct_commands(&events);
        // Should produce one command: "cat /etc/hostname"
        let non_empty: Vec<_> = cmds.iter().filter(|c| !c.command.is_empty()).collect();
        assert_eq!(non_empty.len(), 1);
        assert_eq!(non_empty[0].command, "cat /etc/hostname");
    }
}
