# bloodhound-tui

A terminal UI viewer for [Bloodhound](../README.md) NDJSON trace logs, inspired by [wagoodman/dive](https://github.com/wagoodman/dive).

## Overview

`bloodhound-tui` reconstructs user commands from raw `tty_read` events and correlates them with the resulting system activity — executed programs, syscalls, file operations, and network traffic — providing a structured, navigable view of user behavior traces.

```
┌─ History (4 commands) ──────┬─ Details ──────────────────────────────┐
│ ▸ ls -la              (4)   │ [All] [Exec] [Syscall] [Files] [Net]  │
│   cat /etc/passwd      (5)  │                                       │
│   curl http://exampl…  (7)  │  EXEC  execve /usr/bin/ls [ls -la]    │
│   mkdir /tmp/test      (3)  │  FILE  openat /home/user (O_RDONLY..) │
│                             │  FILE  openat /home/user/.bashrc …    │
│                             │  SYS   write (pid:5002 rc=512)        │
│                             │  SYS   231 (pid:5002 rc=0)            │
├─────────────────────────────┴────────────────────────────────────────┤
│ sample.ndjson │ 42 events total │ Command 1/4 │ 4 events shown      │
└──────────────────────────────────────────────────────────────────────┘
```

## Installation

```bash
cargo build -p bloodhound-tui --release
```

The binary will be at `target/release/bloodhound-tui`.

## Usage

```bash
bloodhound-tui <path-to-ndjson-file>
```

The input file must be NDJSON output from the Bloodhound daemon (typically `/var/log/bloodhound.ndjson` on the guest VM).

Files larger than 50 MB will produce a warning prompt before loading.

## Keybindings

| Key              | Action                                      |
|------------------|---------------------------------------------|
| `j` / `↓`       | Move down (history selection or scroll)     |
| `k` / `↑`       | Move up                                     |
| `g`              | Jump to top                                 |
| `G`              | Jump to bottom                              |
| `Tab`            | Switch active pane (History ↔ Details)       |
| `1`–`5`          | Switch detail tab (All/Exec/Syscall/Files/Network) |
| `h` / `←`        | Previous tab (when in Details pane)         |
| `l` / `→`        | Next tab (when in Details pane)             |
| `q` / `Esc`      | Quit                                        |

## Detail Tabs

| Tab       | Events shown                                              |
|-----------|-----------------------------------------------------------|
| **All**     | Every correlated event                                  |
| **Exec**    | `execve`, `execveat`                                    |
| **Syscall** | Raw syscalls and tracepoints not covered by other tabs  |
| **Files**   | `openat`, `mkdir`, `unlink`, `rename`, `chmod`, etc.    |
| **Network** | `connect`, `bind`, `sendto`, `recvfrom`, packet events  |

## How It Works

1. **Parse** — Reads the NDJSON file and deserializes each line into a `BehaviorEvent`.
2. **Reconstruct** — Extracts `tty_read` events, decodes Base64 data, and reconstructs command strings by processing control characters (backspace, Ctrl-C, ANSI escapes, etc.).
3. **Correlate** — Groups non-TTY events into time windows between consecutive Enter keystrokes.
4. **Display** — Renders an interactive two-pane TUI with category-colored event summaries.

## Development

```bash
# Run tests
cargo test -p bloodhound-tui

# Run with sample data
cargo run -p bloodhound-tui -- bloodhound-tui/testdata/sample.ndjson
```
