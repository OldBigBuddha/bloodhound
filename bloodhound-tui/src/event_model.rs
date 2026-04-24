use serde::Deserialize;
use std::collections::HashMap;

/// Syscall numbers (as string, since `event.name` is a string for
/// Tier 1 `SYSCALL` events) that have a Tier 2 rich-extraction
/// counterpart. Must stay aligned with `tier2_syscalls` in
/// `bloodhound/src/loader.rs`.
const TIER2_COVERED_NRS: &[&str] = &[
    "0",   // read
    "1",   // write
    "9",   // mmap
    "17",  // pread64
    "18",  // pwrite64
    "19",  // readv
    "20",  // writev
    "32",  // dup
    "33",  // dup2
    "40",  // sendfile (opt-in)
    "41",  // socket
    "42",  // connect
    "44",  // sendto
    "45",  // recvfrom
    "49",  // bind
    "50",  // listen
    "56",  // clone
    "59",  // execve
    "76",  // truncate
    "77",  // ftruncate
    "80",  // chdir
    "81",  // fchdir
    "82",  // rename
    "83",  // mkdir
    "84",  // rmdir
    "86",  // link
    "87",  // unlink
    "88",  // symlink
    "90",  // chmod
    "91",  // fchmod
    "92",  // chown
    "93",  // fchown
    "165", // mount
    "166", // umount2
    "257", // openat
    "258", // mkdirat
    "260", // fchownat
    "263", // unlinkat
    "265", // linkat
    "266", // symlinkat
    "268", // fchmodat
    "275", // splice (opt-in)
    "292", // dup3
    "316", // renameat2
    "322", // execveat
    "435", // clone3
];

/// Deserialized BehaviorEvent from Bloodhound NDJSON output.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct BehaviorEvent {
    pub header: EventHeader,
    pub event: EventType,
    #[serde(default)]
    pub proc: Option<ProcInfo>,
    #[serde(default)]
    pub args: Option<serde_json::Value>,
    #[serde(default)]
    pub return_code: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct EventHeader {
    pub timestamp: f64,
    pub auid: u32,
    pub sessionid: u32,
    pub pid: u32,
    #[serde(default)]
    pub ppid: Option<u32>,
    pub comm: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct EventType {
    #[serde(rename = "type")]
    pub event_type: String,
    pub name: String,
    pub layer: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ProcInfo {
    #[serde(default)]
    pub main_executable: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub tty: Option<String>,
}

/// Event category for tab filtering in the detail pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventCategory {
    Process,
    Security,
    Files,
    Network,
    /// Events that should not appear in any tab (tty shown in Output pane,
    /// raw Layer 2 syscalls are too low-level for user-facing display).
    Hidden,
}

impl BehaviorEvent {
    /// Categorize this event for tab filtering.
    pub fn category(&self) -> EventCategory {
        match self.event.name.as_str() {
            "execve" | "execveat" | "clone" | "clone3" => EventCategory::Process,

            "ingress" | "egress" | "connect" | "bind" | "listen" | "socket" | "sendto"
            | "recvfrom" => EventCategory::Network,

            "openat" | "read" | "write" | "mkdir" | "mkdirat" | "rmdir" | "unlink"
            | "unlinkat" | "rename" | "renameat2" | "symlink" | "symlinkat" | "link"
            | "linkat" | "chmod" | "fchmod" | "fchmodat" | "chown" | "fchown" | "fchownat"
            | "truncate" | "ftruncate" | "chdir" | "fchdir" | "mount" | "umount2"
            | "file_open" | "inode_unlink" | "inode_rename" => EventCategory::Files,

            "task_kill" | "bpf" | "ptrace_access_check" | "task_fix_setuid" => {
                EventCategory::Security
            }

            "tty_read" | "tty_write" => EventCategory::Hidden,
            _ if self.event.event_type == "SYSCALL" => EventCategory::Hidden,

            _ => EventCategory::Security,
        }
    }

    /// Check if this event is a tty_read.
    #[allow(dead_code)]
    pub fn is_tty_read(&self) -> bool {
        self.event.name == "tty_read"
    }

    /// Check if this event is a tty_write.
    pub fn is_tty_write(&self) -> bool {
        self.event.name == "tty_write"
    }

    /// Check if this event is a tty event (read or write).
    pub fn is_tty(&self) -> bool {
        self.event.name == "tty_read" || self.event.name == "tty_write"
    }

    /// Userspace-synthesised meta events (`LIFECYCLE`, `HEARTBEAT`).
    ///
    /// These are not user-attributable behavioural events and must be
    /// kept out of command-group correlation and the detail pane — they
    /// would otherwise inflate per-command event counts and obscure
    /// real syscall activity. Tree construction and identity resolution
    /// consume them via a separate path.
    pub fn is_synthetic(&self) -> bool {
        matches!(self.event.event_type.as_str(), "LIFECYCLE" | "HEARTBEAT")
    }

    /// True when a Tier 1 raw `SYSCALL` event describes a syscall that
    /// also has Tier 2 rich coverage.
    ///
    /// The daemon's `TIER2_BITMAP` already suppresses Tier 1 emission
    /// for these syscalls in-kernel, so duplicates should never reach
    /// us in a correctly-configured run. The check is defensive: it
    /// protects the detail pane from double-counting if a daemon ships
    /// with an incomplete bitmap or a newer Tier 2 that the kernel-side
    /// filter missed. The list is kept in sync with `tier2_syscalls`
    /// in `bloodhound/src/loader.rs`.
    pub fn is_redundant_tier1(&self) -> bool {
        if self.event.event_type != "SYSCALL" {
            return false;
        }
        TIER2_COVERED_NRS.contains(&self.event.name.as_str())
    }

    /// Format a one-line summary for display in the detail pane.
    ///
    /// File-related events use human-readable action labels (READ, WRITE,
    /// CREATE, DELETE, RENAME, PERM, OWNER, MOUNT, …) instead of raw syscall
    /// names. If `fd_table` is provided, `read`/`write` resolve their fd to
    /// the originating path (built from prior `openat` events).
    pub fn summary_line(&self, fd_table: Option<&HashMap<(u32, u32), String>>) -> String {
        let pid = self.header.pid;
        let rc = self
            .return_code
            .map(|r| format!(" rc={}", r))
            .unwrap_or_default();

        let (action, detail) = match self.event.name.as_str() {
            "execve" | "execveat" => {
                let detail = if let Some(args) = &self.args {
                    let filename = args
                        .get("filename")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let argv = args
                        .get("argv")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_default();
                    format!(" {} [{}]", filename, argv)
                } else {
                    String::new()
                };
                (self.event.name.as_str(), detail)
            }

            "clone" | "clone3" => {
                let detail = self
                    .args
                    .as_ref()
                    .and_then(|a| a.get("flags"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join("|")
                    })
                    .filter(|s| !s.is_empty())
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default();
                ("FORK", detail)
            }

            // openat → READ / WRITE based on flags.
            "openat" => {
                if let Some(args) = &self.args {
                    let filename = args
                        .get("filename")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let empty = Vec::new();
                    let flags: Vec<&str> = args
                        .get("flags")
                        .and_then(|v| v.as_array())
                        .unwrap_or(&empty)
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect();
                    let action = if flags.contains(&"O_WRONLY") || flags.contains(&"O_RDWR") {
                        "WRITE"
                    } else {
                        "READ"
                    };
                    (action, format!(" {}", filename))
                } else {
                    ("OPEN", String::new())
                }
            }

            "read" => ("READ", self.format_rw_detail(fd_table)),
            "write" => ("WRITE", self.format_rw_detail(fd_table)),

            "mkdir" | "mkdirat" => ("CREATE", self.format_path_detail()),
            "unlink" | "unlinkat" | "rmdir" => ("DELETE", self.format_path_detail()),
            "rename" | "renameat2" => ("RENAME", self.format_two_path_detail()),
            "symlink" | "symlinkat" | "link" | "linkat" => {
                ("LINK", self.format_two_path_detail())
            }
            "chmod" | "fchmodat" => ("PERM", self.format_path_detail()),
            "fchmod" => ("PERM", self.format_fd_detail()),
            "chown" | "fchownat" => ("OWNER", self.format_path_detail()),
            "fchown" => ("OWNER", self.format_fd_detail()),
            "truncate" => ("TRUNC", self.format_path_detail()),
            "ftruncate" => ("TRUNC", self.format_fd_detail()),
            "chdir" => ("CHDIR", self.format_path_detail()),
            "fchdir" => ("CHDIR", self.format_fd_detail()),
            "mount" => ("MOUNT", self.format_two_path_detail()),
            "umount2" => ("UMOUNT", self.format_path_detail()),

            "file_open" => ("OPEN", " (LSM)".to_string()),
            "inode_unlink" => ("DELETE", " (LSM)".to_string()),
            "inode_rename" => ("RENAME", " (LSM)".to_string()),

            "task_kill" => {
                let detail = if let Some(args) = &self.args {
                    let target = args.get("target_pid").and_then(|v| v.as_u64()).unwrap_or(0);
                    let sig = args.get("signal").and_then(|v| v.as_u64()).unwrap_or(0);
                    format!(" pid={} sig={}", target, sig)
                } else {
                    String::new()
                };
                ("KILL", detail)
            }
            "bpf" => {
                let detail = self
                    .args
                    .as_ref()
                    .and_then(|a| a.get("cmd"))
                    .and_then(|v| v.as_u64())
                    .map(|c| format!(" cmd={}", c))
                    .unwrap_or_default();
                ("BPF", detail)
            }
            "ptrace_access_check" => {
                let detail = self
                    .args
                    .as_ref()
                    .and_then(|a| a.get("target_pid"))
                    .and_then(|v| v.as_u64())
                    .map(|p| format!(" pid={}", p))
                    .unwrap_or_default();
                ("PTRACE", detail)
            }
            "task_fix_setuid" => {
                let detail = if let Some(args) = &self.args {
                    let old_uid = args.get("old_uid").and_then(|v| v.as_u64()).unwrap_or(0);
                    let new_uid = args.get("new_uid").and_then(|v| v.as_u64()).unwrap_or(0);
                    format!(" uid:{}→{}", old_uid, new_uid)
                } else {
                    String::new()
                };
                ("SETUID", detail)
            }

            "connect" | "bind" | "sendto" | "recvfrom" => {
                let detail = if let Some(args) = &self.args {
                    let addr = args.get("addr").and_then(|v| v.as_str()).unwrap_or("?");
                    let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                    format!(" {}:{}", addr, port)
                } else {
                    String::new()
                };
                (self.event.name.as_str(), detail)
            }
            "ingress" | "egress" => {
                let detail = if let Some(args) = &self.args {
                    let ifindex = args.get("ifindex").and_then(|v| v.as_u64()).unwrap_or(0);
                    format!(" if={}", ifindex)
                } else {
                    String::new()
                };
                (self.event.name.as_str(), detail)
            }

            _ => {
                let detail = if let Some(args) = &self.args {
                    if let Some(filename) = args.get("filename").and_then(|v| v.as_str()) {
                        format!(" {}", filename)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                (self.event.name.as_str(), detail)
            }
        };

        format!("{}{} (pid:{}{})", action, detail, pid, rc)
    }

    fn format_rw_detail(&self, fd_table: Option<&HashMap<(u32, u32), String>>) -> String {
        let Some(args) = &self.args else {
            return String::new();
        };
        let fd = args.get("fd").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let size = args
            .get("requested_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if let Some(table) = fd_table {
            if let Some(path) = table.get(&(self.header.pid, fd)) {
                return format!(" {} ({}b)", path, size);
            }
        }
        format!(" fd={} ({}b)", fd, size)
    }

    fn format_path_detail(&self) -> String {
        self.args
            .as_ref()
            .and_then(|a| a.get("filename"))
            .and_then(|v| v.as_str())
            .map(|f| format!(" {}", f))
            .unwrap_or_default()
    }

    fn format_fd_detail(&self) -> String {
        self.args
            .as_ref()
            .and_then(|a| a.get("fd"))
            .and_then(|v| v.as_u64())
            .map(|fd| format!(" fd={}", fd))
            .unwrap_or_default()
    }

    fn format_two_path_detail(&self) -> String {
        let Some(args) = &self.args else {
            return String::new();
        };
        let old = args.get("oldpath").and_then(|v| v.as_str()).unwrap_or("?");
        let new = args.get("newpath").and_then(|v| v.as_str()).unwrap_or("?");
        format!(" {} → {}", old, new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: &str, name: &str) -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeader {
                timestamp: 1.0,
                auid: 1000,
                sessionid: 1,
                pid: 42,
                ppid: Some(1),
                comm: "test".to_string(),
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
    fn test_category_process() {
        assert_eq!(make_event("TRACEPOINT", "execve").category(), EventCategory::Process);
        assert_eq!(make_event("TRACEPOINT", "execveat").category(), EventCategory::Process);
        assert_eq!(make_event("TRACEPOINT", "clone").category(), EventCategory::Process);
        assert_eq!(make_event("TRACEPOINT", "clone3").category(), EventCategory::Process);
    }

    #[test]
    fn test_category_network() {
        assert_eq!(make_event("PACKET", "ingress").category(), EventCategory::Network);
        assert_eq!(make_event("TRACEPOINT", "connect").category(), EventCategory::Network);
    }

    #[test]
    fn test_category_files() {
        assert_eq!(make_event("TRACEPOINT", "openat").category(), EventCategory::Files);
        assert_eq!(make_event("TRACEPOINT", "mkdir").category(), EventCategory::Files);
        assert_eq!(make_event("LSM", "file_open").category(), EventCategory::Files);
        assert_eq!(make_event("LSM", "inode_unlink").category(), EventCategory::Files);
        assert_eq!(make_event("LSM", "inode_rename").category(), EventCategory::Files);
    }

    #[test]
    fn test_category_security() {
        assert_eq!(make_event("LSM", "task_kill").category(), EventCategory::Security);
        assert_eq!(make_event("LSM", "bpf").category(), EventCategory::Security);
        assert_eq!(make_event("LSM", "ptrace_access_check").category(), EventCategory::Security);
        assert_eq!(make_event("LSM", "task_fix_setuid").category(), EventCategory::Security);
    }

    #[test]
    fn test_category_hidden() {
        assert_eq!(make_event("TTY", "tty_read").category(), EventCategory::Hidden);
        assert_eq!(make_event("TTY", "tty_write").category(), EventCategory::Hidden);
        assert_eq!(make_event("SYSCALL", "42").category(), EventCategory::Hidden);
    }

    #[test]
    fn test_is_tty_read() {
        assert!(make_event("TTY", "tty_read").is_tty_read());
        assert!(!make_event("TTY", "tty_write").is_tty_read());
    }

    #[test]
    fn test_parse_ndjson_line() {
        let json = r#"{"header":{"timestamp":1.5,"auid":1000,"sessionid":42,"pid":1234,"ppid":1,"comm":"bash"},"event":{"type":"TRACEPOINT","name":"execve","layer":"tooling"},"args":{"filename":"/usr/bin/ls","argv":["ls","-la"]},"return_code":0}"#;
        let event: BehaviorEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.header.pid, 1234);
        assert_eq!(event.event.name, "execve");
        assert_eq!(event.category(), EventCategory::Process);
    }

    #[test]
    fn test_parse_tty_event() {
        let json = r#"{"header":{"timestamp":1.0,"auid":1000,"sessionid":42,"pid":100,"comm":"bash"},"event":{"type":"TTY","name":"tty_read","layer":"intent"},"args":{"data":"bHM="}}"#;
        let event: BehaviorEvent = serde_json::from_str(json).unwrap();
        assert!(event.is_tty_read());
        let data = event.args.as_ref().unwrap().get("data").unwrap().as_str().unwrap();
        assert_eq!(data, "bHM="); // base64 for "ls"
    }

    #[test]
    fn test_parse_packet_event() {
        let json = r#"{"header":{"timestamp":2.0,"auid":0,"sessionid":0,"pid":0,"comm":""},"event":{"type":"PACKET","name":"ingress","layer":"behavior"},"args":{"data":"AAAA","ifindex":2}}"#;
        let event: BehaviorEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.category(), EventCategory::Network);
    }

    #[test]
    fn test_is_synthetic_lifecycle_and_heartbeat() {
        assert!(make_event("LIFECYCLE", "process_start").is_synthetic());
        assert!(make_event("LIFECYCLE", "process_fork").is_synthetic());
        assert!(make_event("LIFECYCLE", "process_exit").is_synthetic());
        assert!(make_event("HEARTBEAT", "heartbeat").is_synthetic());
        assert!(!make_event("TRACEPOINT", "execve").is_synthetic());
        assert!(!make_event("SYSCALL", "231").is_synthetic());
        assert!(!make_event("TTY", "tty_read").is_synthetic());
    }

    fn make_event_with_args(name: &str, args: serde_json::Value) -> BehaviorEvent {
        let mut e = make_event("TRACEPOINT", name);
        e.args = Some(args);
        e
    }

    #[test]
    fn test_summary_openat_rdonly() {
        let e = make_event_with_args(
            "openat",
            serde_json::json!({"filename":"/etc/passwd","flags":["O_RDONLY","O_CLOEXEC"],"mode":0}),
        );
        assert!(e.summary_line(None).starts_with("READ /etc/passwd"));
    }

    #[test]
    fn test_summary_openat_wronly() {
        let e = make_event_with_args(
            "openat",
            serde_json::json!({"filename":"/tmp/out.txt","flags":["O_WRONLY","O_CREAT"],"mode":420}),
        );
        assert!(e.summary_line(None).starts_with("WRITE /tmp/out.txt"));
    }

    #[test]
    fn test_summary_read_fd_fallback() {
        let e = make_event_with_args(
            "read",
            serde_json::json!({"fd":3,"fd_type":"regular","requested_size":4096}),
        );
        assert!(e.summary_line(None).starts_with("READ fd=3 (4096b)"));
    }

    #[test]
    fn test_summary_write_fd_fallback() {
        let e = make_event_with_args(
            "write",
            serde_json::json!({"fd":1,"fd_type":"tty","requested_size":256}),
        );
        assert!(e.summary_line(None).starts_with("WRITE fd=1 (256b)"));
    }

    #[test]
    fn test_summary_read_with_fd_table() {
        let mut fd_table = HashMap::new();
        fd_table.insert((42u32, 3u32), "/etc/passwd".to_string());
        let e = make_event_with_args(
            "read",
            serde_json::json!({"fd":3,"fd_type":"regular","requested_size":4096}),
        );
        assert!(e
            .summary_line(Some(&fd_table))
            .starts_with("READ /etc/passwd (4096b)"));
    }

    #[test]
    fn test_summary_read_without_fd_table_match() {
        let fd_table = HashMap::new();
        let e = make_event_with_args(
            "read",
            serde_json::json!({"fd":99,"fd_type":"other","requested_size":512}),
        );
        assert!(e
            .summary_line(Some(&fd_table))
            .starts_with("READ fd=99 (512b)"));
    }

    #[test]
    fn test_summary_file_actions() {
        let cases = [
            ("mkdir", serde_json::json!({"filename":"/tmp/d"}), "CREATE /tmp/d"),
            ("unlink", serde_json::json!({"filename":"/tmp/x"}), "DELETE /tmp/x"),
            ("rmdir", serde_json::json!({"filename":"/tmp/d"}), "DELETE /tmp/d"),
            ("chmod", serde_json::json!({"filename":"/etc/c"}), "PERM /etc/c"),
            ("fchmod", serde_json::json!({"fd":5}), "PERM fd=5"),
            ("chown", serde_json::json!({"filename":"/var/log"}), "OWNER /var/log"),
            ("truncate", serde_json::json!({"filename":"/tmp/l"}), "TRUNC /tmp/l"),
            ("chdir", serde_json::json!({"filename":"/home/u"}), "CHDIR /home/u"),
            ("umount2", serde_json::json!({"filename":"/mnt"}), "UMOUNT /mnt"),
        ];
        for (name, args, expected_prefix) in cases {
            let e = make_event_with_args(name, args);
            let s = e.summary_line(None);
            assert!(
                s.starts_with(expected_prefix),
                "{} → {} (expected prefix {})",
                name, s, expected_prefix
            );
        }
    }

    #[test]
    fn test_summary_two_path_actions() {
        let rename = make_event_with_args(
            "rename",
            serde_json::json!({"oldpath":"a.txt","newpath":"b.txt"}),
        );
        assert!(rename.summary_line(None).starts_with("RENAME a.txt → b.txt"));

        let symlink = make_event_with_args(
            "symlink",
            serde_json::json!({"oldpath":"/usr/bin/python3","newpath":"/usr/bin/python"}),
        );
        assert!(symlink
            .summary_line(None)
            .starts_with("LINK /usr/bin/python3 → /usr/bin/python"));

        let mount = make_event_with_args(
            "mount",
            serde_json::json!({"oldpath":"/dev/sda1","newpath":"/mnt"}),
        );
        assert!(mount.summary_line(None).starts_with("MOUNT /dev/sda1 → /mnt"));
    }

    #[test]
    fn test_is_redundant_tier1_drops_tier2_covered_syscalls() {
        // SYSCALL + NR that has Tier 2 coverage → redundant.
        assert!(make_event("SYSCALL", "257").is_redundant_tier1()); // openat
        assert!(make_event("SYSCALL", "32").is_redundant_tier1()); // dup
        assert!(make_event("SYSCALL", "435").is_redundant_tier1()); // clone3

        // SYSCALL without Tier 2 coverage → keep.
        assert!(!make_event("SYSCALL", "231").is_redundant_tier1()); // exit_group
        assert!(!make_event("SYSCALL", "72").is_redundant_tier1()); // fcntl (not in bitmap)

        // Non-SYSCALL event types must never be flagged regardless of name.
        assert!(!make_event("TRACEPOINT", "257").is_redundant_tier1());
        assert!(!make_event("TRACEPOINT", "openat").is_redundant_tier1());
    }
}
