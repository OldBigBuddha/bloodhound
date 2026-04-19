use serde::Deserialize;

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
    Exec,
    Syscall,
    Files,
    Network,
}

impl BehaviorEvent {
    /// Categorize this event for tab filtering.
    pub fn category(&self) -> EventCategory {
        match self.event.name.as_str() {
            "execve" | "execveat" => EventCategory::Exec,
            "ingress" | "egress" | "connect" | "bind" | "listen" | "socket" | "sendto"
            | "recvfrom" => EventCategory::Network,
            "openat" | "mkdir" | "mkdirat" | "rmdir" | "unlink" | "unlinkat" | "rename"
            | "renameat2" | "symlink" | "symlinkat" | "link" | "linkat" | "chmod" | "fchmod"
            | "fchmodat" | "chown" | "fchown" | "fchownat" | "truncate" | "ftruncate"
            | "chdir" | "fchdir" | "mount" | "umount2" => EventCategory::Files,
            _ => EventCategory::Syscall,
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
    pub fn summary_line(&self) -> String {
        let name = &self.event.name;
        let pid = self.header.pid;
        let rc = self
            .return_code
            .map(|r| format!(" rc={}", r))
            .unwrap_or_default();

        let detail = match self.event.name.as_str() {
            "execve" | "execveat" => {
                if let Some(args) = &self.args {
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
                }
            }
            "openat" => {
                if let Some(args) = &self.args {
                    let filename = args
                        .get("filename")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let flags = args
                        .get("flags")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join("|")
                        })
                        .unwrap_or_default();
                    format!(" {} ({})", filename, flags)
                } else {
                    String::new()
                }
            }
            "connect" | "bind" | "sendto" | "recvfrom" => {
                if let Some(args) = &self.args {
                    let addr = args.get("addr").and_then(|v| v.as_str()).unwrap_or("?");
                    let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                    format!(" {}:{}", addr, port)
                } else {
                    String::new()
                }
            }
            "ingress" | "egress" => {
                if let Some(args) = &self.args {
                    let ifindex = args.get("ifindex").and_then(|v| v.as_u64()).unwrap_or(0);
                    format!(" if={}", ifindex)
                } else {
                    String::new()
                }
            }
            _ => {
                // For file-related events, try to show filename
                if let Some(args) = &self.args {
                    if let Some(filename) = args.get("filename").and_then(|v| v.as_str()) {
                        format!(" {}", filename)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            }
        };

        format!("{}{} (pid:{}{})", name, detail, pid, rc)
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
    fn test_category_exec() {
        assert_eq!(make_event("TRACEPOINT", "execve").category(), EventCategory::Exec);
        assert_eq!(make_event("TRACEPOINT", "execveat").category(), EventCategory::Exec);
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
    }

    #[test]
    fn test_category_syscall() {
        assert_eq!(make_event("SYSCALL", "42").category(), EventCategory::Syscall);
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
        assert_eq!(event.category(), EventCategory::Exec);
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
