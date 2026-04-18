use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "bloodhound")]
#[command(about = "eBPF-based behavioral tracing daemon")]
pub struct Cli {
    /// Target user UID to trace (audit login UID)
    #[arg(long)]
    pub uid: u32,

    /// Ports to exclude from packet capture (comma-separated)
    #[arg(long, default_value = "22", value_delimiter = ',')]
    pub exclude_ports: Vec<u16>,

    /// Ring buffer size in bytes (must be power of 2)
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    pub ring_buffer_size: u32,

    /// Enable opt-in rich extraction for `sendfile` and `splice`.
    ///
    /// These syscalls dominate event volume on file-serving workloads
    /// (10K+/sec is common). Disabled by default. When enabled, pair with
    /// `--ring-buffer-size` of at least 32 MiB to avoid drops under load.
    #[arg(long, default_value_t = false)]
    pub enable_rich_sendfile: bool,
}
