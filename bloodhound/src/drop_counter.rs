//! Userspace drop accounting.
//!
//! The BPF programs maintain a kernel-side cumulative count of ring
//! buffer overflow events. Heartbeat synthesis and the warning emitter
//! both read a userspace `Arc<AtomicU64>` instead — `bridge_bpf_drop_counter`
//! is the task that closes the loop by periodically copying the BPF
//! total into the userspace counter (issue #28).

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray};
use log::warn;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

/// Shared cumulative drop count, populated by `bridge_bpf_drop_counter`
/// and read by heartbeat synthesis and `poll_drop_counter`.
pub type DropCounter = Arc<AtomicU64>;

pub fn new_counter() -> DropCounter {
    Arc::new(AtomicU64::new(0))
}

/// Reads the cumulative drop count maintained by BPF programs.
///
/// The production implementation sums a `PerCpuArray<u64>` map; tests
/// supply fakes so the bridge loop can be exercised without a real
/// kernel.
pub trait DropCountReader: Send + 'static {
    fn read_total(&mut self) -> Result<u64>;
}

/// Production reader: sums the per-CPU slots of the BPF `DROP_COUNT`
/// map.
pub struct BpfDropCountReader {
    map: PerCpuArray<MapData, u64>,
}

impl BpfDropCountReader {
    pub fn new(map: PerCpuArray<MapData, u64>) -> Self {
        Self { map }
    }
}

impl DropCountReader for BpfDropCountReader {
    fn read_total(&mut self) -> Result<u64> {
        let values = self
            .map
            .get(&0, 0)
            .context("read DROP_COUNT per-cpu map")?;
        Ok(values.iter().sum())
    }
}

/// Periodically copy the BPF-side drop total into `counter`.
///
/// Without this bridge the userspace counter stays at 0 forever — the
/// heartbeat task then never sets `gap_detected` and the warning
/// emitter never fires (issue #28).
///
/// Read errors are logged but do not stop the loop, so transient map
/// access failures cannot silently disable drop accounting.
pub async fn bridge_bpf_drop_counter<R: DropCountReader>(
    mut reader: R,
    counter: DropCounter,
    interval: Duration,
) {
    if interval.is_zero() {
        return;
    }

    let mut ticker = time::interval(interval);
    // `tokio::time::interval` fires immediately at t=0; skip that tick
    // so the first real sample lines up with the configured cadence.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        match reader.read_total() {
            Ok(total) => counter.store(total, Ordering::Relaxed),
            Err(e) => warn!("failed to read BPF drop counter: {e:#}"),
        }
    }
}

/// Poll the drop counter periodically and emit warnings to stderr.
pub async fn poll_drop_counter(counter: DropCounter) {
    let mut last_count: u64 = 0;
    let mut interval = time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let current_count = counter.load(Ordering::Relaxed);
        let delta = current_count.wrapping_sub(last_count);

        if delta > 0 {
            warn!(
                "Ring buffer overflow: {} events dropped (total: {})",
                delta, current_count
            );
            eprintln!(
                "WARNING: Ring buffer overflow: {} events dropped (total: {})",
                delta, current_count
            );
            last_count = current_count;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reader backed by a shared atomic so a test can simulate the BPF
    /// counter advancing while the bridge task is running.
    struct FakeReader(Arc<AtomicU64>);
    impl DropCountReader for FakeReader {
        fn read_total(&mut self) -> Result<u64> {
            Ok(self.0.load(Ordering::Relaxed))
        }
    }

    /// Reader that always returns an error — used to verify the bridge
    /// survives transient read failures instead of dying silently.
    struct FailingReader;
    impl DropCountReader for FailingReader {
        fn read_total(&mut self) -> Result<u64> {
            Err(anyhow::anyhow!("simulated read failure"))
        }
    }

    #[tokio::test]
    async fn bridge_mirrors_bpf_counter_into_userspace_counter() {
        let bpf_side = Arc::new(AtomicU64::new(0));
        let counter = new_counter();

        let bridge = tokio::spawn(bridge_bpf_drop_counter(
            FakeReader(bpf_side.clone()),
            counter.clone(),
            Duration::from_millis(20),
        ));

        bpf_side.store(7, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            counter.load(Ordering::Relaxed),
            7,
            "bridge must mirror the BPF total into the userspace counter"
        );

        bpf_side.store(42, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            counter.load(Ordering::Relaxed),
            42,
            "bridge must keep polling — not just sample once"
        );

        bridge.abort();
    }

    #[tokio::test]
    async fn bridge_survives_reader_errors_without_corrupting_counter() {
        let counter = new_counter();
        counter.store(99, Ordering::Relaxed);

        let bridge = tokio::spawn(bridge_bpf_drop_counter(
            FailingReader,
            counter.clone(),
            Duration::from_millis(20),
        ));

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            counter.load(Ordering::Relaxed),
            99,
            "failed reads must not overwrite the counter"
        );
        assert!(
            !bridge.is_finished(),
            "bridge must keep polling on read errors"
        );

        bridge.abort();
    }

    #[tokio::test]
    async fn zero_interval_disables_bridge() {
        let counter = new_counter();
        let reader = FakeReader(Arc::new(AtomicU64::new(123)));
        bridge_bpf_drop_counter(reader, counter.clone(), Duration::ZERO).await;
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
