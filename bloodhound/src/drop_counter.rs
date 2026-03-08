use log::warn;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

/// Shared drop counter incremented by the ring buffer consumer
/// when the channel is full.
pub type DropCounter = Arc<AtomicU64>;

pub fn new_counter() -> DropCounter {
    Arc::new(AtomicU64::new(0))
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
