use anyhow::Result;
use aya::maps::ring_buf::RingBuf;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::drop_counter::DropCounter;

/// Consume events from the BPF ring buffer asynchronously.
/// Sends raw event bytes to the processing channel.
pub async fn consume_ring_buffer(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<Vec<u8>>,
    _drop_counter: DropCounter,
) -> Result<()> {
    let fd = ring_buf.as_raw_fd();
    let async_fd = AsyncFd::new(fd)?;

    loop {
        // Wait for data to be available via epoll
        let mut guard = async_fd.readable().await?;

        // Drain all available events
        while let Some(item) = ring_buf.next() {
            let data = item.to_vec();
            if tx.send(data).await.is_err() {
                // Receiver dropped, shutting down
                return Ok(());
            }
        }

        guard.clear_ready();
    }
}
