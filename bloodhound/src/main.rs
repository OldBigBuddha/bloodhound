mod cli;
mod consumer;
mod deserializer;
mod drop_counter;
mod enricher;
mod loader;
mod packet_correlator;
mod serializer;
mod shutdown;

use anyhow::Result;
use aya::maps::ring_buf::RingBuf;
use clap::Parser;
use log::info;
use std::time::Duration;
use tokio::sync::mpsc;

use cli::Cli;
use packet_correlator::PacketCorrelator;
use serializer::Serializer;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Cli::parse();
    info!("Bloodhound starting: tracing uid={}", args.uid);
    eprintln!("Bloodhound starting: tracing uid={}", args.uid);

    // Load and attach BPF programs
    let mut bpf = loader::load_and_attach(&args)?;
    info!("BPF programs loaded and attached");
    eprintln!("BPF programs loaded and attached");

    // Set up shutdown handler
    let shutdown_tx = shutdown::shutdown_signal();
    let mut shutdown_rx = shutdown_tx.subscribe();

    // Set up drop counter
    let drop_count = drop_counter::new_counter();
    tokio::spawn(drop_counter::poll_drop_counter(drop_count.clone()));

    // Set up ring buffer consumer
    let map = bpf.take_map("EVENTS").unwrap();
    let ring_buf = RingBuf::try_from(map)?;
    let (event_tx, mut event_rx) = mpsc::channel::<Vec<u8>>(4096);

    // Spawn ring buffer consumer task
    let consumer_drop_count = drop_count.clone();
    let consumer_handle = tokio::spawn(async move {
        if let Err(e) =
            consumer::consume_ring_buffer(ring_buf, event_tx, consumer_drop_count).await
        {
            eprintln!("Ring buffer consumer error: {}", e);
        }
    });

    // Set up packet correlator and serializer
    let mut correlator = PacketCorrelator::new(args.uid);
    let mut output = Serializer::new();

    let drain_timeout = Duration::from_secs(5);

    // Main event processing loop
    loop {
        tokio::select! {
            Some(raw_event) = event_rx.recv() => {
                match deserializer::deserialize(&raw_event) {
                    Ok(mut event) => {
                        // Enrich with /proc info
                        enricher::enrich(&mut event);

                        // Packet correlation
                        if event.event.event_type == "PACKET" {
                            correlator.correlate(&mut event);
                        }

                        // Record socket events for packet correlation
                        if event.event.name == "connect" || event.event.name == "bind" {
                            correlator.record_socket(&event);
                        }

                        // Serialize to stdout
                        if let Err(e) = output.write_event(&event) {
                            eprintln!("Failed to write event: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to deserialize event: {}", e);
                    }
                }
            }

            _ = shutdown_rx.recv() => {
                eprintln!("Shutting down...");

                // Drain remaining events with timeout
                let deadline = tokio::time::Instant::now() + drain_timeout;
                loop {
                    tokio::select! {
                        Some(raw_event) = event_rx.recv() => {
                            if let Ok(mut event) = deserializer::deserialize(&raw_event) {
                                enricher::enrich(&mut event);
                                if event.event.event_type == "PACKET" {
                                    correlator.correlate(&mut event);
                                }
                                let _ = output.write_event(&event);
                            }
                        }
                        _ = tokio::time::sleep_until(deadline) => break,
                        else => break,
                    }
                }

                // Flush output
                if let Err(e) = output.flush() {
                    eprintln!("Failed to flush output: {}", e);
                }

                eprintln!("Shutdown complete");
                break;
            }
        }
    }

    consumer_handle.abort();
    Ok(())
}
