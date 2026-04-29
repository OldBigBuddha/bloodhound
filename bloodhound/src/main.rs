mod cli;
mod consumer;
mod deserializer;
mod drop_counter;
mod enricher;
mod heartbeat;
mod lifecycle;
mod loader;
mod packet_correlator;
mod serializer;
mod shutdown;

use anyhow::{Context, Result};
use aya::maps::{ring_buf::RingBuf, PerCpuArray};
use clap::Parser;
use log::info;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;

use cli::Cli;
use deserializer::BehaviorEvent;
use lifecycle::LifecycleSynthesizer;
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

    // Set up drop counter and the BPF→userspace bridge that keeps it
    // up to date. Without the bridge, the BPF helper increments a
    // per-CPU map that nothing reads back, so the userspace counter
    // (and therefore heartbeat `gap_detected`) stays at 0 forever
    // — see issue #28.
    let drop_count = drop_counter::new_counter();
    tokio::spawn(drop_counter::poll_drop_counter(drop_count.clone()));

    let drop_count_map = bpf
        .take_map("DROP_COUNT")
        .context("DROP_COUNT map not found in BPF object")?;
    let drop_count_map: PerCpuArray<_, u64> = PerCpuArray::try_from(drop_count_map)?;
    let bridge_reader = drop_counter::BpfDropCountReader::new(drop_count_map);
    tokio::spawn(drop_counter::bridge_bpf_drop_counter(
        bridge_reader,
        drop_count.clone(),
        Duration::from_secs(1),
    ));

    // Set up ring buffer consumer
    let map = bpf.take_map("EVENTS").unwrap();
    let ring_buf = RingBuf::try_from(map)?;
    let (event_tx, mut event_rx) = mpsc::channel::<Vec<u8>>(4096);

    // Spawn ring buffer consumer task
    let consumer_handle = tokio::spawn(async move {
        if let Err(e) = consumer::consume_ring_buffer(ring_buf, event_tx).await {
            eprintln!("Ring buffer consumer error: {}", e);
        }
    });

    // Synthesized-event channel for userspace-generated events
    // (lifecycle announcements and heartbeats). Kept separate from the
    // ring-buffer `event_rx` so the main select! can interleave both
    // sources without either starving the other.
    let (syn_tx, mut syn_rx) = mpsc::channel::<BehaviorEvent>(64);

    // Heartbeat task: periodic synthesized events carrying drop deltas
    // and emission counts so downstream consumers can mark intervals
    // as undecidable when drops occurred.
    let events_emitted = heartbeat::new_events_emitted_counter();
    let heartbeat_tx = syn_tx.clone();
    let heartbeat_drops = drop_count.clone();
    let heartbeat_emitted = events_emitted.clone();
    let heartbeat_interval = Duration::from_secs_f64(args.heartbeat_interval);
    tokio::spawn(async move {
        heartbeat::run_heartbeat(
            heartbeat_interval,
            heartbeat_drops,
            heartbeat_emitted,
            heartbeat_tx,
        )
        .await;
    });

    // Set up packet correlator, lifecycle synthesizer, and serializer
    let mut correlator = PacketCorrelator::new(args.uid);
    let mut lifecycle_synth = LifecycleSynthesizer::new();
    let mut output = Serializer::new();

    let drain_timeout = Duration::from_secs(5);

    // Helper: serialise an event and bump the emitted counter that
    // heartbeat samples for its `events_emitted_delta` field.
    let write_counted = |out: &mut Serializer<_>, ev: &BehaviorEvent| {
        if let Err(e) = out.write_event(ev) {
            eprintln!("Failed to write event: {}", e);
            return;
        }
        events_emitted.fetch_add(1, Ordering::Relaxed);
    };

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

                        // `process_start` precedes the first event
                        // from a pid so consumers see the identity
                        // anchor before any behavioural event.
                        for precursor in lifecycle_synth.before(&event) {
                            write_counted(&mut output, &precursor);
                        }

                        // Serialize the original event
                        write_counted(&mut output, &event);

                        // `process_fork` / `process_exit` follow the
                        // triggering clone/exit_group, preserving
                        // FIFO ordering with respect to the stream.
                        for followup in lifecycle_synth.after(&event) {
                            write_counted(&mut output, &followup);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to deserialize event: {}", e);
                    }
                }
            }

            Some(syn_event) = syn_rx.recv() => {
                // Heartbeat and any other userspace-synthesised events
                // share the same serialiser; ordering with raw events
                // is FIFO-per-source, determined by select! wake order.
                write_counted(&mut output, &syn_event);
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
                                for precursor in lifecycle_synth.before(&event) {
                                    let _ = output.write_event(&precursor);
                                }
                                let _ = output.write_event(&event);
                                for followup in lifecycle_synth.after(&event) {
                                    let _ = output.write_event(&followup);
                                }
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
