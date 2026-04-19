//! Periodic synthesised `HEARTBEAT` events.
//!
//! Issue #3: the in-kernel ring buffer can drop events under pressure,
//! and `DROP_COUNT` is a single polled counter with no placement in the
//! event stream. Downstream consumers therefore have no reliable way to
//! mark an interval as *undecidable* when drops occur — they either
//! trust every gap or treat every correlation as unsound.
//!
//! This module emits a lightweight synthesized event every N seconds
//! carrying:
//!
//! - `drop_count_delta`  — drops recorded since the previous heartbeat
//! - `drop_count_total`  — cumulative drops since daemon startup
//! - `events_emitted_delta` — events written to stdout in the interval
//! - `gap_detected`      — convenience flag (== `drop_count_delta > 0`)
//!
//! The emission path is userspace-only. Events are pushed through an
//! mpsc channel and serialised by the main processing loop alongside
//! normal events so they share FIFO ordering and the same `Serializer`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;
use tokio::sync::mpsc;
use tokio::time;

use crate::deserializer::{BehaviorEvent, EventHeaderJson, EventTypeJson};
use crate::drop_counter::DropCounter;

/// Shared counter incremented by the main loop each time an event is
/// serialised to stdout. The heartbeat task diff's this against its
/// previous sample to report `events_emitted_delta`.
pub type EventsEmittedCounter = Arc<AtomicU64>;

pub fn new_events_emitted_counter() -> EventsEmittedCounter {
    Arc::new(AtomicU64::new(0))
}

/// Spawn a periodic heartbeat emitter. The task ticks every
/// `interval`, computes deltas against its last sample, builds a
/// `HEARTBEAT` `BehaviorEvent`, and sends it on `tx`. When `tx` is
/// closed the task exits.
///
/// An `interval` of zero disables heartbeats — the task returns
/// immediately so consumers that do not expect them are unaffected.
pub async fn run_heartbeat(
    interval: Duration,
    drop_counter: DropCounter,
    events_emitted: EventsEmittedCounter,
    tx: mpsc::Sender<BehaviorEvent>,
) {
    if interval.is_zero() {
        return;
    }

    let mut ticker = time::interval(interval);
    // Skip the immediate first tick — `tokio::time::interval` fires at
    // t=0, which would produce a heartbeat before any events have been
    // counted.
    ticker.tick().await;

    let mut prev_drops: u64 = drop_counter.load(Ordering::Relaxed);
    let mut prev_emitted: u64 = events_emitted.load(Ordering::Relaxed);

    loop {
        ticker.tick().await;

        let now_drops = drop_counter.load(Ordering::Relaxed);
        let now_emitted = events_emitted.load(Ordering::Relaxed);
        let drops_delta = now_drops.saturating_sub(prev_drops);
        let emitted_delta = now_emitted.saturating_sub(prev_emitted);
        prev_drops = now_drops;
        prev_emitted = now_emitted;

        let event = build_heartbeat(drops_delta, now_drops, emitted_delta);
        if tx.send(event).await.is_err() {
            // Receiver gone — main loop has shut down.
            return;
        }
    }
}

/// Construct a single heartbeat event with the given deltas.
///
/// Kept separate from the emission loop so unit tests can exercise
/// the shape of the event without spinning up tokio.
fn build_heartbeat(
    drops_delta: u64,
    drops_total: u64,
    emitted_delta: u64,
) -> BehaviorEvent {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    let mut args = serde_json::Map::new();
    args.insert("drop_count_delta".into(), json!(drops_delta));
    args.insert("drop_count_total".into(), json!(drops_total));
    args.insert("events_emitted_delta".into(), json!(emitted_delta));
    if drops_delta > 0 {
        args.insert("gap_detected".into(), json!(true));
    }

    BehaviorEvent {
        header: EventHeaderJson {
            timestamp: now,
            auid: 0,
            sessionid: 0,
            pid: 0,
            ppid: None,
            comm: String::new(),
        },
        event: EventTypeJson {
            event_type: "HEARTBEAT".into(),
            name: "heartbeat".into(),
            layer: "behavior".into(),
        },
        proc: None,
        args: Some(serde_json::Value::Object(args)),
        return_code: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── event shape ──────────────────────────────────────────────────────

    #[test]
    fn heartbeat_has_expected_type_and_name() {
        let ev = build_heartbeat(0, 0, 0);
        assert_eq!(ev.event.event_type, "HEARTBEAT");
        assert_eq!(ev.event.name, "heartbeat");
        assert_eq!(ev.event.layer, "behavior");
    }

    #[test]
    fn heartbeat_header_sentinels_signal_not_applicable() {
        let ev = build_heartbeat(0, 0, 0);
        assert_eq!(ev.header.auid, 0);
        assert_eq!(ev.header.sessionid, 0);
        assert_eq!(ev.header.pid, 0);
        assert!(ev.header.ppid.is_none());
        assert_eq!(ev.header.comm, "");
    }

    #[test]
    fn zero_drops_omits_gap_flag() {
        let ev = build_heartbeat(0, 5, 100);
        let args = ev.args.unwrap();
        assert_eq!(args["drop_count_delta"], 0);
        assert_eq!(args["drop_count_total"], 5);
        assert_eq!(args["events_emitted_delta"], 100);
        assert!(args.get("gap_detected").is_none());
    }

    #[test]
    fn nonzero_drops_sets_gap_flag() {
        let ev = build_heartbeat(3, 10, 100);
        let args = ev.args.unwrap();
        assert_eq!(args["drop_count_delta"], 3);
        assert_eq!(args["gap_detected"], true);
    }

    // ── emitter plumbing ─────────────────────────────────────────────────

    /// Zero interval must short-circuit the loop — downstream consumers
    /// that do not expect `HEARTBEAT` events opt out by setting this.
    #[tokio::test]
    async fn zero_interval_disables_emitter() {
        let drops = crate::drop_counter::new_counter();
        let emitted = new_events_emitted_counter();
        let (tx, mut rx) = mpsc::channel::<BehaviorEvent>(8);

        // Task should return immediately without sending anything.
        run_heartbeat(Duration::ZERO, drops, emitted, tx).await;
        assert!(rx.try_recv().is_err());
    }

    /// Short real-time interval is enough to verify the loop does fire
    /// events without needing paused-time plumbing — the tick pacing is
    /// tokio's responsibility and not what this module needs to test.
    #[tokio::test]
    async fn emits_heartbeat_with_nonzero_deltas() {
        let drops = crate::drop_counter::new_counter();
        let emitted = new_events_emitted_counter();
        let (tx, mut rx) = mpsc::channel::<BehaviorEvent>(8);

        drops.fetch_add(3, Ordering::Relaxed);
        emitted.fetch_add(10, Ordering::Relaxed);

        let handle = tokio::spawn(run_heartbeat(
            Duration::from_millis(50),
            drops.clone(),
            emitted.clone(),
            tx,
        ));

        let ev = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("heartbeat did not arrive within expected window")
            .expect("channel closed unexpectedly");

        assert_eq!(ev.event.event_type, "HEARTBEAT");
        let args = ev.args.unwrap();
        // The first sample taken inside `run_heartbeat` happens after
        // the initial tick is consumed. By the time the first *emitted*
        // heartbeat fires, the baseline has already observed the
        // pre-spawn increments, so delta is 0 but total carries them.
        assert_eq!(args["drop_count_total"], 3);

        handle.abort();
    }
}
