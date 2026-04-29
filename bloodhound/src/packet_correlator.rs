use std::collections::HashMap;
use std::net::IpAddr;

use crate::deserializer::BehaviorEvent;

/// 5-tuple key for socket/packet correlation.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FiveTuple {
    pub protocol: u8,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Socket entry from connect/bind events.
#[derive(Debug, Clone)]
pub struct SocketEntry {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub auid: u32,
    pub sessionid: u32,
    pub comm: String,
    pub timestamp: f64,
}

/// Packet correlator: maps 5-tuples to process context.
pub struct PacketCorrelator {
    table: HashMap<FiveTuple, SocketEntry>,
    max_entries: usize,
    target_auid: u32,
}

impl PacketCorrelator {
    pub fn new(target_auid: u32) -> Self {
        Self {
            table: HashMap::new(),
            max_entries: 4096,
            target_auid,
        }
    }

    /// Record a connect/bind event for later packet correlation.
    pub fn record_socket(&mut self, event: &BehaviorEvent) {
        let args = match &event.args {
            Some(a) => a,
            None => return,
        };

        let family = args.get("family").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        let addr_str = args.get("addr").and_then(|v| v.as_str()).unwrap_or("");

        let addr: IpAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return,
        };

        // For connect: dst is the remote; for bind: src is the local
        let is_connect = event.event.name == "connect";

        let entry = SocketEntry {
            pid: event.header.pid,
            ppid: event.header.ppid,
            auid: event.header.auid,
            sessionid: event.header.sessionid,
            comm: event.header.comm.clone(),
            timestamp: event.header.timestamp,
        };

        // We store with partial 5-tuple (address + port) since we don't
        // know the local/remote port pairing at connect time for the
        // packet direction. We try multiple lookup strategies.

        // Simple key: just addr + port for now
        let key = if is_connect {
            // Connect: we know the remote addr:port
            FiveTuple {
                protocol: 0, // Will match any protocol
                src_addr: "0.0.0.0".parse().unwrap(),
                dst_addr: addr,
                src_port: 0,
                dst_port: port,
            }
        } else {
            // Bind: we know the local addr:port
            FiveTuple {
                protocol: 0,
                src_addr: addr,
                dst_addr: "0.0.0.0".parse().unwrap(),
                src_port: port,
                dst_port: 0,
            }
        };

        // LRU eviction when table is full
        if self.table.len() >= self.max_entries {
            // Remove oldest entry
            let oldest_key = self
                .table
                .iter()
                .min_by(|a, b| a.1.timestamp.partial_cmp(&b.1.timestamp).unwrap())
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest_key {
                self.table.remove(&k);
            }
        }

        self.table.insert(key, entry);
    }

    /// Try to correlate a PACKET event with a known socket.
    /// Populates the event's header fields if a match is found.
    pub fn correlate(&self, event: &mut BehaviorEvent) {
        // For PACKET events, try to find a matching socket entry
        let args = match &event.args {
            Some(a) => a,
            None => {
                self.set_default_header(event);
                return;
            }
        };

        // We'd need to parse the raw packet to extract 5-tuple
        // For now, set default values
        self.set_default_header(event);
    }

    fn set_default_header(&self, event: &mut BehaviorEvent) {
        // For unmatched packets: set auid to target, pid/ppid to 0
        event.header.auid = self.target_auid;
        event.header.sessionid = 0;
        event.header.pid = 0;
        event.header.ppid = None;
        event.header.comm = String::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deserializer::{BehaviorEvent, EventHeaderJson, EventTypeJson};

    fn make_packet_event() -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeaderJson {
                timestamp: 1.0,
                auid: 0,
                sessionid: 0,
                pid: 0,
                ppid: None,
                comm: String::new(),
            },
            event: EventTypeJson {
                event_type: "PACKET".to_string(),
                name: "ingress".to_string(),
                layer: "behavior".to_string(),
            },
            proc: None,
            args: Some(serde_json::json!({"data": "AAAA"})),
            return_code: None,
        }
    }

    fn make_connect_event(addr: &str, port: u16) -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeaderJson {
                timestamp: 1.0,
                auid: 1000,
                sessionid: 1,
                pid: 42,
                ppid: Some(1),
                comm: "curl".to_string(),
            },
            event: EventTypeJson {
                event_type: "TRACEPOINT".to_string(),
                name: "connect".to_string(),
                layer: "behavior".to_string(),
            },
            proc: None,
            args: Some(serde_json::json!({
                "family": 2,
                "port": port,
                "addr": addr,
            })),
            return_code: Some(0),
        }
    }

    fn make_bind_event(addr: &str, port: u16) -> BehaviorEvent {
        let mut event = make_connect_event(addr, port);
        event.event.name = "bind".to_string();
        event.header.comm = "sshd".to_string();
        event
    }

    // ── Contract: correlator correctly assigns target auid ───────────────

    /// Unmatched packets must receive the target user's auid.
    /// This ensures packet events are always attributable.
    #[test]
    fn unmatched_packet_gets_target_auid() {
        let correlator = PacketCorrelator::new(1000);
        let mut pkt = make_packet_event();

        correlator.correlate(&mut pkt);

        assert_eq!(pkt.header.auid, 1000);
        assert_eq!(pkt.header.pid, 0);
        assert!(pkt.header.ppid.is_none());
        assert_eq!(pkt.header.comm, "");
    }

    /// Target auid is configurable and correctly propagated.
    #[test]
    fn target_auid_is_configurable() {
        let correlator = PacketCorrelator::new(5555);
        let mut pkt = make_packet_event();

        correlator.correlate(&mut pkt);

        assert_eq!(pkt.header.auid, 5555);
    }

    // ── Contract: socket recording grows the table ──────────────────────

    /// Recording a connect event increases the table size.
    #[test]
    fn record_connect_grows_table() {
        let mut correlator = PacketCorrelator::new(1000);
        assert_eq!(correlator.table.len(), 0);

        correlator.record_socket(&make_connect_event("10.0.0.1", 80));
        assert_eq!(correlator.table.len(), 1);

        correlator.record_socket(&make_connect_event("10.0.0.2", 443));
        assert_eq!(correlator.table.len(), 2);
    }

    /// Recording a bind event also populates the table.
    #[test]
    fn record_bind_grows_table() {
        let mut correlator = PacketCorrelator::new(1000);
        correlator.record_socket(&make_bind_event("0.0.0.0", 8080));
        assert_eq!(correlator.table.len(), 1);
    }

    // ── Contract: bounded capacity with LRU eviction ────────────────────

    /// When the table reaches max_entries, the oldest entry is evicted.
    #[test]
    fn lru_eviction_at_capacity() {
        let mut correlator = PacketCorrelator::new(1000);
        correlator.max_entries = 3;

        // Fill to capacity
        let mut ev1 = make_connect_event("10.0.0.1", 80);
        ev1.header.timestamp = 1.0;
        correlator.record_socket(&ev1);

        let mut ev2 = make_connect_event("10.0.0.2", 80);
        ev2.header.timestamp = 2.0;
        correlator.record_socket(&ev2);

        let mut ev3 = make_connect_event("10.0.0.3", 80);
        ev3.header.timestamp = 3.0;
        correlator.record_socket(&ev3);

        assert_eq!(correlator.table.len(), 3);

        // Adding one more should evict the oldest (timestamp=1.0)
        let mut ev4 = make_connect_event("10.0.0.4", 80);
        ev4.header.timestamp = 4.0;
        correlator.record_socket(&ev4);

        assert_eq!(correlator.table.len(), 3);
    }

    // ── Contract: resilience against invalid input ───────────────────────

    /// Events with no args must not panic.
    #[test]
    fn record_event_without_args_does_not_panic() {
        let mut correlator = PacketCorrelator::new(1000);
        let mut event = make_connect_event("10.0.0.1", 80);
        event.args = None;
        correlator.record_socket(&event); // Should silently return
        assert_eq!(correlator.table.len(), 0);
    }

    /// Events with unparseable address must not panic.
    #[test]
    fn record_event_with_bad_addr_does_not_panic() {
        let mut correlator = PacketCorrelator::new(1000);
        let event = make_connect_event("not_an_ip", 80);
        correlator.record_socket(&event); // Should silently return
        assert_eq!(correlator.table.len(), 0);
    }

    /// Correlate with no args must not panic.
    #[test]
    fn correlate_packet_without_args_does_not_panic() {
        let correlator = PacketCorrelator::new(1000);
        let mut pkt = make_packet_event();
        pkt.args = None;

        correlator.correlate(&mut pkt);
        // Should set default header without panicking
        assert_eq!(pkt.header.auid, 1000);
    }
}

