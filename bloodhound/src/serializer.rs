use crate::deserializer::BehaviorEvent;
use std::io::{self, LineWriter, Write};

/// Line-buffered NDJSON writer.
///
/// Wraps the underlying writer in a `LineWriter` so the buffer is
/// flushed at every `\n`, i.e. once per event. Low-rate synthesised
/// events (`HEARTBEAT` every 1s, sporadic `LIFECYCLE`) were otherwise
/// trapped in an 8 KiB `BufWriter` and never reached downstream
/// consumers until hundreds of such events accumulated — which for
/// `HEARTBEAT` meant ~10 minutes of invisibility in quiet sessions.
pub struct Serializer<W: Write> {
    writer: LineWriter<W>,
}

impl Serializer<io::Stdout> {
    pub fn new() -> Self {
        Self {
            writer: LineWriter::new(io::stdout()),
        }
    }
}

impl<W: Write> Serializer<W> {
    /// Create a serializer writing to an arbitrary writer.
    pub fn with_writer(writer: W) -> Self {
        Self {
            writer: LineWriter::new(writer),
        }
    }

    /// Serialize a BehaviorEvent as NDJSON and write to the output.
    pub fn write_event(&mut self, event: &BehaviorEvent) -> io::Result<()> {
        serde_json::to_writer(&mut self.writer, event)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    /// Flush the output buffer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deserializer::{EventHeaderJson, EventTypeJson};

    fn make_event(name: &str) -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeaderJson {
                timestamp: 1.0,
                auid: 1000,
                sessionid: 1,
                pid: 42,
                ppid: Some(1),
                comm: "test".to_string(),
            },
            event: EventTypeJson {
                event_type: "TRACEPOINT".to_string(),
                name: name.to_string(),
                layer: "behavior".to_string(),
            },
            proc: None,
            args: None,
            return_code: Some(0),
        }
    }

    // ── Contract: NDJSON output format ───────────────────────────────────

    /// Each event must be a single line of valid JSON followed by a newline.
    #[test]
    fn single_event_is_one_json_line() {
        let mut buf = Vec::new();
        {
            let mut ser = Serializer::with_writer(&mut buf);
            ser.write_event(&make_event("openat")).unwrap();
            ser.flush().unwrap();
        }
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1, "Expected exactly one line");
        // Must be valid JSON
        let _: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    }

    /// Multiple events produce multiple lines (NDJSON).
    #[test]
    fn multiple_events_produce_ndjson() {
        let mut buf = Vec::new();
        {
            let mut ser = Serializer::with_writer(&mut buf);
            ser.write_event(&make_event("openat")).unwrap();
            ser.write_event(&make_event("read")).unwrap();
            ser.write_event(&make_event("write")).unwrap();
            ser.flush().unwrap();
        }
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 3, "Expected exactly three lines");

        // Each line is independently parseable JSON
        for (i, line) in lines.iter().enumerate() {
            let val: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("Line {} is not valid JSON: {}", i, e));
            assert!(val.is_object());
        }
    }

    /// Output must end with a newline (important for stream consumers).
    #[test]
    fn output_ends_with_newline() {
        let mut buf = Vec::new();
        {
            let mut ser = Serializer::with_writer(&mut buf);
            ser.write_event(&make_event("openat")).unwrap();
            ser.flush().unwrap();
        }
        assert!(buf.ends_with(b"\n"), "Output must end with newline");
    }

    /// Event content is preserved through serialization.
    #[test]
    fn event_name_preserved_in_output() {
        let mut buf = Vec::new();
        {
            let mut ser = Serializer::with_writer(&mut buf);
            ser.write_event(&make_event("mkdir")).unwrap();
            ser.flush().unwrap();
        }
        let output = String::from_utf8(buf).unwrap();
        let val: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(val["event"]["name"], "mkdir");
    }
}
