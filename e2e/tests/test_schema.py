"""Schema validation tests."""
from helpers import validate_all_events, validate_event


class TestSchemaValidation:
    """Validate all events against docs/schema.json."""

    def test_all_events_conform_to_schema(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """Every event in the output should conform to the BehaviorEvent schema."""
        # Generate some diverse activity
        ssh_cmd("ls /tmp")
        ssh_cmd("cat /etc/hostname")
        ssh_cmd("mkdir /tmp/schema_test && rmdir /tmp/schema_test")
        ssh_cmd("echo hello > /tmp/schema_out && rm /tmp/schema_out")
        wait_for_events()

        events = bloodhound_events()
        assert len(events) > 0, "No events captured"

        validate_all_events(events)

    def test_required_fields_present(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """All events must have required 'header' and 'event' fields."""
        ssh_cmd("true")
        wait_for_events()

        events = bloodhound_events()
        for ev in events:
            assert "header" in ev, f"Missing 'header' field: {ev}"
            assert "event" in ev, f"Missing 'event' field: {ev}"

            header = ev["header"]
            assert "timestamp" in header
            assert "auid" in header
            assert "sessionid" in header
            assert "pid" in header
            assert "comm" in header

            event = ev["event"]
            assert "type" in event
            assert "name" in event
            assert "layer" in event

    def test_event_type_values(self, ssh_cmd, bloodhound_events, wait_for_events):
        """event.type must be one of the allowed enum values."""
        ssh_cmd("ls /tmp")
        wait_for_events()

        events = bloodhound_events()
        allowed_types = {"SYSCALL", "TTY", "PACKET", "KPROBE", "TRACEPOINT", "LSM"}
        for ev in events:
            assert ev["event"]["type"] in allowed_types, (
                f"Invalid event type: {ev['event']['type']}"
            )

    def test_layer_values(self, ssh_cmd, bloodhound_events, wait_for_events):
        """event.layer must be one of the allowed enum values."""
        ssh_cmd("ls /tmp")
        wait_for_events()

        events = bloodhound_events()
        allowed_layers = {"intent", "tooling", "behavior"}
        for ev in events:
            assert ev["event"]["layer"] in allowed_layers, (
                f"Invalid layer: {ev['event']['layer']}"
            )


class TestAuidFilter:
    """Test that only target user's events appear."""

    def test_only_target_auid_events(
        self, ssh_cmd, bloodhound_events, wait_for_events, ssh_config
    ):
        """All events should have the target user's auid."""
        ssh_cmd("ls /tmp")
        wait_for_events()

        events = bloodhound_events()
        target_auid = 1000  # testuser uid

        from helpers import assert_auid_filter
        assert_auid_filter(events, target_auid)


class TestShutdown:
    """Test graceful shutdown."""

    def test_sigterm_produces_clean_exit(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """Sending SIGTERM should result in a clean exit with flushed events."""
        # Generate some activity first
        ssh_cmd("echo shutdown_test")
        wait_for_events()

        # Send SIGTERM to bloodhound
        ssh_cmd("sudo kill -TERM $(pgrep bloodhound)", user="root")
        wait_for_events(seconds=3)

        # Retrieve events (should have been flushed before exit)
        events = bloodhound_events()
        # The output file should end with a complete JSON line (no truncation)
        assert len(events) > 0, "No events found after shutdown"
