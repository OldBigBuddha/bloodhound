"""Layer 1: TTY capture tests.

These tests require interactive SSH sessions (PTY allocated) to trigger
tty_write and tty_read kprobes.
"""
import base64
import pexpect

from helpers import assert_event_exists, filter_events, validate_all_events


class TestTtyWrite:
    """Test tty_write events (user input sent to terminal)."""

    def test_tty_write_on_command_input(
        self, interactive_ssh, bloodhound_events, wait_for_events
    ):
        """Typing a command in an interactive session should produce tty_write events."""
        session = interactive_ssh()
        session.sendline("echo hello_tty_test")
        session.expect("hello_tty_test")
        session.sendline("exit")
        session.expect(pexpect.EOF)
        wait_for_events()

        events = bloodhound_events()
        tty_writes = filter_events(events, event_type="TTY", name="tty_write")

        assert len(tty_writes) > 0, "No tty_write events found"

        # Verify event structure
        for ev in tty_writes:
            assert ev["event"]["layer"] == "intent"
            assert "args" in ev
            assert "data" in ev["args"]
            # Data should be valid Base64
            decoded = base64.b64decode(ev["args"]["data"])
            assert len(decoded) > 0

        # Check that our command appears in the decoded TTY data
        all_decoded = b""
        for ev in tty_writes:
            all_decoded += base64.b64decode(ev["args"]["data"])
        assert b"hello_tty_test" in all_decoded or b"echo" in all_decoded


class TestTtyRead:
    """Test tty_read events (terminal output returned to user)."""

    def test_tty_read_on_command_output(
        self, interactive_ssh, bloodhound_events, wait_for_events
    ):
        """Command output in an interactive session should produce tty_read events."""
        session = interactive_ssh()
        session.sendline("echo tty_read_marker")
        session.expect("tty_read_marker")
        session.sendline("exit")
        session.expect(pexpect.EOF)
        wait_for_events()

        events = bloodhound_events()
        tty_reads = filter_events(events, event_type="TTY", name="tty_read")

        assert len(tty_reads) > 0, "No tty_read events found"

        for ev in tty_reads:
            assert ev["event"]["layer"] == "intent"
