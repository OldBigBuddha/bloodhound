"""Layer 2: Execution (execve/execveat) tests.

Non-interactive SSH can be used for these tests since TTY is not involved.
"""
from helpers import assert_event_exists, filter_events, validate_all_events


class TestExecve:
    """Test execve tracepoint events."""

    def test_binary_execution(self, ssh_cmd, bloodhound_events, wait_for_events):
        """Running a binary should produce an execve event."""
        ssh_cmd("ls /tmp")
        wait_for_events()

        events = bloodhound_events()
        # Filter for execve events whose filename ends with 'ls'.
        # We cannot use assert_event_exists (which returns the first match)
        # because SSH login may trigger other execve events first, e.g.
        # systemd --user session setup runs under the same loginuid.
        execve_events = filter_events(
            events, event_type="TRACEPOINT", name="execve", layer="tooling",
        )
        ls_events = [
            e for e in execve_events
            if e.get("args", {}).get("filename", "").endswith("ls")
        ]
        assert len(ls_events) > 0, (
            f"No execve event with filename ending in 'ls' found. "
            f"Got filenames: {[e.get('args',{}).get('filename','?') for e in execve_events[:10]]}"
        )
        ev = ls_events[0]

        # Verify args
        assert "args" in ev
        assert "filename" in ev["args"]
        assert "argv" in ev["args"]
        assert isinstance(ev["args"]["argv"], list)

        # argv should contain 'ls' and '/tmp'
        argv = ev["args"]["argv"]
        assert any("ls" in a for a in argv), f"'ls' not found in argv: {argv}"
        assert "/tmp" in argv, f"'/tmp' not found in argv: {argv}"

    def test_execve_has_return_code(self, ssh_cmd, bloodhound_events, wait_for_events):
        """execve events should include a return_code."""
        ssh_cmd("true")
        wait_for_events()

        events = bloodhound_events()
        ev = assert_event_exists(events, event_type="TRACEPOINT", name="execve")
        assert "return_code" in ev

    def test_execve_has_header_fields(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """execve events should have all required header fields."""
        ssh_cmd("echo test_header")
        wait_for_events()

        events = bloodhound_events()
        ev = assert_event_exists(events, event_type="TRACEPOINT", name="execve")

        header = ev["header"]
        assert "timestamp" in header
        assert "auid" in header
        assert "sessionid" in header
        assert "pid" in header
        assert "comm" in header
        assert isinstance(header["timestamp"], (int, float))
        assert header["timestamp"] > 0

    def test_script_execution(self, ssh_cmd, bloodhound_events, wait_for_events):
        """Running a script shows interpreter in filename, script in argv."""
        ssh_cmd("python3 -c 'print(42)'")
        wait_for_events()

        events = bloodhound_events()
        python_events = filter_events(events, event_type="TRACEPOINT", name="execve")
        python_exec = [
            e for e in python_events
            if "python" in e.get("args", {}).get("filename", "")
        ]
        assert len(python_exec) > 0, "No python execve event found"
