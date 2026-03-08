"""Layer 3: Syscall tracing tests (Tier 1 raw + Tier 2 rich)."""
from helpers import (
    assert_event_exists,
    assert_no_event,
    filter_events,
    validate_all_events,
)


class TestTier2Openat:
    """Test openat rich extraction."""

    def test_openat_on_cat(self, ssh_cmd, bloodhound_events, wait_for_events):
        """cat /etc/hostname should trigger an openat event."""
        ssh_cmd("cat /etc/hostname")
        wait_for_events()

        events = bloodhound_events()
        # Filter for openat events with /etc/hostname specifically.
        # SSH login may trigger other openat events first (e.g. /etc/passwd
        # from PAM/NSS lookups), so we cannot rely on first-match.
        openat_events = filter_events(
            events, event_type="TRACEPOINT", name="openat", layer="behavior",
        )
        hostname_events = [
            e for e in openat_events
            if "/etc/hostname" in e.get("args", {}).get("filename", "")
        ]
        assert len(hostname_events) > 0, (
            f"No openat event for /etc/hostname found. "
            f"Got filenames: {[e.get('args',{}).get('filename','?') for e in openat_events[:10]]}"
        )
        ev = hostname_events[0]
        assert "args" in ev
        assert "filename" in ev["args"]

    def test_openat_has_flags(self, ssh_cmd, bloodhound_events, wait_for_events):
        """openat events should include decoded flags."""
        ssh_cmd("cat /etc/hostname")
        wait_for_events()

        events = bloodhound_events()
        ev = assert_event_exists(events, event_type="TRACEPOINT", name="openat")
        assert "flags" in ev["args"]
        assert isinstance(ev["args"]["flags"], list)


class TestTier2ReadWrite:
    """Test read/write rich extraction."""

    def test_read_on_cat(self, ssh_cmd, bloodhound_events, wait_for_events):
        """cat should trigger read events."""
        ssh_cmd("cat /etc/hostname")
        wait_for_events()

        events = bloodhound_events()
        ev = assert_event_exists(
            events, event_type="TRACEPOINT", name="read", layer="behavior"
        )
        assert "args" in ev
        assert "fd" in ev["args"]
        assert "fd_type" in ev["args"]

    def test_write_on_cat(self, ssh_cmd, bloodhound_events, wait_for_events):
        """cat should trigger write events (stdout)."""
        ssh_cmd("cat /etc/hostname")
        wait_for_events()

        events = bloodhound_events()
        ev = assert_event_exists(
            events, event_type="TRACEPOINT", name="write", layer="behavior"
        )
        assert "args" in ev
        assert "fd_type" in ev["args"]


class TestTier2DirectoryOps:
    """Test directory operation syscalls."""

    def test_mkdir_rmdir(self, ssh_cmd, bloodhound_events, wait_for_events):
        """mkdir + rmdir should produce events with paths."""
        ssh_cmd("mkdir /tmp/test_bloodhound_dir && rmdir /tmp/test_bloodhound_dir")
        wait_for_events()

        events = bloodhound_events()

        # Check mkdir
        mkdir_events = filter_events(events, event_type="TRACEPOINT", name="mkdir") + \
                       filter_events(events, event_type="TRACEPOINT", name="mkdirat")
        assert len(mkdir_events) > 0, "No mkdir/mkdirat events found"

        # Check rmdir
        rmdir_ev = assert_event_exists(
            events, event_type="TRACEPOINT", name="rmdir"
        )


class TestTier2ProcessFork:
    """Test clone/clone3 events."""

    def test_clone_on_fork(self, ssh_cmd, bloodhound_events, wait_for_events):
        """Python os.fork() should trigger a clone event."""
        ssh_cmd("python3 -c 'import os; os.fork()'")
        wait_for_events()

        events = bloodhound_events()
        clone_events = filter_events(events, event_type="TRACEPOINT", name="clone") + \
                       filter_events(events, event_type="TRACEPOINT", name="clone3")
        assert len(clone_events) > 0, "No clone/clone3 events found"

        ev = clone_events[0]
        assert "args" in ev
        assert "flags" in ev["args"]
        assert isinstance(ev["args"]["flags"], list)


class TestTier1Raw:
    """Test Tier 1 raw syscall events."""

    def test_raw_syscall_emitted(self, ssh_cmd, bloodhound_events, wait_for_events):
        """Commands should produce raw SYSCALL events for non-Tier2 syscalls."""
        ssh_cmd("ls /tmp")
        wait_for_events()

        events = bloodhound_events()
        raw_events = filter_events(events, event_type="SYSCALL")
        assert len(raw_events) > 0, "No raw SYSCALL events found"

        ev = raw_events[0]
        assert "args" in ev
        assert "syscall_nr" in ev["args"]
        assert "raw_args" in ev["args"]
        assert len(ev["args"]["raw_args"]) == 6
        assert ev["event"]["layer"] == "behavior"


class TestTier1Tier2Dedup:
    """Test that Tier 2 syscalls don't appear as Tier 1 raw events."""

    def test_openat_not_duplicated(self, ssh_cmd, bloodhound_events, wait_for_events):
        """openat should appear as TRACEPOINT but not as raw SYSCALL."""
        ssh_cmd("cat /etc/hostname")
        wait_for_events()

        events = bloodhound_events()

        # Should have TRACEPOINT openat
        assert_event_exists(events, event_type="TRACEPOINT", name="openat")

        # Should NOT have SYSCALL with openat NR (257)
        raw_events = filter_events(events, event_type="SYSCALL")
        openat_raw = [
            e for e in raw_events
            if e.get("args", {}).get("syscall_nr") == 257
        ]
        assert len(openat_raw) == 0, (
            "openat appeared as both TRACEPOINT and raw SYSCALL (dedup failed)"
        )


class TestExclusion:
    """Test that excluded syscalls don't appear."""

    def test_futex_excluded(self, ssh_cmd, bloodhound_events, wait_for_events):
        """futex (NR 202) should never appear in events."""
        ssh_cmd("ls /tmp")
        wait_for_events()

        events = bloodhound_events()
        raw_events = filter_events(events, event_type="SYSCALL")
        futex_events = [
            e for e in raw_events
            if e.get("args", {}).get("syscall_nr") == 202
        ]
        assert len(futex_events) == 0, "Excluded syscall futex (202) found in events"
