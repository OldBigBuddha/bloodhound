"""Layer 1: TTY capture tests.

These tests require interactive SSH sessions (PTY allocated) to trigger
tty_write and tty_read kprobes.
"""
import base64
import pexpect

from helpers import assert_event_exists, filter_events, validate_all_events


def _concat_tty_data(events):
    """Decode and concatenate args.data across a list of TTY events."""
    buf = b""
    for ev in events:
        data = ev.get("args", {}).get("data")
        if data:
            buf += base64.b64decode(data)
    return buf


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
        all_decoded = _concat_tty_data(tty_writes)
        assert b"hello_tty_test" in all_decoded or b"echo" in all_decoded


class TestTtyRead:
    """Test tty_read events (user input being read by a shell or other process)."""

    def test_tty_read_on_command_output(
        self, interactive_ssh, bloodhound_events, wait_for_events
    ):
        """An interactive session should produce tty_read events with layer=intent."""
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

    def test_tty_read_every_event_has_data_field(
        self, interactive_ssh, bloodhound_events, wait_for_events
    ):
        """Structural invariant: post-#2, every tty_read carries `args.data` (Base64).

        Pre-#2 the kprobe-entry implementation emitted metadata only. This
        test pins the post-#2 contract that `args.data` is always present
        and at least one byte long — catches the 'metadata regression' case.
        """
        session = interactive_ssh()
        session.sendline("echo has_data_field_test")
        session.expect("has_data_field_test")
        session.sendline("exit")
        session.expect(pexpect.EOF)
        wait_for_events()

        tty_reads = filter_events(
            bloodhound_events(), event_type="TTY", name="tty_read"
        )
        assert len(tty_reads) > 0, "No tty_read events found"

        for ev in tty_reads:
            assert "args" in ev, f"tty_read event missing args: {ev}"
            assert "data" in ev["args"], (
                f"tty_read event missing args.data (metadata-only regression): {ev}"
            )
            decoded = base64.b64decode(ev["args"]["data"])
            assert len(decoded) > 0, (
                f"tty_read event has zero-length data, which the kretprobe "
                f"should have early-returned on (ret <= 0): {ev}"
            )

    def test_tty_read_data_contains_typed_input(
        self, interactive_ssh, bloodhound_events, wait_for_events
    ):
        """Direct verification of issue #2 acceptance criteria: typing a
        unique marker string produces tty_read events whose concatenated
        decoded data contains that marker.

        This is the test that was missing pre-hotfix `c5c0bcc`: without it,
        the `bpf_probe_read_user_buf` / `_kernel_buf` confusion was caught
        only because events went to zero, not because data was verified.
        A subtler bug (e.g., truncation, off-by-one, wrong buffer) would
        have slipped through.
        """
        # Unique marker unlikely to appear in any other process's TTY traffic
        marker = "tty_read_acceptance_marker_b5f27a91"
        session = interactive_ssh()
        session.sendline(f"echo {marker}")
        session.expect(marker)
        session.sendline("exit")
        session.expect(pexpect.EOF)
        wait_for_events(seconds=3)

        tty_reads = filter_events(
            bloodhound_events(), event_type="TTY", name="tty_read"
        )
        assert len(tty_reads) > 0, "No tty_read events found"

        all_decoded = _concat_tty_data(tty_reads)
        assert marker.encode() in all_decoded, (
            f"Issue #2 acceptance criteria failed: typed marker {marker!r} "
            f"not found in concatenated tty_read data (length={len(all_decoded)}). "
            f"This indicates the kretprobe data path is broken — events fire "
            f"but do not carry the bytes that were actually read."
        )


class TestPtsFilter:
    """Test the pts/* device filter introduced by issue #12.

    The spec (`docs/tracing.md` §Layer 1 §TTY device filtering) requires
    that TTY events are emitted only for PTY **slave** devices. These
    tests pin that contract by exercising non-slave pathways and
    asserting that no events leak through.
    """

    def test_pty_master_write_is_filtered(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """Writing to the master side of a PTY pair should NOT produce
        a tty_write event.

        Kernel: `pty_write(master_tty, ...)` is called with a tty_struct
        whose `driver->subtype == PTY_TYPE_MASTER` (value 1). The
        `is_pts_slave()` helper in `layer1_tty.rs` must reject this.
        Writing to the slave side (same test, paired marker) must still
        produce an event to prove the filter is not over-eager.
        """
        marker_master = "pts_filter_master_unique_c8e431"
        marker_slave = "pts_filter_slave_unique_4a71b8"

        # Run as testuser (the traced user) so events would fire if not filtered.
        # openpty returns (master_fd, slave_fd). Write to each side, then close.
        script = (
            "import os, pty; "
            "m, s = pty.openpty(); "
            f"os.write(m, b'{marker_master}'); "
            f"os.write(s, b'{marker_slave}'); "
            "os.close(m); os.close(s)"
        )
        result = ssh_cmd(f'python3 -c "{script}"')
        assert result.returncode == 0, (
            f"PTY write script failed: stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )
        wait_for_events(seconds=3)

        tty_events = filter_events(bloodhound_events(), event_type="TTY")
        all_data = _concat_tty_data(tty_events)

        # Positive control: slave-side write MUST appear (filter must not
        # reject everything). If this fails the filter is over-zealous or
        # the `pty_write` kprobe is no longer firing at all.
        assert marker_slave.encode() in all_data, (
            f"Slave-side PTY write marker {marker_slave!r} not found in "
            f"TTY event stream — the #12 filter appears to be rejecting "
            f"valid slave writes. Collected {len(tty_events)} TTY events, "
            f"total decoded bytes: {len(all_data)}."
        )

        # Core assertion: master-side write MUST NOT leak through.
        assert marker_master.encode() not in all_data, (
            f"Master-side PTY write marker {marker_master!r} leaked into "
            f"TTY event stream — issue #12 filter regression. The kprobe "
            f"on `pty_write` fired for a master tty_struct and emitted "
            f"the event without rejecting it."
        )
