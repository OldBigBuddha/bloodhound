"""Contract tests for exit_group → process_exit.

Locks in docs/output-schema.md's LIFECYCLE / process_exit contract:

    process_exit — emitted immediately after a Tier 1 raw-syscall event
    for exit_group (syscall 231). Carries args.pid and args.exit_code
    (from raw_args[0]). ... process_fork / process_exit follow [the
    triggering event], preserving FIFO ordering with respect to the
    stream.

On main these tests are expected to fail because the Tier 1 raw capture
emits on raw_syscalls:sys_exit, which never fires for exit_group — the
task is gone by then. After the enter-side emit fix in layer3_raw.rs,
all of them turn green.

All tests filter by the exiting pid to stay deterministic under the
shared-VM serial execution model: the bash/ssh teardown itself issues
exit_group calls that would otherwise blur "at least one" assertions.
"""
import pytest

from helpers import filter_events, validate_all_events


SYS_EXIT_GROUP = 231


def _run_exit_group(ssh_cmd, code: int) -> int:
    """Run a one-shot python3 that prints its pid, flushes, then _exit(code).

    Returns the exiting pid parsed from the command's stdout. Python's
    os._exit() maps to glibc _exit(), which issues exit_group(N) on
    Linux — exactly the syscall the contract covers.
    """
    script = (
        "import os, sys; print(os.getpid()); "
        f"sys.stdout.flush(); os._exit({code})"
    )
    result = ssh_cmd(f"python3 -c {script!r}")
    lines = [ln for ln in result.stdout.strip().splitlines() if ln.strip()]
    assert lines, (
        f"python3 produced no stdout; stderr={result.stderr!r}, "
        f"returncode={result.returncode}"
    )
    return int(lines[0])


def _raw_exit_group_for_pid(events, pid: int) -> list[dict]:
    """Raw SYSCALL(231) events attributable to a specific pid."""
    return [
        e for e in filter_events(events, event_type="SYSCALL", pid=pid)
        if e.get("args", {}).get("syscall_nr") == SYS_EXIT_GROUP
    ]


def _process_exit_for_pid(events, pid: int) -> list[dict]:
    """LIFECYCLE process_exit events whose payload args.pid matches.

    The contract names args.pid as the attribution field; we verify it
    explicitly rather than relying on header.pid so a future change
    that drifts the two apart surfaces here first.
    """
    lifecycle = filter_events(
        events,
        event_type="LIFECYCLE",
        name="process_exit",
        layer="behavior",
    )
    return [e for e in lifecycle if e.get("args", {}).get("pid") == pid]


class TestExitGroupContract:
    """Tier 1 raw SYSCALL(231) + LIFECYCLE process_exit contract."""

    def test_exit_group_emits_raw_syscall_231(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """I1: exit_group(N) produces a Tier 1 raw SYSCALL event."""
        pid = _run_exit_group(ssh_cmd, 0)
        wait_for_events()
        events = bloodhound_events()

        raw = _raw_exit_group_for_pid(events, pid)
        assert len(raw) >= 1, (
            f"No raw SYSCALL(231) event for pid={pid}. Contract: every "
            f"exit_group from a traced process MUST emit a Tier 1 raw "
            f"event (docs/output-schema.md)."
        )
        assert raw[0]["args"]["raw_args"][0] == 0
        assert raw[0]["event"]["name"] == str(SYS_EXIT_GROUP)
        assert raw[0]["event"]["layer"] == "behavior"

    def test_exit_group_triggers_process_exit_lifecycle(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """I2 + I3: a LIFECYCLE process_exit with matching args.pid follows."""
        pid = _run_exit_group(ssh_cmd, 0)
        wait_for_events()
        events = bloodhound_events()

        exits = _process_exit_for_pid(events, pid)
        assert len(exits) == 1, (
            f"Expected exactly one process_exit for pid={pid}, got "
            f"{len(exits)}."
        )
        assert exits[0]["event"]["layer"] == "behavior"

    @pytest.mark.parametrize("code", [0, 1, 42, 255])
    def test_exit_group_preserves_exit_code(
        self, code, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """I4: exit_code round-trips raw_args[0] → process_exit.args.exit_code."""
        pid = _run_exit_group(ssh_cmd, code)
        wait_for_events()
        events = bloodhound_events()

        raw = _raw_exit_group_for_pid(events, pid)
        assert len(raw) >= 1, f"No raw SYSCALL(231) for pid={pid}"
        assert raw[0]["args"]["raw_args"][0] == code, (
            f"raw_args[0]={raw[0]['args']['raw_args'][0]}, expected {code}"
        )

        exits = _process_exit_for_pid(events, pid)
        assert len(exits) == 1
        assert exits[0]["args"]["exit_code"] == code, (
            f"process_exit.args.exit_code={exits[0]['args']['exit_code']}, "
            f"expected {code}"
        )

    def test_syscall_231_precedes_process_exit_for_same_pid(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """I5: FIFO — raw SYSCALL(231) appears before process_exit, no other
        events from the same pid interleave between them."""
        pid = _run_exit_group(ssh_cmd, 0)
        wait_for_events()
        events = bloodhound_events()

        raw_idx = next(
            (
                i for i, e in enumerate(events)
                if e.get("event", {}).get("type") == "SYSCALL"
                and e.get("header", {}).get("pid") == pid
                and e.get("args", {}).get("syscall_nr") == SYS_EXIT_GROUP
            ),
            None,
        )
        exit_idx = next(
            (
                i for i, e in enumerate(events)
                if e.get("event", {}).get("type") == "LIFECYCLE"
                and e.get("event", {}).get("name") == "process_exit"
                and e.get("args", {}).get("pid") == pid
            ),
            None,
        )
        assert raw_idx is not None, "raw SYSCALL(231) not found in stream"
        assert exit_idx is not None, "process_exit not found in stream"
        assert raw_idx < exit_idx, (
            f"Ordering violation: SYSCALL(231) at {raw_idx}, "
            f"process_exit at {exit_idx} (process_exit must follow)."
        )

        interleaved = [
            e for e in events[raw_idx + 1 : exit_idx]
            if e.get("header", {}).get("pid") == pid
        ]
        assert interleaved == [], (
            f"Per-pid FIFO violation: events from pid={pid} appeared "
            f"between SYSCALL(231) and process_exit: "
            f"{[e.get('event') for e in interleaved]}"
        )

    def test_only_one_process_exit_per_exit_group(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """Safety: exactly one raw + one process_exit — no double emission
        from enter and exit side both firing."""
        pid = _run_exit_group(ssh_cmd, 0)
        wait_for_events()
        events = bloodhound_events()

        raw = _raw_exit_group_for_pid(events, pid)
        exits = _process_exit_for_pid(events, pid)
        assert len(raw) == 1, (
            f"Expected exactly 1 raw SYSCALL(231) for pid={pid}, got "
            f"{len(raw)} — check for duplicate emission across enter/exit."
        )
        assert len(exits) == 1, (
            f"Expected exactly 1 process_exit for pid={pid}, got {len(exits)}."
        )

    def test_exit_group_events_validate_against_schema(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """I8: all events including the new emit path pass jsonschema."""
        _run_exit_group(ssh_cmd, 0)
        wait_for_events()
        events = bloodhound_events()
        validate_all_events(events)


class TestExitGroupUidFilter:
    """The --uid filter must apply to the enter-side emit path."""

    def test_untraced_user_exit_group_not_captured(
        self, ssh_cmd, bloodhound_events, wait_for_events
    ):
        """I7: exit_group from a non-matching auid must NOT be captured.

        The VM daemon runs with --uid 1000 (testuser). Root's auid is 0,
        so root's exit_group calls must be filtered out by should_trace().
        A regression that bypasses that gate on the new enter-side path
        would surface here.
        """
        script = (
            "import os, sys; print(os.getpid()); "
            "sys.stdout.flush(); os._exit(0)"
        )
        result = ssh_cmd(f"python3 -c {script!r}", user="root")
        lines = [
            ln for ln in result.stdout.strip().splitlines() if ln.strip()
        ]
        assert lines, f"root python3 stdout empty: stderr={result.stderr!r}"
        root_pid = int(lines[0])
        wait_for_events()

        events = bloodhound_events()
        raw = _raw_exit_group_for_pid(events, root_pid)
        exits = _process_exit_for_pid(events, root_pid)
        assert len(raw) == 0, (
            f"Root's exit_group was captured ({len(raw)} events) — the "
            f"--uid filter is not being applied to the enter-side emit path."
        )
        assert len(exits) == 0
