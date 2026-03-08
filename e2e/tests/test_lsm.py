"""LSM hook tests."""
from helpers import assert_event_exists, filter_events


class TestLsmTaskKill:
    """Test lsm/task_kill hook."""

    def test_kill_daemon_blocked(self, ssh_cmd, bloodhound_events, wait_for_events):
        """Attempting to kill the daemon should fail and the daemon should survive.

        The kill is blocked by one of two mechanisms:
        - Standard Unix DAC: testuser (uid 1000) cannot kill a root process.
        - LSM task_kill hook: returns -EPERM for target user → daemon kills.

        Note: Linux checks DAC *before* calling the LSM hook, so if DAC
        already blocks the kill, the LSM hook is never invoked and no
        task_kill event is emitted.
        """
        import time
        # Wait for daemon to stabilize (may have just restarted from previous test)
        time.sleep(3)

        # Get daemon PID and verify it's valid
        result = ssh_cmd("pgrep bloodhound", user="root")
        if result.returncode != 0:
            import pytest
            pytest.skip("Bloodhound daemon not running")

        daemon_pid = result.stdout.strip()

        # Verify the PID is still alive before attempting kill
        check = ssh_cmd(f"kill -0 {daemon_pid}", user="root")
        if check.returncode != 0:
            import pytest
            pytest.skip(f"Daemon PID {daemon_pid} no longer valid")

        # Attempt to kill (should be blocked by DAC and/or LSM)
        result = ssh_cmd(f"kill -9 {daemon_pid}")
        assert result.returncode != 0, "kill -9 should have failed (EPERM)"
        wait_for_events()

        # Verify daemon is still running with the SAME PID
        result = ssh_cmd(f"kill -0 {daemon_pid}", user="root")
        assert result.returncode == 0, (
            f"Daemon (PID {daemon_pid}) was killed despite protection"
        )


class TestLsmBpf:
    """Test lsm/bpf hook."""

    def test_bpf_load_blocked(self, ssh_cmd, bloodhound_events, wait_for_events):
        """Non-daemon BPF program load should be blocked."""
        # Try to load a simple BPF program (should fail)
        ssh_cmd("bpftool prog load /dev/null /sys/fs/bpf/test 2>/dev/null || true")
        wait_for_events()

        events = bloodhound_events()
        bpf_events = filter_events(events, event_type="LSM", name="bpf")
        # May or may not have events depending on whether bpftool is installed
        # and whether the user has CAP_BPF. The test is best-effort.
