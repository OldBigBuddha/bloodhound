import json
import os
import subprocess
import time

import pexpect
import pytest


def pytest_addoption(parser):
    parser.addoption("--ssh-port", default="2222", help="SSH port for VM")
    parser.addoption("--ssh-host", default="localhost", help="SSH host for VM")
    parser.addoption("--ssh-user", default="testuser", help="SSH user")
    parser.addoption("--ssh-pass", default="testpass", help="SSH password")
    parser.addoption(
        "--bloodhound-output",
        default="/var/log/bloodhound.ndjson",
        help="Path to bloodhound output file in VM",
    )


@pytest.fixture(scope="session")
def ssh_config(request):
    return {
        "host": request.config.getoption("--ssh-host"),
        "port": request.config.getoption("--ssh-port"),
        "user": request.config.getoption("--ssh-user"),
        "password": request.config.getoption("--ssh-pass"),
        "output_path": request.config.getoption("--bloodhound-output"),
    }


@pytest.fixture(scope="session")
def ssh_cmd(ssh_config):
    """Build an SSH command prefix for non-interactive commands."""

    def run(cmd, user=None):
        u = user or ssh_config["user"]
        # Use matching password: root uses "root", others use the configured password
        password = "root" if u == "root" else ssh_config["password"]
        full_cmd = [
            "sshpass",
            "-p",
            password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-p",
            ssh_config["port"],
            f"{u}@{ssh_config['host']}",
            cmd,
        ]
        print(f"  [SSH {u}] {cmd}")
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=30
        )
        return result

    return run


@pytest.fixture(scope="session")
def scp_cmd(ssh_config):
    """Build an SCP command for file retrieval (runs as root)."""

    def fetch(remote_path, local_path):
        full_cmd = [
            "sshpass",
            "-p",
            "root",  # scp runs as root to access /var/log/bloodhound.ndjson
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-P",
            ssh_config["port"],
            f"root@{ssh_config['host']}:{remote_path}",
            local_path,
        ]
        subprocess.run(full_cmd, check=True, timeout=30)

    return fetch


@pytest.fixture
def interactive_ssh(ssh_config):
    """Create an interactive SSH session via pexpect (allocates PTY)."""

    def create_session():
        cmd = (
            f"sshpass -p {ssh_config['password']} "
            f"ssh -o StrictHostKeyChecking=no "
            f"-p {ssh_config['port']} "
            f"{ssh_config['user']}@{ssh_config['host']}"
        )
        child = pexpect.spawn(cmd, timeout=30)
        # Wait for shell prompt
        child.expect(r"[\$#] ", timeout=15)
        return child

    return create_session


@pytest.fixture(autouse=True)
def _event_baseline(ssh_config, request):
    """Record the current NDJSON line count before each test.

    Since we cannot safely truncate the NDJSON file (the daemon holds it open
    via systemd StandardOutput=file: and truncating creates NUL-byte gaps),
    we instead record how many lines exist BEFORE the test starts and only
    return events generated after that point.
    """
    result = subprocess.run(
        [
            "sshpass", "-p", "root",
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-p", ssh_config["port"],
            f"root@{ssh_config['host']}",
            f"wc -l < {ssh_config['output_path']}",
        ],
        capture_output=True, text=True, timeout=10,
    )
    try:
        request.node._baseline = int(result.stdout.strip())
    except (ValueError, AttributeError):
        request.node._baseline = 0


@pytest.fixture
def bloodhound_events(ssh_config, scp_cmd, ssh_cmd, tmp_path, request):
    """Retrieve and parse bloodhound NDJSON output from the VM.

    Only returns events generated AFTER the test started (using the baseline
    line count recorded by the _event_baseline fixture).
    """

    def get_events():
        local_file = str(tmp_path / "bloodhound.ndjson")
        scp_cmd(ssh_config["output_path"], local_file)

        baseline = getattr(request.node, "_baseline", 0)
        events = []
        with open(local_file) as f:
            for i, line in enumerate(f):
                if i < baseline:
                    continue
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Skip corrupted/truncated lines (common after daemon
                        # crash-loops or if SCP catches a partial write)
                        continue
        return events

    return get_events


@pytest.fixture
def wait_for_events():
    """Wait a brief period for events to be processed and flushed."""

    def wait(seconds=2):
        time.sleep(seconds)

    return wait
