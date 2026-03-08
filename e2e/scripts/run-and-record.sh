#!/usr/bin/env bash
# run-and-record.sh — Feed a shell script line-by-line into a VM and collect
# the bloodhound trace.
#
# Usage: ./scripts/run-and-record.sh <script.sh> [output-dir]
#
# Each non-empty, non-comment line in <script.sh> is typed into an interactive
# SSH session (PTY allocated) so that bloodhound records every command
# individually as tty_write/exec/syscall events — not just "bash script.sh".
#
# Prerequisites:
#   - rootfs.ext4 and vmlinuz already exist (run `make rootfs` once)
#   - Python 3 + pexpect installed  (the e2e venv works fine)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(dirname "${SCRIPT_DIR}")"
PYTHON="${E2E_DIR}/venv/bin/python3"

USER_SCRIPT="${1:?Usage: $0 <script.sh> [output-dir]}"
OUTPUT_DIR="${2:-${E2E_DIR}/output}"

ROOTFS_IMG="${ROOTFS_IMG:-rootfs.ext4}"
SSH_PORT="${SSH_PORT:-2222}"
VM_MEMORY="${VM_MEMORY:-2048}"
VM_CPUS="${VM_CPUS:-2}"
SSH_USER="${SSH_USER:-testuser}"
SSH_PASS="${SSH_PASS:-testpass}"
SNAPSHOT="${SNAPSHOT:-1}"  # Use -snapshot by default to keep rootfs clean

mkdir -p "${OUTPUT_DIR}"

cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    pkill -f "qemu-system-x86_64.*${ROOTFS_IMG}" 2>/dev/null || true
    echo "✅ VM terminated"
}
trap cleanup EXIT

# ── 1. Boot VM ───────────────────────────────────────────────────────
echo "🚀 Booting VM..."

SNAPSHOT_FLAG=""
if [[ "${SNAPSHOT}" == "1" ]]; then
    SNAPSHOT_FLAG="-snapshot"
    echo "   (using -snapshot, rootfs will not be modified)"
fi

sudo qemu-system-x86_64 \
    -kernel "${E2E_DIR}/vmlinuz" \
    -drive "file=${E2E_DIR}/${ROOTFS_IMG},format=raw,if=virtio" \
    -append "root=/dev/vda rw console=ttyS0 lsm=landlock,lockdown,yama,apparmor,bpf" \
    -m "${VM_MEMORY}" \
    -smp "${VM_CPUS}" \
    -nographic \
    -enable-kvm \
    -net nic,model=virtio \
    -net "user,hostfwd=tcp::${SSH_PORT}-:22" \
    ${SNAPSHOT_FLAG} \
    > "${E2E_DIR}/qemu.log" 2>&1 &

# QEMU -nographic modifies the terminal's stty settings (disables onlcr,
# which translates \n → \r\n on output). Even with stdout/stderr redirected,
# QEMU still alters the controlling terminal. Without this reset, all
# subsequent output wraps horizontally instead of starting at column 0.
stty sane 2>/dev/null || true

echo "⏳ Waiting for VM to become ready..."
for i in $(seq 1 30); do
    if sshpass -p root ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
        -p "${SSH_PORT}" root@localhost true 2>/dev/null; then
        echo "✅ VM is ready (took ~$((i*2))s)"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "❌ VM failed to boot within 60s"
        exit 1
    fi
    sleep 2
done

# ── 2. Verify bloodhound is running ─────────────────────────────────
STATUS=$(sshpass -p root ssh -o StrictHostKeyChecking=no -p "${SSH_PORT}" \
    root@localhost "systemctl is-active bloodhound" 2>/dev/null || echo "unknown")
if [[ "${STATUS}" != "active" ]]; then
    echo "❌ bloodhound daemon is not active (status: ${STATUS})"
    echo "   Check with: sshpass -p root ssh -p ${SSH_PORT} root@localhost journalctl -u bloodhound --no-pager -n 20"
    exit 1
fi
echo "✅ bloodhound daemon is active"

# ── 3. Clear old log (fresh recording) ──────────────────────────────
sshpass -p root ssh -o StrictHostKeyChecking=no -p "${SSH_PORT}" \
    root@localhost "systemctl stop bloodhound; truncate -s0 /var/log/bloodhound.ndjson; systemctl start bloodhound"
sleep 2

# ── 4. Run user script line-by-line via interactive SSH ──────────────
echo ""
echo "📝 Executing commands from: ${USER_SCRIPT}"
echo "─────────────────────────────────────────"

"${PYTHON}" - "${USER_SCRIPT}" "${SSH_PORT}" "${SSH_USER}" "${SSH_PASS}" <<'PYTHON_SCRIPT'
import sys
import time
import re

import pexpect

script_path = sys.argv[1]
ssh_port    = sys.argv[2]
ssh_user    = sys.argv[3]
ssh_pass    = sys.argv[4]

PROMPT = r'[\$#] '
CMD_TIMEOUT = 60

# Read commands from script (skip empty lines and comments)
with open(script_path) as f:
    lines = f.readlines()

commands = []
for line in lines:
    stripped = line.strip()
    # Skip shebang, empty lines, pure comments
    if not stripped or stripped.startswith('#') or stripped.startswith('#!/'):
        continue
    commands.append(stripped)

if not commands:
    print("⚠️  No commands found in script")
    sys.exit(0)

print(f"   Found {len(commands)} command(s) to execute\n")

# Open interactive SSH session (PTY allocated via pexpect)
ssh_cmd = (
    f"sshpass -p {ssh_pass} "
    f"ssh -o StrictHostKeyChecking=no "
    f"-p {ssh_port} "
    f"{ssh_user}@localhost"
)

# Filter out ANSI escape sequences from PTY output to prevent
# terminal rendering corruption. Raw PTY output contains cursor
# movement, color codes, and line-clearing sequences that corrupt
# the local terminal when piped directly to stdout.
class CleanLog:
    """Strip ANSI escape sequences before writing to stdout."""
    ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    def write(self, data):
        sys.stdout.write(self.ANSI_RE.sub('', data))
    def flush(self):
        sys.stdout.flush()

child = pexpect.spawn(ssh_cmd, timeout=30, encoding='utf-8')
child.logfile_read = CleanLog()
child.expect(PROMPT, timeout=15)

for i, cmd in enumerate(commands, 1):
    print(f"\n>>> [{i}/{len(commands)}] {cmd}")
    child.sendline(cmd)
    try:
        child.expect(PROMPT, timeout=CMD_TIMEOUT)
    except pexpect.TIMEOUT:
        print(f"\n⚠️  Command timed out after {CMD_TIMEOUT}s, continuing...")
    # Small delay between commands for event flushing
    time.sleep(0.5)

# Graceful exit
child.sendline("exit")
try:
    child.expect(pexpect.EOF, timeout=5)
except pexpect.TIMEOUT:
    pass
child.close()
print("\n✅ All commands executed")
PYTHON_SCRIPT

# ── 5. Wait for events to flush ─────────────────────────────────────
echo ""
echo "⏳ Waiting for events to flush..."
sleep 3

EVENT_COUNT=$(sshpass -p root ssh -o StrictHostKeyChecking=no -p "${SSH_PORT}" \
    root@localhost "wc -l < /var/log/bloodhound.ndjson" 2>/dev/null || echo "0")
echo "   Recorded ${EVENT_COUNT} events"

# ── 6. Retrieve log data ────────────────────────────────────────────
SCRIPT_BASE="$(basename "${USER_SCRIPT}" .sh)"
OUTPUT_FILE="${OUTPUT_DIR}/${SCRIPT_BASE}.ndjson"

sshpass -p root scp -o StrictHostKeyChecking=no -P "${SSH_PORT}" \
    root@localhost:/var/log/bloodhound.ndjson "${OUTPUT_FILE}"

echo "📦 Logs saved to: ${OUTPUT_FILE}"
echo "   (${EVENT_COUNT} events)"

# ── 7. VM cleanup (handled by trap) ─────────────────────────────────
echo ""
echo "🎉 Done!"
