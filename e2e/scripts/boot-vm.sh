#!/usr/bin/env bash
set -euxo pipefail

ROOTFS_IMG="${1:-rootfs.ext4}"
SSH_PORT="${2:-2222}"
VM_MEMORY="${3:-2048}"
VM_CPUS="${4:-2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(dirname "${SCRIPT_DIR}")"

# Find kernel image
KERNEL="${E2E_DIR}/vmlinuz"
if [[ ! -f "${KERNEL}" ]]; then
    KERNEL=$(ls /boot/vmlinuz-* 2>/dev/null | head -1)
fi

if [[ -z "${KERNEL}" ]]; then
    echo "ERROR: No kernel image found"
    exit 1
fi

# Redirect QEMU console output to log file.
# Without this, the -nographic console output (kernel boot messages, getty prompts)
# interleaves with pytest output in the same terminal, making test results unreadable.
# Debug VM issues by inspecting ${E2E_DIR}/qemu.log instead.
sudo qemu-system-x86_64 \
    -kernel "${KERNEL}" \
    -drive "file=${E2E_DIR}/${ROOTFS_IMG},format=raw,if=virtio" \
    -append "root=/dev/vda rw console=ttyS0 lsm=landlock,lockdown,yama,apparmor,bpf" \
    -m "${VM_MEMORY}" \
    -smp "${VM_CPUS}" \
    -nographic \
    -enable-kvm \
    -net nic,model=virtio \
    -net "user,hostfwd=tcp::${SSH_PORT}-:22" \
    -pidfile "${E2E_DIR}/qemu.pid" \
    > "${E2E_DIR}/qemu.log" 2>&1 &

# QEMU -nographic corrupts the terminal's stty settings (disables onlcr)
# even when stdout/stderr are redirected. Restore sane terminal state.
stty sane 2>/dev/null || true

wait
