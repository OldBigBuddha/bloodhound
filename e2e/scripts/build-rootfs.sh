#!/usr/bin/env bash
set -euxo pipefail

ROOTFS_IMG="${1:-rootfs.ext4}"
ROOTFS_SIZE="${2:-4G}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(dirname "${SCRIPT_DIR}")"
PROJECT_ROOT="$(dirname "${E2E_DIR}")"

# Build Docker image
docker build -t bloodhound-e2e "${E2E_DIR}"

# Export filesystem as tarball + extract vmlinuz
CONTAINER_ID=$(docker create bloodhound-e2e)
docker export "${CONTAINER_ID}" -o "${E2E_DIR}/rootfs.tar"

# Extract vmlinuz from the container (must match the kernel modules installed
# in the Dockerfile). The E2E VM MUST boot with this exact kernel — using the
# host kernel (e.g. 6.14.0-azure on GitHub Actions) will cause task_struct
# offset mismatches and zero trace events.
docker cp "${CONTAINER_ID}:/boot/vmlinuz-6.8.0-49-generic" "${E2E_DIR}/vmlinuz" 2>/dev/null || true
if [[ ! -f "${E2E_DIR}/vmlinuz" ]]; then
    echo "WARNING: vmlinuz not found in Docker image, trying rootfs.tar..."
    tar xf "${E2E_DIR}/rootfs.tar" -C "${E2E_DIR}" --strip-components=1 boot/vmlinuz-6.8.0-49-generic 2>/dev/null \
        && mv "${E2E_DIR}/vmlinuz-6.8.0-49-generic" "${E2E_DIR}/vmlinuz" || true
fi
docker rm "${CONTAINER_ID}"

# Create ext4 image from tarball
rm -f "${E2E_DIR}/${ROOTFS_IMG}"
truncate -s "${ROOTFS_SIZE}" "${E2E_DIR}/${ROOTFS_IMG}"
mkfs.ext4 -F "${E2E_DIR}/${ROOTFS_IMG}"

# Mount and extract
MOUNT_DIR=$(mktemp -d)
sudo mount -o loop "${E2E_DIR}/${ROOTFS_IMG}" "${MOUNT_DIR}"
sudo tar xf "${E2E_DIR}/rootfs.tar" -C "${MOUNT_DIR}"

# Copy bloodhound binary into the image (prefer Docker output, fallback to cargo target)
BINARY="${PROJECT_ROOT}/target/docker/bloodhound"
if [[ ! -f "${BINARY}" ]]; then
    BINARY="${PROJECT_ROOT}/target/x86_64-unknown-linux-musl/release/bloodhound"
fi
if [[ -f "${BINARY}" ]]; then
    sudo mkdir -p "${MOUNT_DIR}/opt/bloodhound"
    sudo cp "${BINARY}" "${MOUNT_DIR}/opt/bloodhound/bloodhound"
    sudo chmod +x "${MOUNT_DIR}/opt/bloodhound/bloodhound"
fi

# Create systemd service
sudo mkdir -p "${MOUNT_DIR}/etc/systemd/system"
sudo tee "${MOUNT_DIR}/etc/systemd/system/bloodhound.service" > /dev/null << 'UNIT'
[Unit]
Description=Bloodhound eBPF Tracing Daemon
After=network.target

[Service]
Type=simple
ExecStartPre=-/sbin/modprobe sch_ingress
ExecStartPre=-/bin/sh -c 'for iface in $(ls /sys/class/net); do tc qdisc add dev $iface clsact 2>/dev/null; done'
ExecStart=/opt/bloodhound/bloodhound --uid 1000
StandardOutput=file:/var/log/bloodhound.ndjson
StandardError=journal
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
UNIT

# Configure networking for QEMU (guest has no network config from Docker export)
sudo mkdir -p "${MOUNT_DIR}/etc/systemd/network"
sudo tee "${MOUNT_DIR}/etc/systemd/network/80-dhcp.network" > /dev/null << 'NET'
[Match]
Name=ens* eth*

[Network]
DHCP=yes
NET

# DNS resolution (QEMU user-mode gateway is 10.0.2.2)
sudo mkdir -p "${MOUNT_DIR}/etc"
echo "nameserver 10.0.2.3" | sudo tee "${MOUNT_DIR}/etc/resolv.conf" > /dev/null

# Enable services at boot
sudo mkdir -p "${MOUNT_DIR}/etc/systemd/system/multi-user.target.wants"
sudo ln -sf /etc/systemd/system/bloodhound.service \
    "${MOUNT_DIR}/etc/systemd/system/multi-user.target.wants/bloodhound.service"
sudo ln -sf /lib/systemd/system/systemd-networkd.service \
    "${MOUNT_DIR}/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
sudo mkdir -p "${MOUNT_DIR}/etc/systemd/system/sockets.target.wants"
sudo ln -sf /lib/systemd/system/ssh.socket \
    "${MOUNT_DIR}/etc/systemd/system/sockets.target.wants/ssh.socket"

sudo umount "${MOUNT_DIR}"
rmdir "${MOUNT_DIR}"
rm -f "${E2E_DIR}/rootfs.tar"

echo "Rootfs image created: ${E2E_DIR}/${ROOTFS_IMG}"
