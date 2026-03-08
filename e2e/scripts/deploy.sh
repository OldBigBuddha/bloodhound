#!/usr/bin/env bash
# deploy.sh — Build, copy to VM, and restart bloodhound daemon.
# Usage: ./scripts/deploy.sh [--no-cache]
#
# Options:
#   --no-cache   Pass --no-cache to docker build (forces full rebuild)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
E2E_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$E2E_DIR")"
DOCKER_OUTPUT="${PROJECT_DIR}/target/docker"
BINARY="${DOCKER_OUTPUT}/bloodhound"

SSH_PORT="${SSH_PORT:-2222}"
SSH_HOST="${SSH_HOST:-localhost}"
SSH_OPTS="-o StrictHostKeyChecking=no"

DOCKER_EXTRA_FLAGS=""
if [[ "${1:-}" == "--no-cache" ]]; then
    DOCKER_EXTRA_FLAGS="--no-cache"
    echo "🔨 Building with --no-cache"
fi

# ── 1. Build ────────────────────────────────────────────────────────
echo "🔨 Building bloodhound via Docker..."
docker build \
    ${DOCKER_EXTRA_FLAGS} \
    --platform linux/amd64 \
    -f "${PROJECT_DIR}/Dockerfile.build" \
    --output "type=local,dest=${DOCKER_OUTPUT}" \
    "${PROJECT_DIR}"

echo "✅ Built: $(md5sum "${BINARY}" | awk '{print $1}')"

# ── 2. Deploy ───────────────────────────────────────────────────────
echo "📦 Stopping daemon..."
sshpass -p root ssh ${SSH_OPTS} -p "${SSH_PORT}" "root@${SSH_HOST}" \
    "systemctl stop bloodhound" 2>/dev/null || true

echo "📦 Copying binary to VM..."
sshpass -p root scp ${SSH_OPTS} -P "${SSH_PORT}" \
    "${BINARY}" "root@${SSH_HOST}:/opt/bloodhound/bloodhound"

# ── 3. Restart ──────────────────────────────────────────────────────
echo "🚀 Starting daemon..."
sshpass -p root ssh ${SSH_OPTS} -p "${SSH_PORT}" "root@${SSH_HOST}" \
    "systemctl start bloodhound"

sleep 3

# ── 4. Verify ───────────────────────────────────────────────────────
STATUS=$(sshpass -p root ssh ${SSH_OPTS} -p "${SSH_PORT}" "root@${SSH_HOST}" \
    "systemctl is-active bloodhound" 2>/dev/null || echo "unknown")

if [[ "$STATUS" == "active" ]]; then
    echo "✅ Daemon is active"
    VM_MD5=$(sshpass -p root ssh ${SSH_OPTS} -p "${SSH_PORT}" "root@${SSH_HOST}" \
        "md5sum /opt/bloodhound/bloodhound" 2>/dev/null | awk '{print $1}')
    echo "   VM binary: ${VM_MD5}"
else
    echo "❌ Daemon status: ${STATUS}"
    sshpass -p root ssh ${SSH_OPTS} -p "${SSH_PORT}" "root@${SSH_HOST}" \
        "journalctl -u bloodhound --no-pager -n 10" 2>/dev/null || true
    exit 1
fi
