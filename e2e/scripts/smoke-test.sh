#!/usr/bin/env bash
# Minimal smoke test: verify bloodhound daemon is alive and producing events
set -euo pipefail

SSH_PORT="${1:-2222}"
SSH_HOST="${2:-localhost}"
SSH_USER="testuser"
SSH_PASS="testpass"
ROOT_PASS="root"

ssh_root() { sshpass -p "$ROOT_PASS" ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "root@$SSH_HOST" "$@"; }
ssh_user() { sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "$@"; }

pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }
info() { echo "  ℹ️  $1"; }

echo "=== Bloodhound Smoke Test ==="
echo ""

# 1. SSH connectivity
echo "[1/6] SSH connectivity..."
ssh_root "true" 2>/dev/null && pass "root SSH OK" || fail "Cannot SSH as root"
ssh_user "true" 2>/dev/null && pass "testuser SSH OK" || fail "Cannot SSH as testuser"

# 2. testuser UID check
echo "[2/6] testuser UID..."
TESTUSER_UID=$(ssh_root "id -u testuser" 2>/dev/null)
if [[ "$TESTUSER_UID" == "1000" ]]; then
    pass "testuser uid=$TESTUSER_UID"
else
    fail "testuser uid=$TESTUSER_UID (expected 1000)"
fi

# 3. Daemon running
echo "[3/6] Daemon status..."
DAEMON_STATUS=$(ssh_root "systemctl is-active bloodhound" 2>/dev/null || true)
if [[ "$DAEMON_STATUS" == "active" ]]; then
    pass "bloodhound is $DAEMON_STATUS"
else
    fail "bloodhound is $DAEMON_STATUS"
    info "Journal:"
    ssh_root "journalctl -u bloodhound --no-pager -n 10" 2>/dev/null || true
fi

# 4. AUID check (testuser login should set loginuid)
echo "[4/6] AUID tracking..."
AUID=$(ssh_user "cat /proc/self/loginuid" 2>/dev/null)
if [[ "$AUID" == "1000" ]]; then
    pass "testuser auid=$AUID"
else
    fail "testuser auid=$AUID (expected 1000) — pam_loginuid may not be working"
fi

# 5. Generate activity and wait
echo "[5/6] Generating activity as testuser..."
ssh_user "echo hello; ls /tmp; cat /etc/hostname" >/dev/null 2>&1
sleep 3
NDJSON_LINES=$(ssh_root "wc -l < /var/log/bloodhound.ndjson" 2>/dev/null || echo "0")
if [[ "$NDJSON_LINES" -gt 0 ]]; then
    pass "NDJSON has $NDJSON_LINES events"
else
    fail "NDJSON has 0 events — daemon not tracing testuser"
fi

# 6. Event format check
echo "[6/6] Event format..."
FIRST_EVENT=$(ssh_root "head -1 /var/log/bloodhound.ndjson" 2>/dev/null)
if echo "$FIRST_EVENT" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    pass "Valid JSON"
    info "Sample: $(echo "$FIRST_EVENT" | python3 -c "import sys,json; e=json.load(sys.stdin); h=e.get('header',{}); ev=e.get('event',{}); print(f\"type={ev.get('type','?')} pid={h.get('pid','?')} comm={h.get('comm','?')}\")" 2>/dev/null)"
else
    fail "Invalid JSON: $FIRST_EVENT"
fi

echo ""
echo "=== All smoke tests passed! ==="
