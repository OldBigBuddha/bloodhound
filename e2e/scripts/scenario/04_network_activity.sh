#!/bin/bash
# Scenario 04: Network communication
# ────────────────────────────────────
# Key events to verify:
#   - PACKET (ingress/egress) : TC hook packet capture
#   - execve    : curl, python3, ss, etc.
#   - connect   : socket connection (source for 5-tuple correlation)
#   - openat    : DNS resolver config reads

# ── Self-contained TCP server/client ──────────────────────

# Start a simple HTTP server on port 9090
python3 -m http.server 9090 &
sleep 2

# HTTP GET to the local server (generates connect + PACKET events)
curl -s http://localhost:9090/ -o /dev/null && echo "HTTP request succeeded" || echo "HTTP request failed"

# Multiple requests (for 5-tuple correlation verification)
curl -s http://localhost:9090/ -o /dev/null
curl -s http://localhost:9090/ -o /dev/null

# Stop the HTTP server
kill %1 2>/dev/null
wait %1 2>/dev/null

# ── DNS resolution (local, triggers openat for /etc/resolv.conf) ──

python3 -c 'import socket; addr = socket.getaddrinfo("localhost", 80); print("Resolved:", addr[0][4])'

# ── Inspect network state ─────────────────────────────────

ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true
