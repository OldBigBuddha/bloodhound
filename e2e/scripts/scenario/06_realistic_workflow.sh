#!/bin/bash
# Scenario 06: Realistic learner workflow (combined scenario)
# ────────────────────────────────────────────────────────────
# Key events to verify:
#   All layers fire in this scenario, making it ideal for event correlation:
#   - tty_write/tty_read : command input and output
#   - execve             : every command invocation
#   - openat/read/write  : file I/O
#   - clone              : subprocess creation
#   - PACKET             : network traffic
#
# Simulates a learner building a simple web server and testing it.

# Prepare a working directory
mkdir -p /tmp/my-project
cd /tmp/my-project

# Inspect the project structure
pwd
ls -la

# Create an HTML file (one-liner for run-and-record.sh compatibility)
echo '<!DOCTYPE html><html><head><title>Hello</title></head><body><h1>Hello from Bloodhound!</h1></body></html>' > index.html

# Verify the file
cat index.html
wc -l index.html

# Start a simple HTTP server in the background
python3 -m http.server 8080 &
SERVER_PID=$!
sleep 2

# Fetch a page from the local server
curl -s http://localhost:8080/

# Check running processes
ps aux | grep http.server | grep -v grep

# Stop the server
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

# Clean up
rm -rf /tmp/my-project

echo "done"
