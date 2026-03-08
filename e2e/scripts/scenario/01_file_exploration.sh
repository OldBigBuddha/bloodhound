#!/bin/bash
# Scenario 01: File exploration and text processing
# ──────────────────────────────────────────────────
# Key events to verify:
#   - execve   : ls, cat, grep, wc, head invocations
#   - openat   : file open (path and flags)
#   - read     : file content reads
#   - write    : stdout/stderr output
#   - tty_write: command input captured
#   - tty_read : command output captured

# List directory contents
ls -la /etc/

# Read a specific file
cat /etc/hostname

# Inspect the first few lines
head -5 /etc/passwd

# Search for a pattern
grep "root" /etc/passwd

# Count lines
wc -l /etc/passwd

# Read multiple files in succession
cat /etc/os-release
cat /etc/shells
