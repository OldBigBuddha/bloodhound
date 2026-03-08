#!/bin/bash
# Scenario 02: File and directory creation / modification / deletion
# ──────────────────────────────────────────────────────────────────
# Key events to verify:
#   - openat    : O_CREAT / O_WRONLY flags on write-open
#   - write     : file writes (fd_type=file)
#   - mkdir/at  : directory creation
#   - rmdir     : directory removal
#   - unlinkat  : file deletion
#   - rename/at : file rename

# Create directories
mkdir -p /tmp/bh-test/subdir

# Create a file
echo "hello bloodhound" > /tmp/bh-test/greeting.txt

# Append to the file
echo "second line" >> /tmp/bh-test/greeting.txt

# Verify contents
cat /tmp/bh-test/greeting.txt

# Copy a file
cp /tmp/bh-test/greeting.txt /tmp/bh-test/subdir/copy.txt

# Rename a file
mv /tmp/bh-test/subdir/copy.txt /tmp/bh-test/subdir/renamed.txt

# Change permissions
chmod 600 /tmp/bh-test/greeting.txt

# Clean up: delete files and directories
rm /tmp/bh-test/subdir/renamed.txt
rm /tmp/bh-test/greeting.txt
rmdir /tmp/bh-test/subdir
rmdir /tmp/bh-test
