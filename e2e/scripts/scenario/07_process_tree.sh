#!/bin/bash
# Scenario 07: Process tree structure (TUI tree view verification)
# ─────────────────────────────────────────────────────────────────
# Key events to verify:
#   - execve     : binary execution with ppid chain for tree building
#   - clone/3    : fork events preceding execve
#   - tty_write  : command input captured (parent nodes in tree)
#
# This scenario exercises multiple process creation patterns to verify
# that the TUI can reconstruct a correct execve tree using ppid chains.
# Each command produces a distinct tree shape:
#
#   Pattern 1: Single command       → 1 execve at depth 1
#   Pattern 2: Pipeline             → N execves at depth 1 (siblings)
#   Pattern 3: Subshell             → nested fork + exec
#   Pattern 4: bash -c              → bash at depth 1, children at depth 2
#   Pattern 5: Background process   → fork tracked via ppid
#   Pattern 6: xargs spawn          → multiple children under xargs
#   Pattern 7: Nested bash -c       → depth 3+ hierarchy
#   Pattern 8: Shell built-in only  → no execve (0 children in tree)

# ── Pattern 1: Single command (1 execve, flat) ────────────────────
ls -la /tmp

# ── Pattern 2: Pipeline (3 execves, same depth) ──────────────────
cat /etc/passwd | grep root | wc -l

# ── Pattern 3: Subshell (fork + exec) ────────────────────────────
(cd /tmp && ls -la)

# ── Pattern 4: bash -c (bash → child commands at depth 2) ────────
bash -c 'echo tree_test_start; ls /tmp; echo tree_test_end'

# ── Pattern 5: Background process (fork tracked) ─────────────────
sleep 1 &
wait $!

# ── Pattern 6: xargs spawn (multiple children under xargs) ───────
echo -e "one\ntwo\nthree" | xargs -I {} echo "item: {}"

# ── Pattern 7: Nested bash -c (depth 3+ hierarchy) ───────────────
bash -c 'bash -c "echo deeply_nested"; echo outer'

# ── Pattern 8: Shell built-in only (no execve) ───────────────────
cd /tmp

echo "scenario_07_complete"
