#!/bin/bash
# Scenario 03: Process creation and control
# ──────────────────────────────────────────
# Key events to verify:
#   - execve     : program execution (filename, argv)
#   - clone/3    : process fork
#   - SYSCALL    : tier-1 raw syscalls (wait4, etc.)
#   - tty_write  : interactive command input

# Basic process execution
echo "PID=$$"

# Subshell (fork + exec)
(echo "subshell PID=$$")

# Pipes (multiple processes chained)
echo "hello world" | tr 'a-z' 'A-Z' | wc -c

# Background process
sleep 1 &
wait $!

# Explicit fork via Python (one-liner for run-and-record.sh compatibility)
python3 -c 'import os,sys; pid=os.fork(); (print("child:",os.getpid()),sys.exit(0)) if pid==0 else (os.waitpid(pid,0),print("parent:",os.getpid()))'

# Chained commands
true && echo "success" || echo "failure"

# Process spawning via xargs
echo -e "one\ntwo\nthree" | xargs -I {} echo "item: {}"
