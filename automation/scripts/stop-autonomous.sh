#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'The worker runs in the foreground. Stop it with Ctrl+C, or send SIGTERM through its process supervisor.'
printf '%s\n' 'The worker finishes its current bounded invocation before closing SQLite. No PID-file process is killed by this script.'
