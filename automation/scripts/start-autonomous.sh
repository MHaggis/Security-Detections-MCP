#!/usr/bin/env bash
set -euo pipefail
AUTOMATION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${AUTOMATION_DB_PATH:?Set AUTOMATION_DB_PATH to a dedicated automation database}"
: "${AUTOMATION_MODE:?Set AUTOMATION_MODE=dry-run or explicitly opt into live}"
# Run one worker in the foreground so its supervisor owns its lifecycle.
exec node "$AUTOMATION_DIR/dist/runners/autonomous-loop.js" start
