#!/usr/bin/env bash
# Lightweight Cross-Platform Host Hygiene Agent Runner (macOS / Linux)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Locate Python 3 binary
if command -v python3 >/dev/null 2>&1; then
    PY_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PY_CMD="python"
else
    echo "[!] Error: Python 3 not found on PATH. Please install Python 3.8+." >&2
    exit 1
fi

exec "$PY_CMD" "$SCRIPT_DIR/run_agent.py" "$@"
