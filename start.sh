#!/usr/bin/env bash
set -e

# Script directory
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Locate uv
UV_BIN="$(which uv 2>/dev/null || echo "$HOME/.local/share/mise/shims/uv")"

if [ ! -x "$UV_BIN" ]; then
    echo "[!] Error: 'uv' not found. Please install uv or make sure it is in PATH."
    exit 1
fi

# Ensure .venv exists and sync dependencies
if [ ! -d ".venv" ]; then
    echo "[*] Syncing dependencies using uv..."
    "$UV_BIN" sync
fi

# Execute main.py inside virtualenv with sudo (needed for L2 Scapy raw packets)
exec sudo "$DIR/.venv/bin/python" "$DIR/main.py" "$@"
