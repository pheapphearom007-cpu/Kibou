#!/usr/bin/env bash
# ==============================================================================
# Kibuo Launcher Script
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtualenv if present
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Execute main.py passing any arguments
exec python3 main.py "$@"
