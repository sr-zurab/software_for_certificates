#!/usr/bin/env bash
# Запускает native messaging host для расширения Cert Filter.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PYTHON_BIN="${CERT_FILTER_PYTHON:-}"
if [ -z "$PYTHON_BIN" ]; then
  if [ -x "$DIR/../venv/bin/python3" ]; then
    PYTHON_BIN="$DIR/../venv/bin/python3"
  elif [ -x "$DIR/../../venv/bin/python3" ]; then
    PYTHON_BIN="$DIR/../../venv/bin/python3"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
  else
    echo "python3 not found" >&2
    exit 127
  fi
fi

LOG_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/cert-filter-host"
mkdir -p "$LOG_DIR"
exec "$PYTHON_BIN" "$DIR/cert_filter_host.py" "$@" 2>>"$LOG_DIR/host.log"
