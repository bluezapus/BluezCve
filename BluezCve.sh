#!/usr/bin/env bash

set -e

if [ ! -d ".venv" ]; then
  echo "[!] Virtualenv not found. Run install.sh first."
  exit 1
fi

source .venv/bin/activate

exec python -m BluezCve "$@"
