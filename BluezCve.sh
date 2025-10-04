#!/bin/bash

if [ ! -f ".venv/bin/activate" ]; then
  echo "Virtual environment not found at BluezCve/.venv"
  exit 1
fi

source .venv/bin/activate

if ! python -m BluezCve "$@"; then
  echo "[!] python command failed, use python3..."
  python3 -m BluezCve "$@"
fi
