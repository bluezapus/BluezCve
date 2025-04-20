#!/bin/bash

if [ ! -f "BluezCve/.venv/bin/activate" ]; then
  echo "[✘] Virtual environment not found at BluezCve/.venv"
  exit 1
fi

source BluezCve/.venv/bin/activate

if ! python -m BluezCve "$@"; then
  echo "[!] python gagal, mencoba dengan python3..."
  python3 -m BluezCve "$@"
fi
