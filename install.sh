#!/bin/bash

# Buat virtual environment
python3 -m venv .venv

if [ $? -ne 0 ]; then
  echo "create virtual environment failed."
  exit 1
fi

echo "Virtual environment .venv berhasil dibuat."

# Aktifkan virtual environment
source .venv/bin/activate

# Install dependensi dari requirements.txt
if [ -f "requirements.txt" ]; then
  echo "Installation from requirements.txt..."
  pip install --upgrade pip
  pip install -r requirements.txt
  echo "Semua dependensi terinstall."
else
  echo "File requirements.txt not found. Pass the package installation."
fi


