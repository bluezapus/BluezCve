#!/bin/bash

python3 -m venv .venv

if [ $? -ne 0 ]; then
  echo "create virtual environment failed."
  exit 1
fi

echo "Virtual environment .venv succesed create."

source .venv/bin/activate


if [ -f "requirements.txt" ]; then
  echo "Installation from requirements.txt..."
  pip install --upgrade pip
  pip install -r requirements.txt
  echo "All dependencies were successfully installed ."
else
  echo "File requirements.txt not found. Pass the package installation."
fi

echo "Installing BluezCve as CLI tool..."
pip install -e .

if [ $? -ne 0 ]; then
  echo "BluezCve installation failed."
  exit 1
fi

echo "Installation complete."
echo "You can now run: BluezCve -h or BluezCve.sh -h"
