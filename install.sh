#!/bin/bash
# Install pentrax as a system-wide Kali tool

set -e

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./install.sh)"
  exit 1
fi

# Path to main script
SCRIPT="$(pwd)/pentrax.py"
TARGET="/usr/local/bin/pentrax"

# Add shebang if missing
if ! head -n 1 "$SCRIPT" | grep -q "^#!/"; then
  sed -i '1i#!/usr/bin/env python3' "$SCRIPT"
fi

# Copy to /usr/local/bin
cp "$SCRIPT" "$TARGET"
chmod +x "$TARGET"

# Install Python dependencies
pip3 install --upgrade pip
pip3 install pycryptodome

# Confirm install
if command -v pentrax >/dev/null 2>&1; then
  echo "[+] pentrax installed! Type 'pentrax' anywhere to launch."
else
  echo "[!] Installation failed. Check permissions and try again."
fi