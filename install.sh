#!/bin/bash
# Install pentrax as a system-wide tool
# PENTRA-X v2.0.0 Installer

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              PENTRA-X v2.0.0 INSTALLER                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo ./install.sh)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Installing dependencies..."

# Update pip
pip3 install --upgrade pip

# Install Python requirements
pip3 install -r "$SCRIPT_DIR/requirements.txt"

echo "[*] Installing pentrax package..."

# Install as editable package (development mode)
pip3 install -e "$SCRIPT_DIR"

# Create config directory
echo "[*] Creating config directory..."
mkdir -p /etc/pentrax
if [ ! -f /etc/pentrax/config.yaml ]; then
    cp "$SCRIPT_DIR/config.yaml" /etc/pentrax/config.yaml
fi

# Create user directories
echo "[*] Creating user directories..."
mkdir -p ~/.pentrax/{logs,results,handshakes}

# Verify installation
echo ""
if command -v pentrax >/dev/null 2>&1; then
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  [✓] PENTRA-X installed successfully!                        ║"
    echo "║                                                              ║"
    echo "║  Usage:                                                      ║"
    echo "║    pentrax              - Launch the toolkit                 ║"
    echo "║    python -m pentrax    - Alternative launch method          ║"
    echo "║                                                              ║"
    echo "║  Config: /etc/pentrax/config.yaml                            ║"
    echo "║  Logs:   ~/.pentrax/logs/                                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
else
    echo "[!] Installation may have failed. Please check errors above."
    echo "[*] You can still run with: python3 -m pentrax"
    exit 1
fi