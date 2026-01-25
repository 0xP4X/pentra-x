#!/bin/bash
# PENTRA-X v2.0.0 Installer
# Robust installer for Kali, Parrot, and Debian-based systems

set -e

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              PENTRA-X v2.0.0 INSTALLER                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./install.sh)${NC}"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. System Dependencies
echo -e "${YELLOW}[*] Updating system and installing dependencies...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3-pip python3-dev nmap sqlmap hydra gobuster aircrack-ng curl git build-essential
else
    echo -e "${YELLOW}[!] Non-Debian system detected. Please ensure nmap, sqlmap, hydra, gobuster, and aircrack-ng are installed manually.${NC}"
fi

# 2. Python Dependencies
echo -e "${YELLOW}[*] Installing Python requirements...${NC}"
# Use --break-system-packages if pip supports it (for modern Debian/Kali)
PIP_FLAGS=""
if pip3 help install | grep -q "break-system-packages"; then
    PIP_FLAGS="--break-system-packages"
fi

pip3 install --upgrade pip $PIP_FLAGS
pip3 install .[full] $PIP_FLAGS

# 3. Directories & Config
echo -e "${YELLOW}[*] Setting up directories...${NC}"
mkdir -p /etc/pentrax
if [ ! -f /etc/pentrax/config.yaml ]; then
    cp "$SCRIPT_DIR/config.yaml" /etc/pentrax/config.yaml
    chmod 644 /etc/pentrax/config.yaml
fi

# Create global results/logs directories if they don't exist
mkdir -p /var/log/pentrax
chmod 777 /var/log/pentrax

# User specific directories (for the user who ran sudo)
REAL_USER=${SUDO_USER:-$USER}
USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

if [ -d "$USER_HOME" ]; then
    echo -e "${YELLOW}[*] Setting up user directories for $REAL_USER...${NC}"
    mkdir -p "$USER_HOME/.pentrax"/{logs,results,handshakes}
    chown -R "$REAL_USER:$REAL_USER" "$USER_HOME/.pentrax"
fi

# Verify installation
echo ""
if command -v pentrax >/dev/null 2>&1; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  [✓] PENTRA-X installed successfully!                        ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║  Usage:                                                      ║${NC}"
    echo -e "${GREEN}║    sudo pentrax         - Launch the toolkit                 ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║  Config: /etc/pentrax/config.yaml                            ║${NC}"
    echo -e "${GREEN}║  Results: ~/.pentrax/results/                                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${RED}[!] Installation failed. 'pentrax' command not found in PATH.${NC}"
    exit 1
fi