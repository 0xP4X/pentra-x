# PENTRA-X Makefile
# Standard interface for installation, testing, and cleanup

PYTHON := python3
PIP := pip3
INSTALL_DIR := /etc/pentrax

.PHONY: help install uninstall test clean update

help:
	@echo "PENTRA-X Management Commands:"
	@echo "  make install    - Install the toolkit and its dependencies (requires sudo)"
	@echo "  make uninstall  - Remove the toolkit from the system (requires sudo)"
	@echo "  make test       - Run automated tests"
	@echo "  make clean      - Remove build artifacts and cache files"
	@echo "  make update     - Pull latest changes from git and reinstall"

install:
	@echo "[*] Launching installer script..."
	sudo ./install.sh

uninstall:
	@echo "[*] Removing PENTRA-X..."
	sudo $(PIP) uninstall -y pentrax || true
	sudo rm -f /usr/local/bin/pentrax
	sudo rm -rf $(INSTALL_DIR)
	@echo "[✓] PENTRA-X removed."

test:
	@echo "[*] Running tests..."
	$(PYTHON) -m pytest

clean:
	@echo "[*] Cleaning up build artifacts..."
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "[✓] Cleaned."

update:
	@echo "[*] Updating PENTRA-X..."
	git pull
	$(MAKE) install
