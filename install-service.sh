#!/usr/bin/env bash
# Install check-cert-revoke as a systemd service
set -euo pipefail

INSTALL_DIR="/opt/check-cert-revoke"
CONFIG_DIR="/etc/check-cert-revoke"
SERVICE_NAME="check-cert-revoke"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0"
    exit 1
fi

echo "=== Installing check-cert-revoke systemd service ==="

# Create directories
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

# Copy files
cp check_cert_revoke.py "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp check-cert-revoke.service /etc/systemd/system/

# Create venv and install Python deps
if ! python3 -m venv --help &>/dev/null 2>&1; then
    echo "Installing python3-venv..."
    apt-get install -y python3-venv
fi

VENV="$INSTALL_DIR/venv"
if [[ ! -d "$VENV" ]]; then
    python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Copy config if not exists
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
    cp config.example.json "$CONFIG_DIR/config.json"
    echo "Created $CONFIG_DIR/config.json — EDIT IT with your domains and Telegram token!"
fi

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo ""
echo "=== Installed! ==="
echo "Status:  systemctl status $SERVICE_NAME"
echo "Logs:    journalctl -u $SERVICE_NAME -f"
echo "Config:  $CONFIG_DIR/config.json"
echo "Stop:    systemctl stop $SERVICE_NAME"
echo "Disable: systemctl disable $SERVICE_NAME"
