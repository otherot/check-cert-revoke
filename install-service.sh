#!/usr/bin/env bash
# Install/upgrade/uninstall check-cert-revoke as a systemd service
set -euo pipefail

INSTALL_DIR="/opt/check-cert-revoke"
CONFIG_DIR="/etc/check-cert-revoke"
CONFIG_FILE="$CONFIG_DIR/config.json"
SERVICE_NAME="check-cert-revoke"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0 [--uninstall]"
    exit 1
fi

# ── Uninstall mode ──────────────────────────────────────────────────────────

if [[ "${1:-}" == "--uninstall" ]]; then
    echo "=== Uninstalling $SERVICE_NAME ==="
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    rm -rf "$INSTALL_DIR"
    systemctl daemon-reload
    echo "Service removed. Config kept at $CONFIG_DIR"
    echo "To remove config: rm -rf $CONFIG_DIR"
    exit 0
fi

# ── Detect mode ─────────────────────────────────────────────────────────────

if [[ -f "$SERVICE_FILE" ]]; then
    IS_UPGRADE=true
    echo "=== Upgrading $SERVICE_NAME ==="
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
else
    IS_UPGRADE=false
    echo "=== Installing $SERVICE_NAME ==="
fi

# ── Preserve user config ────────────────────────────────────────────────────

CONFIG_BACKUP=""
if $IS_UPGRADE && [[ -f "$CONFIG_FILE" ]]; then
    CONFIG_BACKUP=$(mktemp)
    cp "$CONFIG_FILE" "$CONFIG_BACKUP"
    echo "Config backed up"
fi

# ── Install files ───────────────────────────────────────────────────────────

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
rm -rf "$INSTALL_DIR"/*
cp check_cert_revoke.py "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp check-cert-revoke.service "$SERVICE_FILE"

# ── Restore or create config ────────────────────────────────────────────────

if [[ -n "$CONFIG_BACKUP" ]] && [[ -f "$CONFIG_BACKUP" ]]; then
    cp "$CONFIG_BACKUP" "$CONFIG_FILE"
    rm -f "$CONFIG_BACKUP"
    echo "Config restored from backup"
elif [[ ! -f "$CONFIG_FILE" ]]; then
    cp config.example.json "$CONFIG_FILE"
    echo "Created $CONFIG_FILE — EDIT IT with your domains and Telegram token!"
fi

# ── Python venv ─────────────────────────────────────────────────────────────

echo "Installing prerequisites..."
apt-get install -y python3-pip python3-venv curl

VENV="$INSTALL_DIR/venv"
rm -rf "$VENV"
python3 -m venv "$VENV"

if ! "$VENV/bin/python3" -m pip --version &>/dev/null; then
    echo "Bootstrapping pip in venv..."
    curl -sS https://bootstrap.pypa.io/get-pip.py | "$VENV/bin/python3"
fi

"$VENV/bin/python3" -m pip install -r "$INSTALL_DIR/requirements.txt"

# ── Start service ───────────────────────────────────────────────────────────

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo ""
echo "=== $($IS_UPGRADE && echo 'Upgraded' || echo 'Installed')! ==="
echo "Status:  systemctl status $SERVICE_NAME"
echo "Logs:    journalctl -u $SERVICE_NAME -f"
echo "Config:  $CONFIG_FILE"
echo "Stop:    systemctl stop $SERVICE_NAME"
echo "Remove:  sudo $0 --uninstall"
