#!/bin/bash
# setup_service.sh

set -e

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root"
  exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.6"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
  echo "Python $REQUIRED_VERSION or higher is required. Found $PYTHON_VERSION"
  exit 1
fi

# Create service directory
INSTALL_DIR="/opt/ddos-defense"
mkdir -p "$INSTALL_DIR"

# Copy files
echo "Copying files to $INSTALL_DIR"
cp -r src/ models/ config.py ddos_defense_service.py "$INSTALL_DIR"

# Create logs directory
mkdir -p "$INSTALL_DIR/logs"
chmod 755 "$INSTALL_DIR/logs"

# Create systemd service file
cat > /etc/systemd/system/ddos-defense.service << EOF
[Unit]
Description=DDoS Defense Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/ddos_defense_service.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start service
systemctl daemon-reload
systemctl enable ddos-defense.service
systemctl start ddos-defense.service

echo "DDoS Defense Service installed and started!"
echo "To check status: systemctl status ddos-defense"
echo "To view logs: journalctl -u ddos-defense -f"