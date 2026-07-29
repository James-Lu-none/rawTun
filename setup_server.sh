#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (e.g. sudo ./setup_server.sh)"
  exit 1
fi

# Get absolute path to the directory containing this script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

echo "Compiling server.cpp..."
g++ -Wall -O2 -std=c++11 "$DIR/server.cpp" -o "$DIR/gateway-server"
if [ $? -ne 0 ]; then
    echo "Compilation failed! Ensure g++ is installed."
    exit 1
fi

echo "Creating systemd service..."
cat << EOF > /etc/systemd/system/gateway-server.service
[Unit]
Description=Gateway Server (UDP Tunnel)
After=network.target

[Service]
Type=simple
ExecStart=$DIR/gateway-server
WorkingDirectory=$DIR
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "Reloading systemd..."
systemctl daemon-reload

echo "Enabling and starting gateway-server.service..."
systemctl enable gateway-server.service
systemctl restart gateway-server.service

echo "Setup complete! Checking status:"
systemctl status gateway-server.service --no-pager
