#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

INTERFACE="wlan1"

echo "[*] Preparing wireless interface $INTERFACE..."

# Kill potentially interfering processes
echo "[*] Killing interfering processes..."
airmon-ng check kill

# Stop NetworkManager specifically
systemctl stop NetworkManager
systemctl stop wpa_supplicant

# Put interface down
ip link set $INTERFACE down

# Set interface up
ip link set $INTERFACE up

echo "[*] Interface $INTERFACE is ready"
echo "[*] You can now run: sudo docker compose up" 