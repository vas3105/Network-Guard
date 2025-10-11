# dlp.py

import re
import csv
from datetime import datetime
import os
from scapy.all import *

# 1. REGEX PATTERNS
REGEX_PATTERNS = {
    'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'Credit Card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
    'Phone Number': r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
    'GPS Coordinate': r'[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)'
}

# 2. LOGGING AND ALERTING
LOG_FILE = 'dlp_events.csv'

def setup_csv():
    """Create the CSV log file and write the header if it doesn't exist."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source_IP', 'Destination_IP', 'Data_Type', 'Matched_Content'])
    print(f"[*] Logging events to {LOG_FILE}")

def log_to_csv(src_ip, dst_ip, data_type, matched_content):
    """Appends a detected event to the CSV log file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, dst_ip, data_type, matched_content])

def alert(packet, data_type, matched_content):
    """Prints an alert to the console."""
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    print(f"DLP ALERT! Detected {data_type}: '{matched_content}' from {src_ip} -> {dst_ip}")

# 3. PACKET INSPECTION
def inspect_packet(packet):
    """
    Inspects each packet's payload for sensitive data using regex.
    """
    if packet.haslayer(Raw) and packet.haslayer(IP):
        try:
            # Decode payload, ignoring errors for non-text data
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # Check against each regex pattern
            for data_type, pattern in REGEX_PATTERNS.items():
                matches = re.findall(pattern, payload)
                if matches:
                    for match in matches:
                        # To avoid logging the GPS tuple, we re-join it as a string
                        if isinstance(match, tuple):
                            match = ', '.join(filter(None, match))
                        alert(packet, data_type, match)
                        log_to_csv(packet[IP].src, packet[IP].dst, data_type, match)
        except Exception as e:
            pass # Ignore packets that can't be processed

# 4. MAIN EXECUTION
if __name__ == "__main__":
    setup_csv()
    print("[*] Starting DLP network sniffer...")
    # Sniff traffic indefinitely. 'prn' specifies the callback function.
    # 'store=0' means we don't keep the packets in memory.
    sniff(prn=inspect_packet, store=0)
