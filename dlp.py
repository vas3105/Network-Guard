# dlp.py (Final Version with Priority Logic)

import re
import csv
from datetime import datetime
import os
from scapy.all import *
from urllib.parse import unquote_plus

# Regex patterns remain the same
REGEX_PATTERNS = {
    'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'Credit Card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
    'Phone Number': r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    'GPS Coordinate': r'[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?),\s*[-+]?(?:180(?:\.0+)?|(?:(?:1[0-7]\d)|(?:[1-9]?\d))(?:\.\d+)?)'
}

# <-- 1. DEFINE THE PRIORITY ORDER (Most specific to least specific)
PROCESSING_ORDER = [
    'Credit Card',
    'Email',
    'Phone Number',
    'GPS Coordinate'
]

LOG_FILE = 'dlp_events.csv'

def setup_csv():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source_IP', 'Destination_IP', 'Data_Type', 'Matched_Content'])
    print(f"[*] Logging events to {LOG_FILE}")

def log_to_csv(src_ip, dst_ip, data_type, matched_content):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src_ip, dst_ip, data_type, matched_content])

def alert(packet, data_type, matched_content):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    print(f"DLP ALERT! Detected {data_type}: '{matched_content}' from {src_ip} -> {dst_ip}")

def inspect_packet(packet):
    if packet.haslayer(Raw) and packet.haslayer(IP):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            searchable_payload = unquote_plus(payload) # We search in a copy

            # <-- 2. LOOP THROUGH THE PRIORITY LIST, NOT THE DICTIONARY
            for data_type in PROCESSING_ORDER:
                pattern = REGEX_PATTERNS[data_type]
                matches = re.findall(pattern, searchable_payload)
                
                if matches:
                    for match in matches:
                        # Log the found data
                        alert(packet, data_type, match)
                        log_to_csv(packet[IP].src, packet[IP].dst, data_type, match)
                        
                        # <-- 3. "CONSUME" THE MATCH by replacing it with placeholders
                        # This prevents it from being matched again by a less specific pattern
                        searchable_payload = searchable_payload.replace(match, '*' * len(match), 1)

        except Exception as e:
            pass

if __name__ == "__main__":
    setup_csv()
    print("[*] Starting DLP network sniffer...")
    sniff(iface="Software Loopback Interface 1", prn=inspect_packet, store=0)