from scapy.all import sniff
import pandas as pd
import os
import re

# Function to classify packets into 'malicious' or 'benign' based on various patterns
def classify_packet(packet):
    if packet.haslayer("IP"):  # Check if the packet has an IP layer
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        protocol = packet["IP"].proto
        packet_length = len(packet)

        # Additional packet details
        src_port = packet.sport if packet.haslayer("TCP") or packet.haslayer("UDP") else None
        dst_port = packet.dport if packet.haslayer("TCP") or packet.haslayer("UDP") else None
        flags = packet.sprintf('%TCP.flags%') if packet.haslayer("TCP") else None

        # Initialize label as benign
        label = 'benign'

        # Extract payload as a string (for analysis)
        payload = str(packet.payload)

        # Broad vulnerability detection logic (based on common malicious patterns)
        if re.search(r'<script.*?>.*?</script>', payload, re.IGNORECASE):  # XSS or similar script injections
            label = 'malicious'
        elif re.search(r'(csrf_token|__RequestVerificationToken)[^&]*=[^&]*', payload, re.IGNORECASE):  # CSRF token misuse
            label = 'malicious'
        elif re.search(r'SELECT.*?FROM.*?WHERE', payload, re.IGNORECASE):  # SQL Injection or similar
            label = 'malicious'
        elif re.search(r'\b(?:GET|POST)\s+.*?\s+HTTP.*?\s*Connection:\s*close', payload, re.IGNORECASE):  # DDoS-like behavior
            label = 'malicious'
        elif re.search(r'<iframe.*?>.*?</iframe>', payload, re.IGNORECASE):  # Clickjacking
            label = 'malicious'

        # More detailed patterns
        elif re.search(r'(UNION\s+SELECT|UPDATE.*?SET|INSERT\s+INTO)', payload, re.IGNORECASE):  # General SQL injection patterns
            label = 'malicious'
        elif re.search(r'(eval\(|base64_decode\()', payload, re.IGNORECASE):  # Obfuscated/malicious code injections
            label = 'malicious'
        elif re.search(r'(/etc/passwd|/bin/bash|system\()', payload, re.IGNORECASE):  # Local file inclusion or command injection
            label = 'malicious'
        elif re.search(r'(xmlhttp\.open\(|fetch\()', payload, re.IGNORECASE):  # CSRF XMLHttpRequest misuse
            label = 'malicious'
        elif re.search(r'(iframe|frameborder|allowfullscreen)', payload, re.IGNORECASE):  # Clickjacking with advanced patterns
            label = 'malicious'
        elif re.search(r'(\bor\b.*=.*)', payload, re.IGNORECASE):  # SQL Injection with OR logic
            label = 'malicious'
        elif packet_length > 1500 and protocol == 6:  # Large payloads over TCP (could indicate flooding attacks)
            label = 'malicious'
        elif packet.haslayer("TCP"):  # Check if it has a TCP layer
            tcp_layer = packet.getlayer("TCP")
            if flags == "S" and not tcp_layer.ack:  # Suspicious SYN packets without ACK (indicative of SYN flood)
                label = 'malicious'

        # Create a dictionary with packet details (excluding the full payload)
        data = {
            'src_ip': ip_src,
            'dst_ip': ip_dst,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'packet_length': packet_length,
            'flags': flags,
            'classification': label
        }

        return data
    return None

# Function to process captured packets
def process_packet(packet):
    packet_data = classify_packet(packet)
    if packet_data:
        # Convert packet data to DataFrame
        df = pd.DataFrame([packet_data])
        
        # Write data to CSV, include header only if file is created fresh
        file_exists = os.path.isfile("captured_and_classified_packets.csv")
        df.to_csv("captured_and_classified_packets.csv", mode='a', header=not file_exists, index=False)

# Remove the existing CSV file if it exists (for fresh data capture every run)
if os.path.isfile("captured_and_classified_packets.csv"):
    os.remove("captured_and_classified_packets.csv")

# Debugging output to confirm network interface
print("Starting packet capture on interface enp0s3...")

# Start capturing packets on a specified interface


sniff(iface="enp0s3", prn=process_packet, store=0)  # Replace "enp0s3" with your network interface
