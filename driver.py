import subprocess
import time
from datetime import datetime
import pandas as pd
from classify_model import train_model, classify_packets

# Function to start capturing packets by running capture.py
def start_packet_capture():
    print("Starting packet capture...")
    capture_process = subprocess.Popen(["sudo", "python3", "capture.py"])
    return capture_process

# Function to run the classification model after some packets are captured
def classify_captured_packets():
    print("Training and classifying captured packets...")

    # Train the model (it will read the captured CSV data)
    model = train_model()

    # Classify the captured packets
    classify_packets(model)

    # Generate firewall rules and WAF log
    generate_firewall_rules()
    generate_waf_log()

# Function to generate firewall rules based on captured data
def generate_firewall_rules():
    # Load classified data
    data = pd.read_csv('captured_and_classified_packets.csv')

    with open("firewall_rules.txt", "w") as file:
        for index, row in data[data['classification'] == 'malicious'].iterrows():
            # Create rule for each malicious entry
            src_ip = row['src_ip']
            dst_ip = row['dst_ip']
            src_port = row['src_port'] if pd.notna(row['src_port']) else 'any'
            dst_port = row['dst_port'] if pd.notna(row['dst_port']) else 'any'
            protocol = 'tcp' if row['protocol'] == 6 else 'udp' if row['protocol'] == 17 else 'any'

            # Write iptables-like rules
            rule = f"iptables -A INPUT -s {src_ip} -d {dst_ip} -p {protocol} --dport {dst_port} --sport {src_port} -j DROP\n"
            file.write(rule)

    print("Firewall rules generated in 'firewall_rules.txt'.")

# Function to generate a WAF log with timestamp and detailed vulnerability information
def generate_waf_log():
    data = pd.read_csv('captured_and_classified_packets.csv')
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Filter malicious packets
    malicious_data = data[data['classification'] == 'malicious']

    # Initialize counters for summary
    total_packets = len(data)
    malicious_count = len(malicious_data)
    benign_count = total_packets - malicious_count
    vulnerability_summary = malicious_data['predictions'].value_counts().to_dict()

    # Calculate risk score with capping
    if benign_count == 0:
        risk_score = 100  # Maximum risk if no benign packets
    else:
        risk_score = (malicious_count / benign_count) * 100
        risk_score = min(risk_score, 100)  # Cap the score at 100

    # Assign risk rating based on the capped risk score
    if risk_score <= 30:
        risk_rating = "Low Risk"
    elif risk_score <= 70:
        risk_rating = "Medium Risk"
    else:
        risk_rating = "High Risk"

    with open("waf_log.txt", "w") as file:
        file.write(f"WAF Log - {now}\n")
        file.write("=" * 50 + "\n")
        file.write("Detailed Information on Malicious Packets:\n\n")

        # Write details for each malicious packet
        for index, row in malicious_data.iterrows():
            src_ip = row['src_ip']
            dst_ip = row['dst_ip']
            protocol = 'TCP' if row['protocol'] == 6 else 'UDP' if row['protocol'] == 17 else 'Other'
            vulnerability = row['predictions']
            entry_point = "Packet Payload Analysis"  # You can adjust this as per analysis

            # Packet details and vulnerability information
            vulnerability_info = f"Detected vulnerability: {vulnerability} from {src_ip} to {dst_ip} over {protocol}."
            entry_info = f"Possible entry point: {entry_point}"

            file.write(f"{vulnerability_info}\n{entry_info}\n")
            file.write("-" * 50 + "\n")

        # Summary Section
        file.write("\nSummary:\n")
        file.write("=" * 50 + "\n")
        file.write(f"Total packets analyzed: {total_packets}\n")
        file.write(f"Malicious packets detected: {malicious_count}\n")
        file.write("Breakdown of detected vulnerabilities:\n")

        for vuln_type, count in vulnerability_summary.items():
            file.write(f"- {vuln_type}: {count}\n")

        # Add risk score and rating to the log
        file.write("\nRisk Analysis:\n")
        file.write("=" * 50 + "\n")
        file.write(f"Risk Score: {risk_score:.2f}%\n")
        file.write(f"Risk Rating: {risk_rating}\n")

    print("WAF log generated in 'waf_log.txt' with risk score and rating.")

# Main driver code
if __name__ == "__main__":
    try:
        # Start the packet capture process
        capture_process = start_packet_capture()

        # Set the time intervals to classify packets (e.g., every 30 seconds)
        interval = 30  # seconds

        while True:
            # Wait for the interval to classify new captured packets
            time.sleep(interval)

            # Classify the captured packets using the trained model
            classify_captured_packets()

    except KeyboardInterrupt:
        print("Stopping packet capture...")

        # Terminate the packet capture process
        capture_process.terminate()
        capture_process.wait()

        # Final classification and generation of logs and rules before exiting
        print("Final classification and logging...")
        classify_captured_packets()

        print("Capture process stopped and logs/rules generated.")