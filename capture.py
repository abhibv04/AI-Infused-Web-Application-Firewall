import time
from datetime import datetime
from zapv2 import ZAPv2
import pandas as pd

# OWASP ZAP Configuration
ZAP_API_KEY = 'YOUR API KEY'
ZAP_BASE_URL = 'http://localhost:8080'
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_BASE_URL, 'https': ZAP_BASE_URL})

OWASP_TOP_10_RULE_IDS = {
    'Injection': [40018],
    'Broken Authentication': [40024],
    'Sensitive Data Exposure': [40029],
    'XML External Entities (XXE)': [90023],
    'Broken Access Control': [10109],
    'Security Misconfiguration': [90033],
    'Cross-Site Scripting (XSS)': [40012, 40014, 40016, 40017],
    'Insecure Deserialization': [40014],
    'Using Components with Known Vulnerabilities': [90003],
    'Insufficient Logging & Monitoring': [40015],
}

CSV_FILE = 'zap_scan_data.csv'
LOG_FILE = 'dynamic_waf_log_2.txt'


def set_owasp_top_10_rules():
    zap.ascan.disable_all_scanners()
    for rule_ids in OWASP_TOP_10_RULE_IDS.values():
        for rule_id in rule_ids:
            zap.ascan.enable_scanners(str(rule_id))
    print("Configured ZAP to scan for OWASP Top 10 vulnerabilities.")


def log_to_csv(site, alerts):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data = []
    for alert in alerts:
        data.append({
            'timestamp': timestamp,
            'url': site,
            'risk': alert['risk'],
            'alert': alert['alert'],
            'description': alert['description'],
            'classification': 'malicious' if alert['risk'] in ['High', 'Medium'] else 'benign'
        })
    df = pd.DataFrame(data)
    df.to_csv(CSV_FILE, mode='a', index=False, header=not pd.io.common.file_exists(CSV_FILE))
    print(f"ZAP scan data for {site} logged to CSV.")


def log_to_file(site, alerts):
    """Logs ZAP scan results in a structured and readable format."""
    # Get the current date and time
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%H:%M:%S')
    
    with open(LOG_FILE, 'a') as log_file:
        # Write the scan date and time
        log_file.write(f"\n=== Scan Results on {current_date} ===\n")
        log_file.write(f"Website scanned on {current_time}: {site}\n")
        log_file.write(f"{'-' * 50}\n")
        
        # Write detailed scan results for each alert
        if alerts:
            for alert in alerts:
                log_file.write(f"Risk: {alert['risk']}\n")
                log_file.write(f"Confidence: {alert['confidence']}\n")
                log_file.write(f"Alert: {alert['alert']}\n")
                log_file.write(f"Description: {alert['description']}\n")
                log_file.write(f"{'-' * 50}\n")
        else:
            log_file.write("No vulnerabilities detected.\n")
            log_file.write(f"{'-' * 50}\n")
    print(f"ZAP scan results for {site} logged to {LOG_FILE}.")

def scan_and_log_sites():
    set_owasp_top_10_rules()
    scanned_sites = set()
    while True:
        accessed_sites = zap.core.sites
        for site in accessed_sites:
            if site not in scanned_sites:
                print(f"Scanning site: {site}")
                zap.ascan.scan(site)
                while int(zap.ascan.status(0)) < 100:
                    print(f"Scan progress: {zap.ascan.status(0)}%")
                    time.sleep(5)
                alerts = zap.core.alerts(baseurl=site)
                log_to_csv(site, alerts)  # Log to CSV
                log_to_file(site, alerts)  # Log to text file
                scanned_sites.add(site)
        time.sleep(10)
