import threading
import time
import re
import signal
import sys
from zap_scan_and_log import scan_and_log_sites
from ml_model import train_model, classify_data, MODEL_PATH

# File paths
CSV_FILE = 'zap_scan_data.csv'
SCAN_LOG_FILE = 'dynamic_waf_log_2.txt'
FIREWALL_RULES_FILE = 'firewall_rules.conf'

# Global threads and events
zap_thread = None
ml_classification_thread = None
stop_event = threading.Event()


def zap_scanner_thread():
    """Thread to start the ZAP scanner and log vulnerabilities."""
    while not stop_event.is_set():
        scan_and_log_sites()


def ml_thread():
    """Thread to periodically retrain the ML model and classify data."""
    while not stop_event.is_set():
        time.sleep(60)  # Retrain and classify periodically
        model = train_model(CSV_FILE)
        if model:
            classify_data(CSV_FILE, model)


def parse_scan_log(log_file):
    """
    Parse the ZAP scan log file and extract vulnerabilities for generating SecRules.
    """
    rules = []
    generated_rule_set = set()  # Track generated rules for deduplication
    try:
        with open(log_file, 'r') as file:
            data = file.read()
            risks = re.findall(
                r'Risk:\s*(.*?)\s*\nConfidence:\s*(.*?)\s*\nAlert:\s*(.*?)\s*\nDescription:\s*(.*?)\s*\n',
                data,
                re.DOTALL,
            )
            print(f"Total risks parsed: {len(risks)}")

            for risk in risks:
                risk_level, confidence, alert, description = risk
                risk_level = risk_level.strip()
                alert = alert.strip()
                description = description.strip()

                if risk_level in ['High', 'Medium']:
                    print(f"Processing Risk: {alert} (Level: {risk_level})")
                    rule = generate_firewall_rule(alert, description)
                    if rule and rule not in generated_rule_set:  # Avoid duplicates
                        rules.append(rule)
                        generated_rule_set.add(rule)  # Add to the set
    except FileNotFoundError:
        print(f"Log file {log_file} not found. Skipping rule generation.")
    return rules


def generate_firewall_rule(alert, description):
    """
    Dynamically generate firewall rules for OWASP Top 10, additional 10 common risks,
    and the requested risks with enhanced logic.
    """
    # OWASP Top 10 Risks
    if "SQL Injection" in alert:
        return f"SecRule ARGS \"@rx (select|union|insert|update|delete|drop|exec|benchmark|sleep)\" " \
               f"\"id:1001,phase:2,deny,msg:'SQL Injection detected',t:none\""
    elif "Cross-Site Scripting" in alert or "XSS" in alert:
        return f"SecRule ARGS|REQUEST_HEADERS \"<script>\" " \
               f"\"id:1002,phase:2,deny,msg:'Cross-Site Scripting detected',t:none\""
    elif "Sensitive Data Exposure" in alert:
        return f"SecRule RESPONSE_HEADERS:X-Content-Type-Options \"!@streq nosniff\" " \
               f"\"id:1003,phase:3,pass,msg:'Missing X-Content-Type-Options header',t:none\""
    elif "Broken Authentication" in alert:
        return f"SecRule RESPONSE_HEADERS:Set-Cookie \"!HttpOnly\" " \
               f"\"id:1004,phase:3,pass,msg:'HttpOnly flag missing in cookies',t:none\""
    elif "Broken Access Control" in alert:
        return f"SecRule REQUEST_HEADERS:Referer \"!@contains trusted-domain.com\" " \
               f"\"id:1005,phase:2,deny,msg:'Unauthorized access attempt detected',t:none\""
    elif "Security Misconfiguration" in alert:
        return f"SecRule RESPONSE_HEADERS:Server \"@rx (Apache|Nginx)\" " \
               f"\"id:1006,phase:3,pass,msg:'Potential misconfigured server detected',t:none\""
    elif "Insecure Deserialization" in alert:
        return f"SecRule REQUEST_BODY \"@rx (O:|N;|s:)\" " \
               f"\"id:1007,phase:2,deny,msg:'Insecure deserialization payload detected',t:none\""
    elif "Using Components with Known Vulnerabilities" in alert:
        return f"SecRule REQUEST_URI \"@contains vulnerable-library.js\" " \
               f"\"id:1008,phase:2,deny,msg:'Outdated or vulnerable library detected',t:none\""
    elif "XML External Entities" in alert or "XXE" in alert:
        return f"SecRule ARGS \"@rx (<!ENTITY|SYSTEM|PUBLIC)\" " \
               f"\"id:1009,phase:2,deny,msg:'XML External Entity detected in payload',t:none\""
    elif "Insufficient Logging and Monitoring" in alert:
        return f"SecRule RESPONSE_HEADERS \"@rx (Error|Warning|Failure)\" " \
               f"\"id:1010,phase:2,pass,msg:'Logging or monitoring issue detected',t:none\""

    # Additional Risks
    elif "Directory Traversal" in alert:
        return f"SecRule ARGS|REQUEST_URI \"@rx (\\.\\.\\/|\\.\\.\\\\)\" " \
               f"\"id:1011,phase:2,deny,msg:'Directory Traversal detected',t:none\""
    elif "Command Injection" in alert:
        return f"SecRule ARGS \"@rx (\\||;|`|\\$\\()\" " \
               f"\"id:1012,phase:2,deny,msg:'Command Injection detected',t:none\""
    elif "Local File Inclusion" in alert or "LFI" in alert:
        return f"SecRule ARGS|REQUEST_URI \"@rx (\\.(php|txt|log|cfg))$\" " \
               f"\"id:1013,phase:2,deny,msg:'Local File Inclusion detected',t:none\""
    elif "Remote File Inclusion" in alert or "RFI" in alert:
        return f"SecRule ARGS|REQUEST_URI \"@rx (http[s]?:\\/\\/)\" " \
               f"\"id:1014,phase:2,deny,msg:'Remote File Inclusion detected',t:none\""
    elif "CRLF Injection" in alert:
        return f"SecRule ARGS \"@rx (\\%0D\\%0A|\\n|\\r)\" " \
               f"\"id:1015,phase:2,deny,msg:'CRLF Injection detected',t:none\""
    elif "HTTP Parameter Pollution" in alert:
        return f"SecRule ARGS_NAMES \"@rx (\\w+\\=\\w+.*\\&.*\\1\\=)\" " \
               f"\"id:1016,phase:2,deny,msg:'HTTP Parameter Pollution detected',t:none\""
    elif "Unvalidated Redirects and Forwards" in alert:
        return f"SecRule REQUEST_URI \"@rx (redirect|forward)\" " \
               f"\"id:1017,phase:2,deny,msg:'Unvalidated Redirect detected',t:none\""
    elif "Malware Upload" in alert:
        return f"SecRule REQUEST_BODY \"@rx (\\.exe|\\.js|\\.bat|\\.sh)\" " \
               f"\"id:1018,phase:2,deny,msg:'Malware upload attempt detected',t:none\""
    elif "Weak Password Policy" in alert:
        return f"SecRule ARGS \"@rx (password=.*.{0,6})\" " \
               f"\"id:1019,phase:2,pass,msg:'Weak password policy detected',t:none\""
    elif "Open Redirects" in alert:
        return f"SecRule ARGS \"@rx (http[s]?://[\\w\\.]+)\" " \
               f"\"id:1020,phase:2,deny,msg:'Open redirect attempt detected',t:none\""

    # New Risks
    elif "Content Security Policy (CSP) Header Not Set" in alert:
        return f"SecRule RESPONSE_HEADERS:Content-Security-Policy \"@streq ''\" " \
               f"\"id:1024,phase:3,deny,msg:'CSP Header Not Set',t:none\""
    elif "Missing Anti-clickjacking Header" in alert:
        return f"SecRule RESPONSE_HEADERS:X-Frame-Options \"!@rx (DENY|SAMEORIGIN)\" " \
               f"\"id:1025,phase:3,deny,msg:'Missing Anti-Clickjacking Header',t:none\""
    elif "CSP: Wildcard Directive" in alert:
        return f"SecRule RESPONSE_HEADERS:Content-Security-Policy \"@rx \\*\" " \
               f"\"id:1026,phase:3,deny,msg:'CSP Wildcard Directive Detected',t:none\""
    elif "CSP: style-src unsafe-inline" in alert:
        return f"SecRule RESPONSE_HEADERS:Content-Security-Policy \"@contains style-src 'unsafe-inline'\" " \
               f"\"id:1027,phase:3,deny,msg:'CSP Unsafe Inline style-src Detected',t:none\""
    elif "CSP: script-src unsafe-eval" in alert:
        return f"SecRule RESPONSE_HEADERS:Content-Security-Policy \"@contains script-src 'unsafe-eval'\" " \
               f"\"id:1028,phase:3,deny,msg:'CSP Unsafe Eval script-src Detected',t:none\""
    elif "Cross-Domain Misconfiguration" in alert:
        if "Missing Access-Control-Allow-Origin" in description:
            return f"SecRule RESPONSE_HEADERS:Access-Control-Allow-Origin \"@streq ''\" " \
                   f"\"id:1029,phase:3,deny,msg:'Missing Access-Control-Allow-Origin Header',t:none\""
        elif "Wildcard in Access-Control-Allow-Origin" in description:
            return f"SecRule RESPONSE_HEADERS:Access-Control-Allow-Origin \"@rx \\*\" " \
                   f"\"id:1030,phase:3,deny,msg:'Wildcard Access-Control-Allow-Origin Header Detected',t:none\""
        elif "Missing Access-Control-Allow-Credentials" in description:
            return f"SecRule RESPONSE_HEADERS:Access-Control-Allow-Credentials \"!@streq true\" " \
                   f"\"id:1031,phase:3,deny,msg:'Missing Access-Control-Allow-Credentials Header',t:none\""
    elif "Session ID in URL Rewrite" in alert:
        return f"SecRule ARGS \"@rx (\\?sessionid=|&sessionid=)\" " \
               f"\"id:1032,phase:2,deny,msg:'Session ID in URL Rewrite Detected',t:none\""

    # Generic fallback rule for unclassified alerts
    else:
        #print(f"No rule template available for alert: {alert}")
        return None


def write_rules_to_file(rules, output_file=FIREWALL_RULES_FILE):
    """
    Write the generated SecRules to a file without duplication.
    """
    if not rules:
        print("No rules generated to write.")
        return

    # Use a set to store unique rules (avoids duplicates)
    unique_rules = set(rules)

    with open(output_file, 'w') as file:
        for rule in unique_rules:
            file.write(rule + "\n\n")
    print(f"Unique firewall rules saved to {output_file}")


def generate_firewall_rules():
    """Parse log and generate SecRules at the end of the session."""
    print("Generating firewall rules...")
    rules = parse_scan_log(SCAN_LOG_FILE)
    write_rules_to_file(rules)


def handle_exit(signum, frame):
    """Handle SIGINT for graceful termination."""
    print("\nTermination signal received. Generating firewall rules...")
    stop_event.set()

    # Generate firewall rules at session end
    generate_firewall_rules()

    # Stop threads
    if zap_thread and zap_thread.is_alive():
        zap_thread.join(timeout=5)
    if ml_classification_thread and ml_classification_thread.is_alive():
        ml_classification_thread.join(timeout=5)

    print("Exiting program.")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_exit)

    print("Starting OWASP ZAP scanner and real-time ML system.")
    zap_thread = threading.Thread(target=zap_scanner_thread)
    ml_classification_thread = threading.Thread(target=ml_thread)

    zap_thread.start()
    ml_classification_thread.start()

    while not stop_event.is_set():
        time.sleep(1)
