#!/usr/bin/env python3
"""
alert-tagger.py — Tag Suricata EVE JSON alerts with MITRE ATT&CK IDs
Usage: python3 alert-tagger.py --input /var/log/suricata/eve.json [--output tagged.json]
"""

import json
import sys
import argparse
from datetime import datetime

# MITRE ATT&CK mapping: keyword in signature -> (Tactic, Technique ID, Name)
MITRE_MAP = {
    "scan":           ("Reconnaissance",     "T1595", "Active Scanning"),
    "nmap":           ("Reconnaissance",     "T1595.001", "Scanning IP Blocks"),
    "sweep":          ("Reconnaissance",     "T1595", "Active Scanning"),
    "brute":          ("Credential Access",  "T1110", "Brute Force"),
    "ssh":            ("Credential Access",  "T1110.003", "Password Spraying"),
    "rdp":            ("Lateral Movement",   "T1021.001", "Remote Desktop Protocol"),
    "smb":            ("Lateral Movement",   "T1021.002", "SMB/Windows Admin Shares"),
    "sql injection":  ("Initial Access",     "T1190", "Exploit Public-Facing Application"),
    "sqli":           ("Initial Access",     "T1190", "Exploit Public-Facing Application"),
    "xss":            ("Initial Access",     "T1059.007", "JavaScript"),
    "lfi":            ("Initial Access",     "T1190", "Exploit Public-Facing Application"),
    "directory traversal": ("Initial Access","T1190", "Exploit Public-Facing Application"),
    "c2":             ("Command & Control",  "T1071", "Application Layer Protocol"),
    "beacon":         ("Command & Control",  "T1071.001", "Web Protocols"),
    "tunnel":         ("Exfiltration",       "T1048", "Exfiltration Over Alternative Protocol"),
    "dns":            ("Command & Control",  "T1071.004", "DNS"),
    "flood":          ("Impact",             "T1499", "Endpoint Denial of Service"),
    "dos":            ("Impact",             "T1498", "Network Denial of Service"),
    "exfil":          ("Exfiltration",       "T1041", "Exfiltration Over C2 Channel"),
    "trojan":         ("Execution",          "T1204", "User Execution"),
    "malware":        ("Execution",          "T1204", "User Execution"),
    "metasploit":     ("Execution",          "T1059", "Command and Scripting Interpreter"),
    "reverse shell":  ("Execution",          "T1059", "Command and Scripting Interpreter"),
    "lateral":        ("Lateral Movement",   "T1210", "Exploitation of Remote Services"),
    "pass-the-hash":  ("Lateral Movement",   "T1550.002", "Pass the Hash"),
}

SEVERITY_MAP = {
    1: "CRITICAL",
    2: "HIGH",
    3: "MEDIUM",
    4: "LOW",
}

def tag_alert(alert: dict) -> dict:
    if alert.get("event_type") != "alert":
        return alert

    sig = alert.get("alert", {}).get("signature", "").lower()
    severity_num = alert.get("alert", {}).get("severity", 3)

    # Find MITRE match
    mitre = None
    for keyword, (tactic, tid, tname) in MITRE_MAP.items():
        if keyword in sig:
            mitre = {"tactic": tactic, "technique_id": tid, "technique_name": tname}
            break

    alert["ids_enrichment"] = {
        "severity_label": SEVERITY_MAP.get(severity_num, "UNKNOWN"),
        "mitre_attack": mitre or {"tactic": "Unknown", "technique_id": "T0000", "technique_name": "Unclassified"},
        "tagged_at": datetime.utcnow().isoformat() + "Z",
        "source_ip": alert.get("src_ip"),
        "dest_ip": alert.get("dest_ip"),
        "proto": alert.get("proto"),
    }
    return alert


def process_file(input_path: str, output_path: str = None):
    tagged = []
    alerts_found = 0
    errors = 0

    print(f"[*] Processing: {input_path}")

    with open(input_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alerts_found += 1
                    event = tag_alert(event)
                tagged.append(event)
            except json.JSONDecodeError:
                errors += 1

    print(f"[+] Total events:  {len(tagged)}")
    print(f"[+] Alerts tagged: {alerts_found}")
    print(f"[!] Parse errors:  {errors}")

    out = output_path or input_path.replace(".json", "_tagged.json")
    with open(out, "w") as f:
        for event in tagged:
            f.write(json.dumps(event) + "\n")

    print(f"[✓] Output saved:  {out}")

    # Summary
    print("\n── MITRE ATT&CK Summary ──")
    tactic_counts = {}
    for event in tagged:
        enrichment = event.get("ids_enrichment", {})
        mitre = enrichment.get("mitre_attack", {})
        tactic = mitre.get("tactic", "Unknown")
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 40)
        print(f"  {tactic:<30} {bar} {count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tag Suricata alerts with MITRE ATT&CK IDs")
    parser.add_argument("--input",  "-i", required=True, help="Path to eve.json")
    parser.add_argument("--output", "-o", help="Output file path (optional)")
    args = parser.parse_args()
    process_file(args.input, args.output)
