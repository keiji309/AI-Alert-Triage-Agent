from __future__ import annotations

from typing import Dict, List, Optional

# Lightweight organization graph used by get_user_context / get_asset_context.
# In production this would be backed by an identity provider + CMDB.

USERS: Dict[str, Dict] = {
    "alice.smith": {"role": "IT Administrator", "department": "IT", "admin": True, "service": False,
                    "known_locations": ["Manila, PH", "Singapore, SG"], "expected_devices": ["work-laptop"]},
    "bob.johnson": {"role": "Finance Analyst", "department": "Finance", "admin": False, "service": False,
                    "known_locations": ["Manila, PH"], "expected_devices": ["work-laptop"]},
    "carol.davis": {"role": "Developer / IT Admin", "department": "Engineering", "admin": True, "service": False,
                    "known_locations": ["Manila, PH", "Singapore, SG"], "expected_devices": ["work-laptop", "carol-mbp"]},
    "dave.wilson": {"role": "Marketing", "department": "Marketing", "admin": False, "service": False,
                    "known_locations": ["Manila, PH"], "expected_devices": ["work-laptop"]},
    "eve.martin": {"role": "HR Specialist", "department": "HR", "admin": False, "service": False,
                   "known_locations": ["Manila, PH"], "expected_devices": ["work-laptop", "iphone-14"]},
    "frank.ruiz": {"role": "IT Administrator (on-call)", "department": "IT", "admin": True, "service": False,
                   "known_locations": ["Manila, PH"], "expected_devices": ["work-laptop"]},
    "backup.svc": {"role": "Scheduled backup service", "department": "Infra", "admin": False, "service": True,
                   "known_locations": [], "expected_devices": []},
    "scanner.svc": {"role": "Vulnerability scanner service", "department": "Security", "admin": False, "service": True,
                    "known_locations": [], "expected_devices": []},
    "qa.automation": {"role": "QA automation account", "department": "QA", "admin": False, "service": True,
                      "known_locations": [], "expected_devices": []},
}

ASSETS: Dict[str, Dict] = {
    "corp-ws-01": {"owner": "alice.smith", "role": "admin workstation", "criticality": "high", "os": "Windows 11", "svc_mgr": "alice.smith"},
    "corp-ws-02": {"owner": "bob.johnson", "role": "finance workstation", "criticality": "medium", "os": "Windows 11"},
    "corp-ws-03": {"owner": "carol.davis", "role": "developer workstation", "criticality": "medium", "os": "Windows 11"},
    "corp-ws-04": {"owner": "dave.wilson", "role": "marketing workstation", "criticality": "low", "os": "Windows 11"},
    "corp-ws-05": {"owner": "eve.martin", "role": "hr workstation", "criticality": "high", "os": "Windows 11"},
    "corp-ws-06": {"owner": "frank.ruiz", "role": "it workstation", "criticality": "high", "os": "Windows 11"},
    "corp-ws-test-01": {"owner": "qa-automation", "role": "AV validation VM", "criticality": "low", "os": "Windows 11", "notes": "designated EICAR/AV test host"},
    "corp-ws-test-02": {"owner": "qa-automation", "role": "AV validation VM", "criticality": "low", "os": "Windows 11", "notes": "designated EICAR/AV test host"},
    "corp-srv-db01": {"owner": "it-team", "role": "production database", "criticality": "critical", "os": "Ubuntu 22.04"},
    "corp-srv-web01": {"owner": "it-team", "role": "corporate website / IIS", "criticality": "high", "os": "Windows Server 2022"},
    "corp-srv-app02": {"owner": "it-team", "role": "application server", "criticality": "high", "os": "Windows Server 2022"},
    "corp-srv-file01": {"owner": "it-team", "role": "central file share (Finance)", "criticality": "critical", "os": "Windows Server 2022"},
    "corp-egress-1": {"owner": "network", "role": "internet egress", "criticality": "infra"},
    "corp-egress-2": {"owner": "network", "role": "internet egress", "criticality": "infra"},
    "corp-vpn-1": {"owner": "network", "role": "VPN concentrator", "criticality": "infra"},
    "scanner-node-1": {"owner": "security", "role": "vuln scanner node", "criticality": "low"},
    "backup-srv-1": {"owner": "infra", "role": "backup server", "criticality": "medium"},
}

MITRE_KB: Dict[str, Dict[str, str]] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "description": "Repeated credential guessing/logon attempts against an account or service."},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion / Lateral Movement / Persistence",
              "description": "Adversary leverages a legitimate account that already has access."},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access",
                  "description": "Victim clicks a link in spearphishing content leading to credential theft/beacon."},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command & Control",
              "description": "Adversary copies tools/files to a compromised system."},
    "T1621": {"name": "Multi-Factor Authentication Request Generation", "tactic": "Credential Access",
              "description": "MFA push prompts spammed until the user approves (fatigue)."},
    "T1090.003": {"name": "Proxy: Multi-hop Proxy", "tactic": "Command & Control",
                  "description": "Traffic routed through proxies/Tor to obscure the C2 channel."},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence",
                  "description": "Malware registers a scheduled task for persistence / privilege gain."},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution",
                  "description": "PowerShell abuse, commonly with encoded (-EncodedCommand) payloads."},
    "T1074.001": {"name": "Data Staged: Local", "tactic": "Collection", "description": "Malware stages data locally before exfil."},
    "T1048.003": {"name": "Exfiltration Over Alternative Protocol: HTTPS", "tactic": "Exfiltration",
                  "description": "Data exfil over HTTPS to hide in normal TLS traffic."},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access",
                  "description": "LSASS memory read to harvest credentials (mimikatz-style)."},
    "T1021.001": {"name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement",
                  "description": "PsExec/admin-share access to run commands on remote hosts."},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement",
              "description": "Adversary moves tools between compromised hosts."},
    "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion",
                  "description": "Event logs cleared / auditing disabled — artifact destruction."},
    "T1496": {"name": "Resource Hijacking", "tactic": "Impact",
              "description": "Host CPU hijacked for cryptocurrency mining."},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery",
              "description": "Port/service scanning to map the network."},
    "T1505.003": {"name": "Server Software Component: Web Shell", "tactic": "Persistence",
                  "description": "Web shell placed in a web server root for remote control."},
}


def get_user(user: str) -> Optional[Dict]:
    return USERS.get(user)


def get_asset(host: str) -> Optional[Dict]:
    return ASSETS.get(host)


def get_mitre_technique(tid: str) -> Optional[Dict]:
    return MITRE_KB.get(tid)