"""Detection engine: stateful, rule-based correlation over a stream of events.

Each rule is mapped to a MITRE ATT&CK technique so alerts are easy to triage.
"""
import re
from collections import defaultdict, deque
from datetime import datetime

SQLI_RE = re.compile(
    r"(union\s+select|or\s+1\s*=\s*1|'\s*--|drop\s+table|sleep\(\d+\)|information_schema)",
    re.I,
)
XSS_RE = re.compile(r"(<script|onerror\s*=|javascript:)", re.I)

# Tiny "threat intelligence feed" of known-bad IPs (documentation/test addresses).
THREAT_INTEL = {"185.220.101.7", "45.155.205.233", "91.240.118.50"}

ADMIN_USERS = {"admin", "root", "administrator"}

# Tunable thresholds
BRUTE_FORCE_THRESHOLD = 5      # failed logins ...
BRUTE_FORCE_WINDOW = 60        # ... within N seconds
PORT_SCAN_THRESHOLD = 10       # distinct ports ...
PORT_SCAN_WINDOW = 30          # ... within N seconds
EXFIL_BYTES = 100 * 1024 * 1024  # 100 MB outbound in a single transfer
COOLDOWN = 60                  # seconds before the same rule+IP can alert again
OFF_HOURS = (7, 20)            # admin logins outside 07:00-20:00 are suspicious


class Detector:
    def __init__(self):
        self.failed = defaultdict(deque)   # ip -> timestamps of failed logins
        self.ports = defaultdict(deque)    # ip -> (timestamp, port)
        self.last_alert = {}               # (rule, ip) -> last alert ts

    def _alert(self, ev, rule, severity, description, mitre):
        key = (rule, ev["src_ip"])
        if ev["ts"] - self.last_alert.get(key, 0) < COOLDOWN:
            return None  # de-duplicate alert storms
        self.last_alert[key] = ev["ts"]
        return {
            "ts": ev["ts"],
            "rule": rule,
            "severity": severity,
            "src_ip": ev["src_ip"],
            "description": description,
            "mitre": mitre,
        }

    def process(self, ev):
        alerts = []
        ip, now, etype = ev["src_ip"], ev["ts"], ev["event_type"]
        msg = ev.get("message") or ""

        # 1. Threat-intel match (any traffic from a known-bad IP)
        if ip in THREAT_INTEL:
            alerts.append(self._alert(
                ev, "THREAT_INTEL_MATCH", "critical",
                f"Traffic from known malicious IP {ip}", "T1071"))

        # 2. Brute force + 3. Credential compromise
        if etype == "login_failed":
            dq = self.failed[ip]
            dq.append(now)
            while dq and now - dq[0] > 300:
                dq.popleft()
            recent = sum(1 for t in dq if now - t <= BRUTE_FORCE_WINDOW)
            if recent >= BRUTE_FORCE_THRESHOLD:
                alerts.append(self._alert(
                    ev, "BRUTE_FORCE", "high",
                    f"{recent} failed logins from {ip} in {BRUTE_FORCE_WINDOW}s "
                    f"(last user: {ev.get('username')})", "T1110"))
        elif etype == "login_success":
            dq = self.failed[ip]
            while dq and now - dq[0] > 300:
                dq.popleft()
            if len(dq) >= BRUTE_FORCE_THRESHOLD:
                alerts.append(self._alert(
                    ev, "CREDENTIAL_COMPROMISE", "critical",
                    f"Successful login for '{ev.get('username')}' from {ip} after "
                    f"{len(dq)} failures - account likely compromised", "T1078"))
            hour = datetime.fromtimestamp(now).hour
            if ev.get("username") in ADMIN_USERS and not (OFF_HOURS[0] <= hour < OFF_HOURS[1]):
                alerts.append(self._alert(
                    ev, "OFF_HOURS_ADMIN_LOGIN", "low",
                    f"Admin login '{ev.get('username')}' at {hour:02d}:00 from {ip}", "T1078"))

        # 4. Port scan
        if etype == "conn" and ev.get("port"):
            dq = self.ports[ip]
            dq.append((now, ev["port"]))
            while dq and now - dq[0][0] > PORT_SCAN_WINDOW:
                dq.popleft()
            distinct = {p for _, p in dq}
            if len(distinct) >= PORT_SCAN_THRESHOLD:
                alerts.append(self._alert(
                    ev, "PORT_SCAN", "medium",
                    f"{ip} probed {len(distinct)} distinct ports in {PORT_SCAN_WINDOW}s", "T1046"))

        # 5. Web attacks
        if etype == "http_request":
            if SQLI_RE.search(msg):
                alerts.append(self._alert(
                    ev, "SQL_INJECTION", "high",
                    f"SQL injection pattern in request from {ip}", "T1190"))
            elif XSS_RE.search(msg):
                alerts.append(self._alert(
                    ev, "XSS_ATTEMPT", "medium",
                    f"Cross-site scripting pattern in request from {ip}", "T1189"))

        # 6. Data exfiltration
        if etype == "transfer" and ev.get("bytes", 0) >= EXFIL_BYTES:
            mb = ev["bytes"] // (1024 * 1024)
            alerts.append(self._alert(
                ev, "DATA_EXFILTRATION", "high",
                f"Large outbound transfer ({mb} MB) from {ip} to {ev.get('dst_ip')}", "T1048"))

        return [a for a in alerts if a]
