"""Traffic simulator: generates realistic background noise plus attack scenarios,
so the dashboard has live data without needing real log sources."""
import random
import threading
import time

INTERNAL = [f"10.0.0.{i}" for i in range(10, 40)]
SERVERS = ["10.0.1.5", "10.0.1.6", "10.0.1.20"]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
EXTERNAL_ATTACKERS = [
    "185.220.101.7", "45.155.205.233", "91.240.118.50",
    "103.77.12.9", "198.51.100.23", "203.0.113.66",
]
PATHS = ["/", "/login", "/api/items", "/products?id=%d", "/about", "/search?q=laptop"]


def _ev(source, event_type, src_ip, **kw):
    ev = {"ts": time.time(), "source": source, "event_type": event_type, "src_ip": src_ip}
    ev.update(kw)
    return ev


# ---------- normal traffic ----------
def normal_event():
    r = random.random()
    ip = random.choice(INTERNAL)
    srv = random.choice(SERVERS)
    if r < 0.40:
        path = random.choice(PATHS)
        if "%d" in path:
            path = path % random.randint(1, 500)
        return _ev("web-server", "http_request", ip, dst_ip=srv, port=443,
                   message=f"GET {path} 200")
    if r < 0.60:
        return _ev("auth", "login_success", ip, dst_ip=srv, username=random.choice(USERS),
                   message="Login successful")
    if r < 0.68:
        return _ev("auth", "login_failed", ip, dst_ip=srv, username=random.choice(USERS),
                   message="Wrong password (user typo)")
    if r < 0.88:
        return _ev("firewall", "conn", ip, dst_ip=srv, port=random.choice([22, 80, 443, 3306]),
                   message="Connection allowed")
    if r < 0.95:
        return _ev("dns", "dns", ip, message="Query: " + random.choice(
            ["google.com", "github.com", "office365.com", "slack.com"]))
    return _ev("proxy", "transfer", ip, dst_ip="93.184.216.34", bytes=random.randint(10_000, 5_000_000),
               message="Outbound transfer")


# ---------- attack scenarios ----------
def brute_force(emit):
    ip = random.choice(EXTERNAL_ATTACKERS)
    target = random.choice(SERVERS)
    for _ in range(random.randint(7, 12)):
        emit(_ev("auth", "login_failed", ip, dst_ip=target, port=22,
                 username=random.choice(["root", "admin", "test", "oracle"]),
                 message="Failed password (SSH)"))
        time.sleep(0.3)
    if random.random() < 0.5:  # sometimes the attacker gets in
        emit(_ev("auth", "login_success", ip, dst_ip=target, port=22,
                 username="admin", message="Accepted password (SSH)"))


def port_scan(emit):
    ip = random.choice(EXTERNAL_ATTACKERS)
    target = random.choice(SERVERS)
    for port in random.sample(range(20, 9000), 16):
        emit(_ev("firewall", "conn", ip, dst_ip=target, port=port, message="SYN probe"))
        time.sleep(0.15)


def sql_injection(emit):
    ip = random.choice(EXTERNAL_ATTACKERS)
    payloads = ["GET /products?id=1 OR 1=1 --", "GET /login?u=admin'--",
                "GET /items?id=1 UNION SELECT username,password FROM users"]
    for p in payloads:
        emit(_ev("web-server", "http_request", ip, dst_ip=SERVERS[0], port=443, message=p))
        time.sleep(0.4)


def xss(emit):
    ip = random.choice(EXTERNAL_ATTACKERS)
    emit(_ev("web-server", "http_request", ip, dst_ip=SERVERS[0], port=443,
             message="GET /search?q=<script>alert(document.cookie)</script>"))


def exfiltration(emit):
    ip = random.choice(INTERNAL)
    emit(_ev("proxy", "transfer", ip, dst_ip=random.choice(EXTERNAL_ATTACKERS),
             bytes=random.randint(150, 900) * 1024 * 1024,
             message="Large outbound transfer to unknown host"))


def threat_intel(emit):
    ip = random.choice(["185.220.101.7", "45.155.205.233", "91.240.118.50"])
    emit(_ev("firewall", "conn", ip, dst_ip=random.choice(SERVERS), port=443,
             message="Inbound connection from flagged IP"))


SCENARIOS = {
    "bruteforce": brute_force,
    "portscan": port_scan,
    "sqli": sql_injection,
    "xss": xss,
    "exfil": exfiltration,
    "threatintel": threat_intel,
}


class Simulator(threading.Thread):
    def __init__(self, emit, attack_every=(12, 25)):
        super().__init__(daemon=True)
        self.emit = emit
        self.attack_every = attack_every
        self.running = True
        self._next_attack = time.time() + 5

    def run(self):
        while True:
            if self.running:
                for _ in range(random.randint(1, 3)):
                    self.emit(normal_event())
                if time.time() >= self._next_attack:
                    name = random.choice(list(SCENARIOS))
                    threading.Thread(target=SCENARIOS[name], args=(self.emit,), daemon=True).start()
                    self._next_attack = time.time() + random.uniform(*self.attack_every)
            time.sleep(random.uniform(0.3, 0.8))
