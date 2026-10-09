# SOC Security Monitoring Dashboard

A mini Security Operations Center (SOC) console: it collects logs, detects attacks with
correlation rules mapped to MITRE ATT&CK, raises alerts, and lets an analyst triage them
(acknowledge, resolve, block IP) from a live web dashboard.

## 1. Architecture

```
 Log sources / Simulator ──► POST /api/ingest ──► Detector (rules) ──► SQLite (logs, alerts, blocked_ips)
                                                                              │
                                      Browser dashboard (Chart.js) ◄── REST API (Flask) ◄┘
```

| File | Role |
|------|------|
| `simulator.py` | Generates normal traffic + 6 attack scenarios (stand-in for real log sources) |
| `detector.py` | Stateful detection rules (sliding windows, threat-intel, regex) |
| `db.py` | SQLite schema and helpers |
| `app.py` | Flask app: ingestion, REST API, simulated firewall block-list |
| `templates/index.html`, `static/style.css`, `static/app.js` | Dashboard UI |

## 1b. The interface

A light, white admin-template design with a left sidebar and four pages:

| Page | What it shows |
|------|---------------|
| Dashboard | Threat-level badge, 6 KPI cards, events/alerts timeline, severity donut, top attacking IPs, detections by rule, latest open alerts |
| Alerts | Full alert queue with status/severity filters; Acknowledge, Resolve, Block/Unblock |
| Log Explorer | Searchable event stream (IP, user, message) |
| Blocked IPs | Firewall block list; block an IP manually or unblock one |

"Simulate attack" (top bar) triggers a chosen attack; "Pause traffic" (sidebar) stops the background simulator.
It also works on phones and tablets (the sidebar becomes a slide-out menu).
To change colours, edit the variables at the top of `static/style.css`.

## 2. Run it (step by step)

```bash
# 1. Python 3.9+ required
python --version

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the server (simulator on)
python app.py                   # add --reset to wipe old data

# 5. Open the dashboard
#    http://127.0.0.1:5000
```

Options: `--no-sim` (real events only), `--host 0.0.0.0 --port 8080`.
Optional write-protection: `export SOC_API_KEY=mysecret` and send header `X-API-Key: mysecret`
(note: the browser UI does not send the key; use it for the ingest API / scripts).

## 3. Detection rules

| Rule | Logic | Severity | MITRE |
|------|-------|----------|-------|
| BRUTE_FORCE | ≥5 failed logins from one IP in 60 s | High | T1110 |
| CREDENTIAL_COMPROMISE | Successful login after ≥5 failures from the same IP | Critical | T1078 |
| PORT_SCAN | ≥10 distinct ports from one IP in 30 s | Medium | T1046 |
| SQL_INJECTION | SQLi patterns in HTTP requests | High | T1190 |
| XSS_ATTEMPT | Script patterns in HTTP requests | Medium | T1189 |
| DATA_EXFILTRATION | Outbound transfer ≥100 MB | High | T1048 |
| THREAT_INTEL_MATCH | Any traffic from a known-bad IP | Critical | T1071 |
| OFF_HOURS_ADMIN_LOGIN | admin/root login outside 07:00–20:00 | Low | T1078 |

Thresholds are constants at the top of `detector.py`. Alerts for the same rule+IP are
de-duplicated for 60 s to avoid alert storms.

## 4. Send your own events

```bash
curl -X POST http://127.0.0.1:5000/api/ingest -H "Content-Type: application/json" -d '{
  "source": "auth", "event_type": "login_failed", "src_ip": "203.0.113.50",
  "username": "root", "message": "Failed password"
}'
```

Supported `event_type` values used by the rules: `login_failed`, `login_success`, `conn`
(needs `port`), `http_request` (attack text in `message`), `transfer` (needs `bytes`).
A JSON array of events is also accepted. To parse real files (e.g. `/var/log/auth.log`),
write a small script that reads lines, builds these dicts, and POSTs them.

## 5. API reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/overview` | KPIs, severity counts, top IPs, rule counts, 30-min timeline |
| GET | `/api/alerts?status=&severity=&limit=` | Alert queue |
| POST | `/api/alerts/<id>/status` | `{"status": "acknowledged|resolved|open"}` |
| GET | `/api/logs?q=&limit=` | Log search |
| POST | `/api/block` | `{"ip": "...", "unblock": false}` |
| GET | `/api/blocked` | Blocked IP list |
| POST | `/api/simulate/<scenario>` | bruteforce, portscan, sqli, xss, exfil, threatintel, toggle |
| POST | `/api/ingest` | Submit event(s) |

## 6. Demo script (for your presentation)

1. Show the live dashboard with normal traffic.
2. Click **Brute force** → watch BRUTE_FORCE (and possibly CREDENTIAL_COMPROMISE) alerts appear.
3. Click **Block IP** on the attacker → further traffic shows as `[DROPPED by firewall]` in the log stream.
4. Click **Port scan**, **SQL injection**, **Exfiltration** and show the MITRE column.
5. Acknowledge and resolve alerts to demonstrate the triage workflow.

## 7. Security notes / hardening ideas

- The UI escapes all log content before rendering (logs are attacker-controlled).
- Add user login (Flask-Login) and role-based access before exposing this beyond localhost.
- Put it behind HTTPS (nginx / Caddy) and bind to 127.0.0.1 unless you need remote access.
- Replace SQLite with PostgreSQL/Elasticsearch for high volume; add log retention.

## 8. Extension ideas

IP geolocation map, email/Slack alert notifications, real threat-intel feeds (AbuseIPDB),
syslog UDP listener, machine-learning anomaly detection, Docker packaging.
