"""SOC Security Monitoring Dashboard - Flask backend.

Run:  python app.py            (with built-in traffic simulator)
      python app.py --no-sim   (only accept real events via POST /api/ingest)
"""
import argparse
import os
import threading
import time

from flask import Flask, jsonify, render_template, request

import db
from detector import Detector
from simulator import SCENARIOS, Simulator

app = Flask(__name__)
detector = Detector()
simulator = None
API_KEY = os.environ.get("SOC_API_KEY")  # optional: protects write endpoints

_lock = threading.Lock()
blocked = set()
SEVERITIES = ["critical", "high", "medium", "low"]


# ---------------------------------------------------------------- ingestion
def ingest_event(ev):
    """Store an event, run detection, store any alerts. Used by simulator and API."""
    ev.setdefault("ts", time.time())
    ev.setdefault("source", "unknown")
    ev.setdefault("event_type", "other")
    ev.setdefault("bytes", 0)
    if not ev.get("src_ip"):
        raise ValueError("src_ip is required")

    # Simulated firewall: traffic from blocked IPs is dropped and not analysed.
    if ev["src_ip"] in blocked:
        ev = dict(ev, event_type="blocked_traffic",
                  message="[DROPPED by firewall] " + (ev.get("message") or ""))
        _store_log(ev)
        return []

    _store_log(ev)
    with _lock:
        alerts = detector.process(ev)
    for a in alerts:
        a["id"] = db.execute(
            "INSERT INTO alerts(ts, rule, severity, src_ip, description, mitre) VALUES (?,?,?,?,?,?)",
            (a["ts"], a["rule"], a["severity"], a["src_ip"], a["description"], a["mitre"]))
    return alerts


def _store_log(ev):
    db.execute(
        "INSERT INTO logs(ts, source, event_type, src_ip, dst_ip, username, port, bytes, message) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (ev["ts"], ev["source"], ev["event_type"], ev["src_ip"], ev.get("dst_ip"),
         ev.get("username"), ev.get("port"), ev.get("bytes", 0), ev.get("message")))


def require_key():
    if API_KEY and request.headers.get("X-API-Key") != API_KEY:
        return jsonify(error="invalid or missing X-API-Key"), 401
    return None


# ------------------------------------------------------------------- pages
@app.route("/")
def index():
    return render_template("index.html")


# --------------------------------------------------------------------- API
@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    denied = require_key()
    if denied:
        return denied
    data = request.get_json(silent=True)
    if data is None:
        return jsonify(error="JSON body required"), 400
    events = data if isinstance(data, list) else [data]
    created = []
    try:
        for ev in events:
            created += ingest_event(ev)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    return jsonify(ingested=len(events), alerts=len(created)), 201


@app.route("/api/overview")
def api_overview():
    now = time.time()
    hour_ago = now - 3600

    total_logs = db.query("SELECT COUNT(*) n FROM logs")[0]["n"]
    logs_hour = db.query("SELECT COUNT(*) n FROM logs WHERE ts > ?", (hour_ago,))[0]["n"]
    open_alerts = db.query("SELECT COUNT(*) n FROM alerts WHERE status='open'")[0]["n"]
    crit_open = db.query(
        "SELECT COUNT(*) n FROM alerts WHERE status='open' AND severity='critical'")[0]["n"]
    total_alerts = db.query("SELECT COUNT(*) n FROM alerts")[0]["n"]

    sev_rows = db.query(
        "SELECT severity, COUNT(*) n FROM alerts WHERE status!='resolved' GROUP BY severity")
    sev = {s: 0 for s in SEVERITIES}
    sev.update({r["severity"]: r["n"] for r in sev_rows})

    rules = db.query(
        "SELECT rule, COUNT(*) n FROM alerts GROUP BY rule ORDER BY n DESC LIMIT 8")
    top_ips = db.query(
        "SELECT src_ip ip, COUNT(*) n FROM alerts GROUP BY src_ip ORDER BY n DESC LIMIT 8")

    # events + alerts per minute for the last 30 minutes
    start = int(now // 60) - 29
    buckets = {m: [0, 0] for m in range(start, start + 30)}
    for r in db.query(
            "SELECT CAST(ts/60 AS INTEGER) m, COUNT(*) n FROM logs WHERE ts > ? GROUP BY m",
            (start * 60,)):
        if r["m"] in buckets:
            buckets[r["m"]][0] = r["n"]
    for r in db.query(
            "SELECT CAST(ts/60 AS INTEGER) m, COUNT(*) n FROM alerts WHERE ts > ? GROUP BY m",
            (start * 60,)):
        if r["m"] in buckets:
            buckets[r["m"]][1] = r["n"]
    timeline = [{"t": m * 60, "events": v[0], "alerts": v[1]} for m, v in buckets.items()]

    return jsonify(
        kpis={"total_logs": total_logs, "logs_hour": logs_hour, "open_alerts": open_alerts,
              "critical_open": crit_open, "total_alerts": total_alerts,
              "blocked_ips": len(blocked)},
        severity=sev, rules=rules, top_ips=top_ips, timeline=timeline,
        simulator=bool(simulator and simulator.running))


@app.route("/api/alerts")
def api_alerts():
    sql, params = "SELECT * FROM alerts WHERE 1=1", []
    for col in ("status", "severity"):
        val = request.args.get(col)
        if val:
            sql += f" AND {col}=?"
            params.append(val)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(min(int(request.args.get("limit", 50)), 500))
    rows = db.query(sql, params)
    for r in rows:
        r["blocked"] = r["src_ip"] in blocked
    return jsonify(rows)


@app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
def api_alert_status(alert_id):
    denied = require_key()
    if denied:
        return denied
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("open", "acknowledged", "resolved"):
        return jsonify(error="status must be open, acknowledged or resolved"), 400
    db.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
    return jsonify(ok=True)


@app.route("/api/logs")
def api_logs():
    sql, params = "SELECT * FROM logs WHERE 1=1", []
    q = request.args.get("q")
    if q:
        sql += " AND (src_ip LIKE ? OR message LIKE ? OR username LIKE ?)"
        params += [f"%{q}%"] * 3
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(min(int(request.args.get("limit", 40)), 500))
    return jsonify(db.query(sql, params))


@app.route("/api/block", methods=["POST"])
def api_block():
    denied = require_key()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify(error="ip required"), 400
    if data.get("unblock"):
        blocked.discard(ip)
        db.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    else:
        blocked.add(ip)
        db.execute("INSERT OR REPLACE INTO blocked_ips(ip, ts, reason) VALUES (?,?,?)",
                   (ip, time.time(), data.get("reason", "Blocked from dashboard")))
    return jsonify(ok=True, blocked=sorted(blocked))


@app.route("/api/blocked")
def api_blocked():
    return jsonify(db.query("SELECT * FROM blocked_ips ORDER BY ts DESC"))


@app.route("/api/simulate/<name>", methods=["POST"])
def api_simulate(name):
    denied = require_key()
    if denied:
        return denied
    if name == "toggle":
        if simulator:
            simulator.running = not simulator.running
        return jsonify(running=bool(simulator and simulator.running))
    if name not in SCENARIOS:
        return jsonify(error=f"unknown scenario, choose from {sorted(SCENARIOS)}"), 404
    threading.Thread(target=SCENARIOS[name], args=(ingest_event,), daemon=True).start()
    return jsonify(started=name)


# -------------------------------------------------------------------- main
def main():
    global simulator
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-sim", action="store_true", help="disable the traffic simulator")
    parser.add_argument("--reset", action="store_true", help="wipe the database on start")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    db.init_db(reset=args.reset)
    blocked.update(r["ip"] for r in db.query("SELECT ip FROM blocked_ips"))

    if not args.no_sim:
        simulator = Simulator(ingest_event)
        simulator.start()

    print(f"SOC dashboard running at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
