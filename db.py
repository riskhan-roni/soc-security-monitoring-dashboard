"""SQLite storage layer for the SOC dashboard."""
import os
import sqlite3
import threading
from contextlib import contextmanager

DB_PATH = os.environ.get(
    "SOC_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc.db")
)
_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    source     TEXT,
    event_type TEXT,
    src_ip     TEXT,
    dst_ip     TEXT,
    username   TEXT,
    port       INTEGER,
    bytes      INTEGER DEFAULT 0,
    message    TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    rule        TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    src_ip      TEXT,
    description TEXT,
    mitre       TEXT,
    status      TEXT    NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip     TEXT PRIMARY KEY,
    ts     REAL NOT NULL,
    reason TEXT
);
"""


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(reset=False):
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    with connect() as c:
        c.executescript(SCHEMA)


def query(sql, params=()):
    with connect() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def execute(sql, params=()):
    with _write_lock, connect() as c:
        return c.execute(sql, params).lastrowid
