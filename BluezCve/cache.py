import sqlite3
import json
import time

DB_FILE = "bluezcve_cache.db"
TTL = 60 * 60 * 24  # 24 jam


def _conn():
    return sqlite3.connect(DB_FILE)


def init_cache():
    with _conn() as c:
        c.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            key TEXT PRIMARY KEY,
            value TEXT,
            ts INTEGER
        )
        """)


def get_cache(key):
    with _conn() as c:
        row = c.execute(
            "SELECT value, ts FROM cve_cache WHERE key=?",
            (key,),
        ).fetchone()

    if not row:
        return None

    value, ts = row
    if time.time() - ts > TTL:
        return None

    return json.loads(value)


def set_cache(key, value):
    with _conn() as c:
        c.execute(
            "REPLACE INTO cve_cache VALUES (?, ?, ?)",
            (key, json.dumps(value), int(time.time())),
        )
