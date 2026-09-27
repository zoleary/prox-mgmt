"""SQLite storage: metric history, and the queue of changes waiting for approval."""

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics (
    ts REAL, node TEXT, cpu REAL, mem_used INTEGER, mem_total INTEGER, assigned INTEGER
);
CREATE INDEX IF NOT EXISTS metrics_ts ON metrics(ts);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL, tool TEXT, input TEXT, summary TEXT,
    status TEXT DEFAULT 'pending', result TEXT, decided REAL
);
"""


class DB:
    def __init__(self, data_dir: str):
        os.makedirs(data_dir, exist_ok=True)
        self.conn = sqlite3.connect(os.path.join(data_dir, "labpilot.db"), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)

    def add_metrics(self, rows: list[tuple]) -> None:
        with self.lock, self.conn:
            self.conn.executemany("INSERT INTO metrics VALUES (?,?,?,?,?,?)", rows)
            self.conn.execute("DELETE FROM metrics WHERE ts < ?", (time.time() - 30 * 86400,))

    def metrics(self, hours: float) -> list[dict]:
        with self.lock:
            cur = self.conn.execute("SELECT * FROM metrics WHERE ts > ? ORDER BY ts", (time.time() - hours * 3600,))
            return [dict(r) for r in cur]

    def add_action(self, tool: str, params: dict, summary: str) -> int:
        with self.lock, self.conn:
            cur = self.conn.execute("INSERT INTO actions (created, tool, input, summary) VALUES (?,?,?,?)",
                                    (time.time(), tool, json.dumps(params), summary))
            return cur.lastrowid

    def get_action(self, action_id: int) -> dict | None:
        with self.lock:
            row = self.conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        return _action(row) if row else None

    def list_actions(self, limit: int = 50) -> list[dict]:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [_action(r) for r in rows]

    def claim_action(self, action_id: int, status: str) -> bool:
        """Atomically move a pending action to `status`. False if it was already decided."""
        with self.lock, self.conn:
            cur = self.conn.execute("UPDATE actions SET status=?, decided=? WHERE id=? AND status='pending'",
                                    (status, time.time(), action_id))
            return cur.rowcount == 1

    def finish_action(self, action_id: int, status: str, result: str) -> None:
        with self.lock, self.conn:
            self.conn.execute("UPDATE actions SET status=?, result=? WHERE id=?", (status, result, action_id))


def _action(row) -> dict:
    d = dict(row)
    d["input"] = json.loads(d["input"])
    return d
