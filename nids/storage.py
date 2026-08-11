from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock

from .flows import Flow


class Storage:
    def __init__(self, path: str = "data/nids.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        with self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL, dst_port INTEGER NOT NULL,
                    protocol INTEGER NOT NULL, duration REAL NOT NULL,
                    total_packets INTEGER NOT NULL, total_bytes INTEGER NOT NULL,
                    features_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    attack_type TEXT NOT NULL, confidence REAL NOT NULL,
                    source TEXT NOT NULL, destination TEXT NOT NULL,
                    src_port INTEGER NOT NULL, dst_port INTEGER NOT NULL,
                    protocol INTEGER NOT NULL, reason TEXT,
                    flow_id INTEGER, feedback TEXT
                );
                """
            )

    def add_flow(self, flow: Flow, features: dict[str, float]) -> int:
        with self.lock, self.connection:
            cursor = self.connection.execute(
                """INSERT INTO flows
                (created_at,src_ip,dst_ip,src_port,dst_port,protocol,duration,
                 total_packets,total_bytes,features_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (flow.last_seen, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
                 flow.protocol, flow.duration(), flow.total_packets(), flow.total_bytes(),
                 json.dumps(features)),
            )
            return int(cursor.lastrowid)

    def add_alert(self, flow: Flow, attack_type: str, confidence: float,
                  reason: str | None, flow_id: int) -> int:
        with self.lock, self.connection:
            cursor = self.connection.execute(
                """INSERT INTO alerts
                (created_at,attack_type,confidence,source,destination,src_port,
                 dst_port,protocol,reason,flow_id)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (flow.last_seen, attack_type, confidence,
                 f"{flow.src_ip}:{flow.src_port}", f"{flow.dst_ip}:{flow.dst_port}",
                 flow.src_port, flow.dst_port, flow.protocol, reason, flow_id),
            )
            return int(cursor.lastrowid)

    def list_alerts(self, limit: int = 100, attack_type: str | None = None) -> list[dict]:
        query = "SELECT * FROM alerts"
        params: list = []
        if attack_type:
            query += " WHERE attack_type = ?"
            params.append(attack_type)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        return [dict(row) for row in self.connection.execute(query, params).fetchall()]

    def list_flows(self, limit: int = 100, search: str | None = None) -> list[dict]:
        query = "SELECT * FROM flows"
        params: list = []
        if search:
            query += " WHERE src_ip LIKE ? OR dst_ip LIKE ?"
            params += [f"%{search}%", f"%{search}%"]
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        rows = []
        for row in self.connection.execute(query, params).fetchall():
            result = dict(row)
            result["features"] = json.loads(result.pop("features_json"))
            rows.append(result)
        return rows

    def get_alert(self, alert_id: int) -> dict | None:
        row = self.connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None

    def feedback(self, alert_id: int, value: str) -> bool:
        if value not in {"true_positive", "false_positive"}:
            return False
        with self.lock, self.connection:
            cursor = self.connection.execute(
                "UPDATE alerts SET feedback = ? WHERE id = ?", (value, alert_id)
            )
            return cursor.rowcount > 0

    def stats(self) -> dict:
        row = self.connection.execute(
            """SELECT COUNT(*) AS flows,
            SUM(CASE WHEN total_bytes > 0 THEN 1 ELSE 0 END) AS active_flows
            FROM flows"""
        ).fetchone()
        alerts = self.connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        high = self.connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE confidence >= 0.9"
        ).fetchone()[0]
        return {
            "flows": int(row["flows"] or 0),
            "active_flows": int(row["active_flows"] or 0),
            "alerts": int(alerts),
            "high_confidence_alerts": int(high),
        }
