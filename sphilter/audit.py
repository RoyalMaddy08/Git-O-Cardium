"""SQLite audit trail: every ingest, proposal, decision and outcome."""
from __future__ import annotations

import json
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, run_id TEXT, scenario_id TEXT, mode TEXT, task_id TEXT,
  kind TEXT,            -- INGEST | PROPOSAL
  tool TEXT, args TEXT, provenance TEXT, derived_from TEXT,
  decision TEXT,        -- ALLOW | DENY | PENDING_APPROVAL | -
  rule TEXT, reason TEXT, executed INTEGER, result TEXT, policy_ms REAL
);
"""


class AuditLog:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def record(self, **kw) -> None:
        cols = ["ts", "run_id", "scenario_id", "mode", "task_id", "kind", "tool", "args", "provenance",
                "derived_from", "decision", "rule", "reason", "executed", "result", "policy_ms"]
        row = {c: kw.get(c) for c in cols}
        row["ts"] = time.time()
        for k in ("args", "derived_from", "result"):
            if row[k] is not None and not isinstance(row[k], str):
                row[k] = json.dumps(row[k], default=str)
        self.db.execute(f"INSERT INTO events ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                        [row[c] for c in cols])
        self.db.commit()

    def rows(self, run_id: str | None = None, kind: str | None = None) -> list[dict]:
        q, p = "SELECT * FROM events WHERE 1=1", []
        if run_id:
            q += " AND run_id=?"; p.append(run_id)
        if kind:
            q += " AND kind=?"; p.append(kind)
        return [dict(r) for r in self.db.execute(q + " ORDER BY id", p)]

    def count(self, kind: str, run_id: str | None = None) -> int:
        return len(self.rows(run_id, kind))
