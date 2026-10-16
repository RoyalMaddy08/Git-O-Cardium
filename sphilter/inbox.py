"""Citizen inbox: the ONLY thing the public portal can do is drop a submission here.

The portal never touches the gateway, tools or policy. Officers pull submissions from the inbox in the
main dashboard, where the text is processed as untrusted data. Shared SQLite file (data/inbox.db).
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import time
from pathlib import Path

from .auth import WARDS, Officer
from .minimoth import normalize_phone

ROOT = Path(__file__).resolve().parent.parent
INBOX_PATH = Path(os.environ.get("SPHILTER_INBOX", ROOT / "data" / "inbox.db"))
LIMITS = dict(name=(1, 60), location=(3, 120), body=(10, 1000))
PER_PHONE = (5, 600)   # at most 5 submissions per phone per 10 minutes
GLOBAL = (30, 60)      # at most 30 submissions per minute overall
SCHEMA = """CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY, ts REAL, name TEXT, ward TEXT, location TEXT, phone TEXT, body TEXT,
  status TEXT DEFAULT 'NEW', result TEXT, processed_by TEXT, processed_ts REAL);"""


class InboxError(ValueError):
    """Message is safe to show to the citizen."""


def _clean(s: str) -> str:
    return (s or "").replace("\x00", "").strip()


class Inbox:
    def __init__(self, path: Path | str = INBOX_PATH):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---------------------------------------------------------------- citizen side
    def submit(self, name: str, ward: str, location: str, phone: str, body: str, now: float | None = None) -> str:
        now = time.time() if now is None else now
        name, location, body = _clean(name), _clean(location), _clean(body)
        for label, val in (("name", name), ("location", location), ("complaint", body)):
            lo, hi = LIMITS["body" if label == "complaint" else label]
            if not lo <= len(val) <= hi:
                raise InboxError(f"Please enter your {label} ({lo} to {hi} characters).")
        if ward not in WARDS:
            raise InboxError("Please choose a ward from the list.")
        try:
            phone = normalize_phone(phone)
        except ValueError as e:
            raise InboxError(str(e)) from None
        n_phone = self.db.execute("SELECT COUNT(*) FROM submissions WHERE phone=? AND ts>?",
                                  (phone, now - PER_PHONE[1])).fetchone()[0]
        n_all = self.db.execute("SELECT COUNT(*) FROM submissions WHERE ts>?", (now - GLOBAL[1],)).fetchone()[0]
        if n_phone >= PER_PHONE[0] or n_all >= GLOBAL[0]:
            raise InboxError("Too many submissions right now. Please try again in a few minutes.")
        tid = "W-" + secrets.token_hex(4).upper()
        self.db.execute("INSERT INTO submissions (id, ts, name, ward, location, phone, body) VALUES (?,?,?,?,?,?,?)",
                        (tid, now, name, ward, location, phone, body))
        self.db.commit()
        return tid

    def public_status(self, tracking_id: str) -> dict | None:
        """All a citizen can learn about a tracking id: ward, time and a one-word status. Nothing else."""
        r = self.db.execute("SELECT ward, ts, status FROM submissions WHERE id=?", ((tracking_id or "").strip().upper(),)).fetchone()
        return None if r is None else {"ward": r["ward"], "submitted_at": r["ts"],
                                       "status": "Received" if r["status"] == "NEW" else "Reviewed by the ward office"}

    # ---------------------------------------------------------------- officer side
    def get(self, tracking_id: str) -> dict | None:
        r = self.db.execute("SELECT * FROM submissions WHERE id=?", (tracking_id,)).fetchone()
        return None if r is None else dict(r)

    def list_for(self, officer: Officer) -> list[dict]:
        q, p = "SELECT * FROM submissions", ()
        if officer.role != "supervisor":
            q, p = q + " WHERE ward=?", (officer.ward,)
        return [dict(r) for r in self.db.execute(q + " ORDER BY ts DESC", p)]

    def save_result(self, tracking_id: str, result_json: str, officer_id: str) -> None:
        self.db.execute("UPDATE submissions SET status='PROCESSED', result=?, processed_by=?, processed_ts=? WHERE id=?",
                        (result_json, officer_id, time.time(), tracking_id))
        self.db.commit()


def can_view(officer: Officer, sub: dict) -> bool:
    return officer.role == "supervisor" or sub["ward"] == officer.ward
