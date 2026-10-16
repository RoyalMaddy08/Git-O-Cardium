"""Persistent record store with PERSISTED PROVENANCE.

Complaints, archived complaints and work-order notes are saved here. Every record keeps where it came from
(origin), a trust label and its lineage (which records it was derived from). Trust is inherited: anything
derived from an untrusted record stays untrusted. Retrieving a record later returns it with that persisted
label, so internal storage never "launders" public text into trusted data.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass

from .schemas import ContentItem, Provenance

SCHEMA = """CREATE TABLE IF NOT EXISTS records (
  id TEXT PRIMARY KEY, kind TEXT, text TEXT, trust TEXT, origin TEXT, lineage TEXT, author TEXT, ts REAL);"""
KINDS = ("complaint", "archive", "work_order_note")


@dataclass
class StoredRecord:
    id: str
    kind: str
    text: str
    trust: str
    origin: str
    lineage: tuple[str, ...]
    author: str


class RecordStore:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def _row(self, r) -> StoredRecord:
        return StoredRecord(r["id"], r["kind"], r["text"], r["trust"], r["origin"], tuple(json.loads(r["lineage"])), r["author"])

    def get(self, rid: str) -> StoredRecord | None:
        r = self.db.execute("SELECT * FROM records WHERE id=?", (rid,)).fetchone()
        return None if r is None else self._row(r)

    def save(self, rid: str, kind: str, text: str, *, origin: str, author: str,
             parents: list[str] = (), trusted: bool = False) -> StoredRecord:
        """trusted=True is only for records created by trusted system code with no untrusted parent.
        Any untrusted parent makes the new record untrusted, whatever the caller asks for."""
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        parent_recs = [self.get(p) for p in parents]
        if any(p is None for p in parent_recs):
            raise ValueError("unknown parent record")
        untrusted = (not trusted) or any(p.trust == Provenance.UNTRUSTED_EXTERNAL.value for p in parent_recs)
        lineage = [x for p in parent_recs for x in (*p.lineage, p.id)]
        if parent_recs and {p.origin for p in parent_recs} != {origin}:  # the origin chain survives derivation: writer <- original public source
            origin = " <- ".join([origin, *dict.fromkeys(p.origin for p in parent_recs)])
        self.db.execute("INSERT OR REPLACE INTO records VALUES (?,?,?,?,?,?,?,?)",
                        (rid, kind, text, (Provenance.UNTRUSTED_EXTERNAL if untrusted else Provenance.TRUSTED_USER).value,
                         origin, json.dumps(lineage), author, time.time()))
        self.db.commit()
        return self.get(rid)

    def archive(self, rid: str, *, author: str = "system:archiver") -> StoredRecord:
        """Copies a record into the archive. Provenance and origin are preserved, lineage records the copy."""
        src = self.get(rid)
        if src is None:
            raise ValueError("unknown record")
        return self.save(f"archive:{rid}", "archive", src.text, origin=src.origin, author=author, parents=[rid],
                         trusted=src.trust == Provenance.TRUSTED_USER.value)

    def retrieve(self, rid: str) -> ContentItem:
        """Later retrieval: the item carries the PERSISTED trust label, origin and lineage."""
        r = self.get(rid)
        if r is None:
            raise KeyError(rid)
        return ContentItem(id=f"stored:{r.kind}:{r.id}", source=f"stored:{r.kind}:{r.id}", text=r.text,
                           provenance=Provenance(r.trust), origin=r.origin, lineage=(*r.lineage, r.id))
