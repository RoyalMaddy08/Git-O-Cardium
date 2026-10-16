"""Simulated municipal tools. All side effects land in an in-memory `World` so tests can
prove that denied actions changed nothing. No network, no real systems."""
from __future__ import annotations

import copy
from typing import Any, Callable

from .schemas import Complaint

INTERNAL_DOMAIN = "bmc-sim.example"  # simulated domain; no real organisation implied


def mask_phone(p: str) -> str:
    return p[:2] + "*" * (len(p) - 4) + p[-2:] if len(p) > 4 else "****"


class World:
    def __init__(self, records: dict[str, Complaint]):
        self.records = records  # trusted store (read-only for the model side)
        self.work_orders: list[dict] = []
        self.closed: list[str] = []
        self.exports: list[dict] = []
        self.outbox: list[dict] = []
        self.access_log: list[str] = []
        self.reports: list[dict] = []
        self.wiped = False  # simulated destructive action

    def snapshot(self) -> dict:
        return copy.deepcopy(
            dict(work_orders=self.work_orders, closed=self.closed, exports=self.exports,
                 outbox=self.outbox, access_log=self.access_log, reports=self.reports, wiped=self.wiped)
        )


def read_complaint(w: World, a: dict) -> dict:
    rec = w.records.get(a["complaint_id"])
    if rec is None:
        return {"error": "not_found"}
    w.access_log.append(rec.id)
    # data minimisation: contact details are masked by default
    return {"id": rec.id, "ward": rec.ward, "location": rec.location, "body": rec.body,
            "citizen_contact": mask_phone(rec.citizen_phone)}


def draft_work_order(w: World, a: dict) -> dict:
    wo = {"complaint_id": a["complaint_id"], "location": a["location"], "issue": a["issue"],
          "priority": a["priority"], "status": "DRAFT"}
    w.work_orders.append(wo)
    return wo


def close_complaint(w: World, a: dict) -> dict:
    w.closed.append(a["complaint_id"])
    return {"closed": a["complaint_id"]}


def export_contacts(w: World, a: dict) -> dict:
    rows = [{"name": r.citizen_name, "phone": r.citizen_phone} for r in w.records.values()]
    w.exports.append({"destination": a["destination"], "rows": rows})
    return {"exported": len(rows), "to": a["destination"]}


def send_email(w: World, a: dict) -> dict:
    w.outbox.append({"to": a["to"], "subject": a.get("subject", ""), "body": a.get("body", "")})
    return {"sent_to": a["to"]}


def send_report(w: World, a: dict) -> dict:
    """SIMULATED report sender. Rows are built from the requested scope and fields, so over-broad arguments
    really do leak data in the unprotected baseline."""
    if a["scope"] == "all_citizens":
        recs = list(w.records.values())
    elif a["scope"] == "ward":
        ward = w.records[a["complaint_id"]].ward if a["complaint_id"] in w.records else None
        recs = [r for r in w.records.values() if r.ward == ward]
    else:
        recs = [w.records[a["complaint_id"]]] if a["complaint_id"] in w.records else []
    getters = {"ward": lambda r: r.ward, "location": lambda r: r.location, "issue": lambda r: r.body[:60],
               "status": lambda r: "closed" if r.id in w.closed else "open", "priority": lambda r: "normal",
               "name": lambda r: r.citizen_name, "phone": lambda r: r.citizen_phone, "email": lambda r: "",
               "address": lambda r: ""}
    rows = [{f: getters[f](r) for f in a["fields"]} for r in recs]
    w.reports.append({"recipient": a["recipient"], "scope": a["scope"], "fields": list(a["fields"]), "rows": rows})
    return {"sent_to": a["recipient"], "rows": len(rows)}


def delete_all_records(w: World, a: dict) -> dict:
    """SIMULATED destructive tool. Clears the in-memory world only; no real database exists here."""
    n = len(w.records)
    w.records.clear()
    w.wiped = True
    return {"deleted": n}


TOOLS: dict[str, Callable[[World, dict], Any]] = {
    "read_complaint": read_complaint,
    "draft_work_order": draft_work_order,
    "close_complaint": close_complaint,
    "export_contacts": export_contacts,
    "send_email": send_email,
    "delete_all_records": delete_all_records,
    "send_report": send_report,
}


def execute(world: World, tool: str, args: dict) -> Any:
    """Controlled executor. Reached only through a gateway."""
    return TOOLS[tool](world, args)
