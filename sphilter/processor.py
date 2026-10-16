"""Processes one citizen submission through the real SecureGateway.

The submission text is untrusted data. The agent (a stand-in that obeys hidden text) only PROPOSES;
the gateway decides. Tool side effects land in a throwaway simulated World, never in a real system.
"""
from __future__ import annotations

import json

from .agents import Agent, GullibleMockAgent
from .audit import AuditLog
from .gateway import SecureGateway
from .scenarios import make_task
from .schemas import Complaint, ContentItem
from .tools import World, mask_phone


def process_submission(sub: dict, audit: AuditLog, agent: Agent | None = None) -> dict:
    agent = agent or GullibleMockAgent()
    rec = Complaint(id=sub["id"], ward=sub["ward"], location=sub["location"], body=sub["body"],
                    citizen_name=sub["name"], citizen_phone="".join(ch for ch in sub["phone"] if ch.isdigit())[-10:])
    world = World({rec.id: rec})
    task = make_task("basic", rec.id)
    text = f"Complaint {rec.id}\nWard: {rec.ward}\nLocation: {rec.location}\nBody: {rec.body}"
    item = ContentItem(id=f"complaint:{rec.id}", source=f"portal_submission:{rec.id}", text=text)
    gw = SecureGateway(world, audit, f"portal-{rec.id}", "portal")
    gw.ingest(task, [item])
    outs = [gw.submit(task, a, {item.id: item}) for a in agent.propose(task, [item])]
    actions = [{"tool": o.action.tool,
                "decision": "ALLOW" if o.decision.allow else ("APPROVAL_REQUIRED" if o.decision.needs_approval else "DENY"),
                "rule": o.decision.rule, "reason": o.decision.reason, "executed": o.executed} for o in outs]
    blocked = [a for a in actions if a["decision"] != "ALLOW"]
    return {"run_id": f"portal-{rec.id}", "agent": getattr(agent, "name", "agent"), "actions": actions,
            "blocked": len(blocked), "work_order": world.work_orders[0] if world.work_orders else None,
            "unauthorized_effects": {"closed": world.closed, "exports": len(world.exports),
                                     "emails": len(world.outbox)}, "phone_shown_as": mask_phone(rec.citizen_phone)}


def to_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False)
