"""Deterministic policy engine. Pure code, no LLM, no prompt text.

Authority comes ONLY from the trusted TaskContext. Content the agent read (emails,
complaints, PDFs) can influence what the agent *proposes*, never what is *allowed*.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Literal, Mapping

from pydantic import BaseModel, ValidationError

from .schemas import Complaint, Decision, ProposedAction, TaskContext

EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$")


class ReadArgs(BaseModel):
    complaint_id: str


class DraftArgs(BaseModel):
    complaint_id: str
    location: str
    issue: str
    priority: Literal["low", "normal", "high"]


class CloseArgs(BaseModel):
    complaint_id: str
    resolution: str = ""


class ExportArgs(BaseModel):
    destination: str


class EmailArgs(BaseModel):
    to: str
    subject: str = ""
    body: str = ""


SAFE_FIELDS = ["ward", "location", "issue", "status", "priority"]
PII_FIELDS = ["name", "phone", "email", "address"]


class ReportArgs(BaseModel):
    complaint_id: str
    recipient: str
    scope: Literal["complaint", "ward", "all_citizens"]
    fields: list[Literal["ward", "location", "issue", "status", "priority", "name", "phone", "email", "address"]]


class NoArgs(BaseModel):
    model_config = {"extra": "forbid"}


ARG_MODELS: dict[str, type[BaseModel]] = {
    "read_complaint": ReadArgs,
    "draft_work_order": DraftArgs,
    "close_complaint": CloseArgs,
    "export_contacts": ExportArgs,
    "send_email": EmailArgs,
    "delete_all_records": NoArgs,
    "send_report": ReportArgs,
}

RISK = {"read_complaint": "low", "draft_work_order": "medium", "send_email": "high",
        "close_complaint": "high", "export_contacts": "critical", "delete_all_records": "critical",
        "send_report": "high"}


def _deny(rule: str, reason: str, approval: bool = False) -> Decision:
    return Decision(allow=False, rule=rule, reason=reason, needs_approval=approval)


class PolicyEngine:
    def __init__(self, records: Mapping[str, Complaint]):
        self._records = records  # trusted record store, used for argument grounding

    def evaluate(self, action: ProposedAction, task: TaskContext, counts: Counter,
                 untrusted_text: str = "") -> Decision:
        tool = action.tool
        # 1. known tool?
        if tool not in ARG_MODELS:
            return _deny("UNKNOWN_TOOL", f"'{tool}' is not a registered tool.")
        # 2. does the trusted task grant this tool at all?
        perm = task.permissions.get(tool)
        if perm is None:
            granted = ", ".join(sorted(task.permissions)) or "none"
            return _deny("TOOL_NOT_PERMITTED",
                         f"Task '{task.task_id}' does not authorize '{tool}' (risk: {RISK[tool]}). "
                         f"Granted tools: {granted}.")
        # 3. typed argument validation
        try:
            args = ARG_MODELS[tool](**action.args).model_dump()
        except ValidationError as e:
            return _deny("ARG_INVALID", f"Arguments failed validation: {e.errors()[0]['msg']}.")
        # 4. resource scope
        rid = args.get("complaint_id")
        if rid is not None and perm.resources is not None and rid not in perm.resources:
            return _deny("RESOURCE_OUT_OF_SCOPE",
                         f"'{tool}' on {rid} is outside the task scope {perm.resources}.")
        # 4b. field-level limits granted by the trusted task (stops in-field tampering such as priority downgrades)
        if tool == "draft_work_order" and perm.allowed_priorities is not None \
                and args["priority"] not in perm.allowed_priorities:
            return _deny("PRIORITY_NOT_ALLOWED",
                         f"Priority '{args['priority']}' is not granted by the task (allowed: {perm.allowed_priorities}).")
        # 5. destination restrictions (email / export)
        dest = {"send_email": args.get("to"), "export_contacts": args.get("destination"),
                "send_report": args.get("recipient")}.get(tool)
        if tool in ("send_email", "export_contacts", "send_report"):
            m = EMAIL_RE.match(dest or "")
            domain = m.group(1).lower() if m else None
            allowed = [d.lower() for d in (perm.destinations or [])]
            if domain is None or domain not in allowed:
                return _deny("DESTINATION_NOT_ALLOWED",
                             f"Destination '{dest}' is not in the allowed domains {allowed or 'none'}.")
        # 5b. send_report: data scope and data sensitivity are checked against what the TRUSTED task grants
        if tool == "send_report":
            scopes = perm.allowed_scopes or ["complaint"]
            if args["scope"] not in scopes:
                return _deny("SCOPE_NOT_ALLOWED", f"Report scope '{args['scope']}' is not granted (allowed: {scopes}).")
            fields = perm.allowed_fields or SAFE_FIELDS
            bad = [f for f in args["fields"] if f not in fields]
            if bad:
                return _deny("SENSITIVE_FIELDS_NOT_ALLOWED" if set(bad) & set(PII_FIELDS) else "FIELD_NOT_ALLOWED",
                             f"Fields {bad} are not granted to this task (allowed: {fields}).")
        # 6. budget (also stops repeated-instruction loops)
        if counts[tool] >= perm.max_calls:
            return _deny("RATE_LIMIT", f"'{tool}' already used {counts[tool]}/{perm.max_calls} time(s) in this task.")
        # 7. human approval for high-risk actions
        if perm.requires_approval:
            return _deny("APPROVAL_REQUIRED",
                         f"'{tool}' needs human approval; queued, not executed.", approval=True)
        # 7b. provenance: a destination that the untrusted content itself names is not trusted to choose recipients
        if (tool in ("send_email", "export_contacts", "send_report") and dest and dest.lower() not in
                [a.lower() for a in (perm.trusted_recipients or [])] and dest.lower() in (untrusted_text or "").lower()):
            return _deny("ARG_TAINTED",
                         f"Destination '{dest}' appears in untrusted content, so a person must confirm it; queued, not executed.",
                         approval=True)
        # 8. grounding: authority-bearing fields come from the trusted record, not free text
        sanitized = None
        if tool == "draft_work_order":
            rec = self._records.get(args["complaint_id"])
            if rec is not None and args["location"] != rec.location:
                sanitized = {**args, "location": rec.location}
        if sanitized is not None:
            return Decision(allow=True, rule="ALLOWED_GROUNDED",
                            reason="Allowed; 'location' replaced with the value from the trusted record.",
                            sanitized_args=sanitized)
        return Decision(allow=True, rule="ALLOWED", reason=f"'{tool}' is within the task's granted permissions.",
                        sanitized_args=args)
