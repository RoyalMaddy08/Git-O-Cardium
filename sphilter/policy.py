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


ARG_MODELS: dict[str, type[BaseModel]] = {
    "read_complaint": ReadArgs,
    "draft_work_order": DraftArgs,
    "close_complaint": CloseArgs,
    "export_contacts": ExportArgs,
    "send_email": EmailArgs,
}

RISK = {"read_complaint": "low", "draft_work_order": "medium", "send_email": "high",
        "close_complaint": "high", "export_contacts": "critical"}


def _deny(rule: str, reason: str, approval: bool = False) -> Decision:
    return Decision(allow=False, rule=rule, reason=reason, needs_approval=approval)


class PolicyEngine:
    def __init__(self, records: Mapping[str, Complaint]):
        self._records = records  # trusted record store, used for argument grounding

    def evaluate(self, action: ProposedAction, task: TaskContext, counts: Counter) -> Decision:
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
        # 5. destination restrictions (email / export)
        dest = args.get("to") if tool == "send_email" else args.get("destination")
        if tool in ("send_email", "export_contacts"):
            m = EMAIL_RE.match(dest or "")
            domain = m.group(1).lower() if m else None
            allowed = [d.lower() for d in (perm.destinations or [])]
            if domain is None or domain not in allowed:
                return _deny("DESTINATION_NOT_ALLOWED",
                             f"Destination '{dest}' is not in the allowed domains {allowed or 'none'}.")
        # 6. budget (also stops repeated-instruction loops)
        if counts[tool] >= perm.max_calls:
            return _deny("RATE_LIMIT", f"'{tool}' already used {counts[tool]}/{perm.max_calls} time(s) in this task.")
        # 7. human approval for high-risk actions
        if perm.requires_approval:
            return _deny("APPROVAL_REQUIRED",
                         f"'{tool}' needs human approval; queued, not executed.", approval=True)
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
