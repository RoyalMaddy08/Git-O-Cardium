
"""Deterministic policy engine. Pure code, no LLM, no prompt text.

Authority comes ONLY from the trusted TaskContext. Content the agent read (emails,
complaints, PDFs) can influence what the agent proposes, never what is allowed.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Literal, Mapping

from pydantic import BaseModel, ConfigDict, ValidationError

from .schemas import Complaint, Decision, ProposedAction, TaskContext


EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$")


# Reject unexpected fields instead of silently ignoring them.
class ReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    complaint_id: str


class DraftArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    complaint_id: str
    location: str
    issue: str
    priority: Literal["low", "normal", "high"]


class CloseArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    complaint_id: str
    resolution: str = ""


class ExportArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    destination: str


class EmailArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
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

RISK = {
    "read_complaint": "low",
    "draft_work_order": "medium",
    "send_email": "high",
    "close_complaint": "high",
    "export_contacts": "critical",
}

COMPLAINT_TOOLS = {
    "read_complaint",
    "draft_work_order",
    "close_complaint",
}


def _deny(rule: str, reason: str, approval: bool = False) -> Decision:
    return Decision(
        allow=False,
        rule=rule,
        reason=reason,
        needs_approval=approval,
    )


class PolicyEngine:
    def __init__(self, records: Mapping[str, Complaint]):
        # Trusted complaint record store.
        self._records = records

    def evaluate(
        self,
        action: ProposedAction,
        task: TaskContext,
        counts: Counter,
    ) -> Decision:
        tool = action.tool

        # 1. Reject unknown tools.
        if tool not in ARG_MODELS:
            return _deny(
                "UNKNOWN_TOOL",
                f"'{tool}' is not a registered tool.",
            )

        # 2. Check trusted task permissions.
        perm = task.permissions.get(tool)
        if perm is None:
            granted = ", ".join(sorted(task.permissions)) or "none"
            return _deny(
                "TOOL_NOT_PERMITTED",
                f"Task '{task.task_id}' does not authorize '{tool}' "
                f"(risk: {RISK[tool]}). Granted tools: {granted}.",
            )

        # 3. Validate argument types and reject extra fields.
        try:
            args = ARG_MODELS[tool](**action.args).model_dump()
        except (ValidationError, TypeError) as e:
            if isinstance(e, ValidationError):
                detail = e.errors()[0]["msg"]
            else:
                detail = str(e)

            return _deny(
                "ARG_INVALID",
                f"Arguments failed validation: {detail}.",
            )

        # 4. Enforce complaint resource scope.
        rid = args.get("complaint_id")

        if (
            rid is not None
            and perm.resources is not None
            and rid not in perm.resources
        ):
            return _deny(
                "RESOURCE_OUT_OF_SCOPE",
                f"'{tool}' on {rid} is outside the task scope "
                f"{perm.resources}.",
            )

        # 5. Complaint actions must reference an existing trusted record.
        if tool in COMPLAINT_TOOLS and rid not in self._records:
            return _deny(
                "COMPLAINT_NOT_FOUND",
                f"Complaint '{rid}' does not exist in the trusted record store.",
            )

        # 6. Validate email/export destinations against allowed domains.
        if tool == "send_email":
            dest = args.get("to", "")
        elif tool == "export_contacts":
            dest = args.get("destination", "")
        else:
            dest = None

        if tool in ("send_email", "export_contacts"):
            match = EMAIL_RE.fullmatch(dest or "")
            domain = match.group(1).lower() if match else None
            allowed = [
                d.lower()
                for d in (perm.destinations or [])
            ]

            if domain is None or domain not in allowed:
                return _deny(
                    "DESTINATION_NOT_ALLOWED",
                    f"Destination '{dest}' is not in the allowed "
                    f"domains {allowed or 'none'}.",
                )

        # 7. Enforce the configured tool-call budget.
        if counts[tool] >= perm.max_calls:
            return _deny(
                "RATE_LIMIT",
                f"'{tool}' already used {counts[tool]}/"
                f"{perm.max_calls} time(s) in this task.",
            )

        # 8. Require approval for actions that need human authorization.
        # A pending action is NOT allowed to execute.
        if perm.requires_approval:
            return _deny(
                "APPROVAL_REQUIRED",
                f"'{tool}' needs human approval; queued, not executed.",
                approval=True,
            )

        # 9. Ground authority-bearing location data in trusted records.
        sanitized = None

        if tool == "draft_work_order":
            rec = self._records[rid]

            if args["location"] != rec.location:
                sanitized = {
                    **args,
                    "location": rec.location,
                }

        if sanitized is not None:
            return Decision(
                allow=True,
                rule="ALLOWED_GROUNDED",
                reason=(
                    "Allowed; 'location' replaced with the value "
                    "from the trusted record."
                ),
                sanitized_args=sanitized,
            )

        return Decision(
            allow=True,
            rule="ALLOWED",
            reason=f"'{tool}' is within the task's granted permissions.",
            sanitized_args=args,
        )
