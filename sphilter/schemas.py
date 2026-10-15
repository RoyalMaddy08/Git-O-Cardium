"""Typed contracts between the (untrusted) model side and the (trusted) enforcement side."""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Provenance(str, Enum):
    TRUSTED_USER = "trusted_user"
    UNTRUSTED_EXTERNAL = "untrusted_external"


class ContentItem(BaseModel):
    """Anything the agent reads. Content is DATA: it never carries authority."""

    model_config = ConfigDict(frozen=True)
    id: str
    source: str
    text: str
    provenance: Provenance = Provenance.UNTRUSTED_EXTERNAL


class Complaint(BaseModel):
    """Synthetic complaint record (trusted store). No real citizen data anywhere."""

    id: str
    ward: str
    location: str
    body: str
    citizen_name: str
    citizen_phone: str


class ToolPermission(BaseModel):
    """What the TRUSTED task owner grants for one tool."""

    resources: list[str] | None = None  # allowed complaint ids; None = any
    destinations: list[str] | None = None  # allowed email domains; None/[] = none
    max_calls: int = 1
    requires_approval: bool = False


class TaskContext(BaseModel):
    """Created by trusted code from the officer's request, never from agent output."""

    task_id: str
    objective: str
    complaint_id: str
    profile: str
    permissions: dict[str, ToolPermission]


class ProposedAction(BaseModel):
    """The ONLY thing a model can produce. A proposal is not an execution."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    # Advisory only: the agent's own claim about which content it relied on.
    # Never used to ALLOW anything; used for audit explanations.
    derived_from: list[str] = Field(default_factory=list)


class Decision(BaseModel):
    allow: bool
    rule: str
    reason: str
    needs_approval: bool = False
    sanitized_args: dict[str, Any] | None = None


class Outcome(BaseModel):
    action: ProposedAction
    decision: Decision | None  # None for the unprotected baseline
    executed: bool
    exec_args: dict[str, Any] | None = None
    result: Any = None
    policy_ms: float = 0.0
    mode: Literal["protected", "baseline"] = "protected"
