"""Secure tool gateway: the ONLY path from a proposed action to a side effect.

SecureGateway = policy check -> controlled executor -> audit.
DirectGateway = the unprotected baseline (executes whatever the agent proposes).
"""
from __future__ import annotations

import time
from collections import Counter

from .audit import AuditLog
from .policy import PolicyEngine
from .schemas import ContentItem, Decision, Outcome, ProposedAction, TaskContext
from .tools import World, execute


MAX_CONSECUTIVE_DENIALS = 5  # after this many hard denials in a row the run is halted


class SecureGateway:
    def __init__(self, world: World, audit: AuditLog, run_id: str, scenario_id: str = ""):
        self.__world = world  # name-mangled: the agent side holds no tool handle
        self.__policy = PolicyEngine(world.records)
        self._audit, self._run, self._scn = audit, run_id, scenario_id
        self._counts: Counter = Counter()
        self._streak = 0
        self._untrusted_text = ""  # everything untrusted this run ingested (for provenance checks)

    def ingest(self, task: TaskContext, items: list[ContentItem]) -> None:
        for it in items:
            if it.provenance.value == "untrusted_external":
                self._untrusted_text += "\n" + it.text
            self._audit.record(run_id=self._run, scenario_id=self._scn, mode="protected", task_id=task.task_id,
                               kind="INGEST", tool="-", args={"source": it.source, "chars": len(it.text)},
                               provenance=it.provenance.value, decision="-", rule="TAGGED_AS_DATA", origin=" <- ".join([it.origin or it.source, *it.lineage]),
                               reason="Content stored as data; carries no authority.", executed=0)

    def submit(self, task: TaskContext, action: ProposedAction, items: dict[str, ContentItem]) -> Outcome:
        t0 = time.perf_counter()
        if self._streak >= MAX_CONSECUTIVE_DENIALS:
            d = Decision(allow=False, rule="RUN_HALTED",
                         reason=f"Run halted after {MAX_CONSECUTIVE_DENIALS} consecutive denials; no further actions are evaluated.")
        else:
            d = self.__policy.evaluate(action, task, self._counts, self._untrusted_text)
            if d.allow or d.needs_approval:
                self._streak = 0
            else:
                self._streak += 1
        policy_ms = (time.perf_counter() - t0) * 1000
        executed, result, exec_args = False, None, None
        if d.allow:
            exec_args = d.sanitized_args or action.args
            result = execute(self.__world, action.tool, exec_args)
            self._counts[action.tool] += 1
            executed = True
        label = "ALLOW" if d.allow else ("PENDING_APPROVAL" if d.needs_approval else "DENY")
        prov = sorted({items[i].provenance.value for i in action.derived_from if i in items})
        self._audit.record(run_id=self._run, scenario_id=self._scn, mode="protected", task_id=task.task_id,
                           kind="PROPOSAL", tool=action.tool, args=action.args, provenance=",".join(prov),
                           derived_from=action.derived_from, decision=label, rule=d.rule, reason=d.reason,
                           executed=int(executed), result=result, policy_ms=policy_ms,
                           origin="; ".join(sorted({items[i].origin or items[i].source for i in action.derived_from if i in items})),
                           exec_args=exec_args,
                           execution_outcome=("PENDING" if d.needs_approval else "BLOCKED" if not d.allow else
                                              "EXECUTED_MODIFIED" if d.rule == "ALLOWED_GROUNDED" else "EXECUTED"))
        return Outcome(action=action, decision=d, executed=executed, exec_args=exec_args, result=result,
                       policy_ms=policy_ms, mode="protected")


class DirectGateway:
    """Baseline: no policy, no audit. Models an agent wired straight to its tools."""

    def __init__(self, world: World):
        self.__world = world

    def ingest(self, task, items) -> None:
        pass

    def submit(self, task: TaskContext, action: ProposedAction, items) -> Outcome:
        try:
            result = execute(self.__world, action.tool, action.args)
            return Outcome(action=action, decision=None, executed=True, exec_args=action.args,
                           result=result, mode="baseline")
        except Exception as e:  # malformed args etc.
            return Outcome(action=action, decision=None, executed=False, result={"error": str(e)}, mode="baseline")
