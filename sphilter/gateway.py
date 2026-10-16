
"""Secure tool gateway: the ONLY path from a proposed action to a side effect.

SecureGateway = policy check -> controlled executor -> audit.
DirectGateway = the unprotected baseline (executes whatever the agent proposes).
"""
from __future__ import annotations

import time
from collections import Counter

from .audit import AuditLog
from .policy import PolicyEngine
from .schemas import ContentItem, Outcome, ProposedAction, TaskContext
from .tools import World, execute



class SecureGateway:
    """Policy enforcement, bounded proposals, controlled execution, and audit."""

    def __init__(
        self,
        world: World,
        audit: AuditLog,
        run_id: str,
        scenario_id: str = "",
        max_proposals: int = 20,
    ):
        if max_proposals < 1:
            raise ValueError("max_proposals must be at least 1")

        self.__world = world
        self.__policy = PolicyEngine(world.records)
        self._audit, self._run, self._scn = audit, run_id, scenario_id
        self._counts: Counter = Counter()
        self._proposal_counts: Counter = Counter()
        self._max_proposals = max_proposals

    def ingest(self, task: TaskContext, items: list[ContentItem]) -> None:
        for it in items:
            self._audit.record(
                run_id=self._run,
                scenario_id=self._scn,
                mode="protected",
                task_id=task.task_id,
                kind="INGEST",
                tool="-",
                args={"source": it.source, "chars": len(it.text)},
                provenance=it.provenance.value,
                decision="-",
                rule="TAGGED_AS_DATA",
                reason="Content stored as data; carries no authority.",
                executed=0,
            )

    def submit(
        self,
        task: TaskContext,
        action: ProposedAction,
        items: dict[str, ContentItem],
    ) -> Outcome:
        # Count every proposal, including denied proposals and failed executions.
        self._proposal_counts[task.task_id] += 1
        proposal_number = self._proposal_counts[task.task_id]

        t0 = time.perf_counter()

        if proposal_number > self._max_proposals:
            from .schemas import Decision

            decision = Decision(
                allow=False,
                rule="PROPOSAL_LIMIT",
                reason=(
                    f"Task '{task.task_id}' exceeded the proposal limit "
                    f"of {self._max_proposals}."
                ),
            )
        else:
            decision = self.__policy.evaluate(action, task, self._counts)

        policy_ms = (time.perf_counter() - t0) * 1000
        executed = False
        execution_failed = False
        result = None
        exec_args = None
        error_message = None
        error_type = None

        if decision.allow:
            exec_args = decision.sanitized_args or action.args

            # Count execution attempts, including exceptions.
            self._counts[action.tool] += 1

            try:
                result = execute(self.__world, action.tool, exec_args)
                executed = True
            except Exception as exc:
                execution_failed = True
                error_type = type(exc).__name__
                error_message = str(exc)
                result = {"error": error_message, "type": error_type}

        if execution_failed:
            label = "EXECUTION_FAILED"
            audit_rule = "EXECUTION_ERROR"
            audit_reason = (
                f"Policy allowed the action ({decision.rule}), "
                f"but execution raised {error_type}: {error_message}"
            )
        else:
            label = (
                "ALLOW"
                if decision.allow
                else (
                    "PENDING_APPROVAL"
                    if decision.needs_approval
                    else "DENY"
                )
            )
            audit_rule = decision.rule
            audit_reason = decision.reason

        provenance = sorted(
            {
                items[item_id].provenance.value
                for item_id in action.derived_from
                if item_id in items
            }
        )

        self._audit.record(
            run_id=self._run,
            scenario_id=self._scn,
            mode="protected",
            task_id=task.task_id,
            kind="PROPOSAL",
            tool=action.tool,
            args=action.args,
            provenance=",".join(provenance),
            derived_from=action.derived_from,
            decision=label,
            rule=audit_rule,
            reason=audit_reason,
            executed=int(executed),
            result=result,
            policy_ms=policy_ms,
        )

        return Outcome(
            action=action,
            decision=decision,
            executed=executed,
            exec_args=exec_args,
            result=result,
            policy_ms=policy_ms,
            mode="protected",
        )


class DirectGateway:
    """Baseline: no policy, no audit. Models an agent wired straight to its tools."""

    def __init__(self, world: World):
        self.__world = world

    def ingest(self, task, items) -> None:
        pass

    def submit(
        self,
        task: TaskContext,
        action: ProposedAction,
        items,
    ) -> Outcome:
        try:
            result = execute(self.__world, action.tool, action.args)
            return Outcome(
                action=action,
                decision=None,
                executed=True,
                exec_args=action.args,
                result=result,
                mode="baseline",
            )
        except Exception as exc:
            return Outcome(
                action=action,
                decision=None,
                executed=False,
                result={"error": str(exc)},
                mode="baseline",
            )
