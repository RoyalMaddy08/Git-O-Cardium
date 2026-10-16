"""Conformance suite: the written test matrix (docs spec) as executable cases.

Each case drives the real SecureGateway with hand-written proposals (no mock agent), then compares
ACTUAL vs EXPECTED for: decision, reason code, world side effects, and audit rows.
Expectations are written here, independent of policy.py. Statuses:
  PASS / FAIL            expected vs actual
  KNOWN_FAIL             documented gap that still fails as predicted (not a pass)
  UNEXPECTED_PASS        documented gap that now passes -> update the docs
  NOT_RUNNABLE           control not implemented yet; nothing is claimed
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditLog
from .gateway import SecureGateway
from .scenarios import RECORDS, make_task
from .schemas import ContentItem, ProposedAction
from .tools import INTERNAL_DOMAIN, World

LABELS = {"PENDING_APPROVAL": "APPROVAL_REQUIRED"}  # code label -> spec label (open question with Person 1)
OK = INTERNAL_DOMAIN


@dataclass
class Act:
    tool: str
    args: dict
    decision: str          # expected: ALLOW | DENY | APPROVAL_REQUIRED
    rule: str | tuple = ()  # expected reason code(s); empty = not checked


@dataclass
class Case:
    id: str
    lens: str
    kind: str              # legit | malicious | check
    title: str
    acts: list[Act] = field(default_factory=list)
    profile: str = "basic"
    target: str = "C-101"
    # expected side effects after the run
    work_orders: int = 0
    closed: int = 0
    exports: int = 0
    outbox: int = 0
    reports: int = 0
    content: str = "Body: synthetic"  # untrusted text ingested before the proposals
    custom: str | None = None       # name of a custom check function
    not_runnable: str | None = None  # reason, if the control is not implemented
    known_gap: str | None = None     # documented gap expected to FAIL today


LENS_ORDER = ["headline", "social", "political", "historical", "international", "legal", "environmental",
              "regional", "technological"]
CASES_DIR = Path(__file__).resolve().parent.parent / "cases"
DECISIONS = ("ALLOW", "DENY", "APPROVAL_REQUIRED")
_CASE_KEYS = {"id", "lens", "kind", "title", "profile", "target", "acts", "expect", "custom", "not_runnable", "known_gap", "content"}
_EXPECT_KEYS = {"work_orders", "closed", "exports", "outbox", "reports"}


def validate_case_dict(d: dict) -> list[str]:
    """Structural checks for one case (used by the loader and by the UI editor)."""
    errs: list[str] = []
    if not isinstance(d, dict):
        return ["case must be a JSON object"]
    for k in ("id", "lens", "kind", "title"):
        if not isinstance(d.get(k), str) or not d.get(k):
            errs.append(f"'{k}' is required (text)")
    errs += [f"unknown key '{k}'" for k in d if k not in _CASE_KEYS]
    if d.get("kind") not in ("legit", "malicious", "check"):
        errs.append("kind must be legit, malicious or check")
    if d.get("profile", "basic") not in ("basic", "notify", "closure_needs_approval", "reporting", "report_needs_approval"):
        errs.append("profile must be basic, notify, closure_needs_approval, reporting or report_needs_approval")
    if d.get("target", "C-101") not in RECORDS:
        errs.append(f"target must be one of {sorted(RECORDS)}")
    exp = d.get("expect", {})
    if not isinstance(exp, dict) or set(exp) - _EXPECT_KEYS or any(not isinstance(v, int) or v < 0 for v in exp.values()):
        errs.append(f"expect must map {sorted(_EXPECT_KEYS)} to whole numbers >= 0")
    acts = d.get("acts", [])
    if not isinstance(acts, list):
        errs.append("acts must be a list")
        acts = []
    for i, a in enumerate(acts):
        if not isinstance(a, dict) or not isinstance(a.get("tool"), str) or not isinstance(a.get("args"), dict):
            errs.append(f"acts[{i}] needs 'tool' (text) and 'args' (object)")
            continue
        if a.get("decision") not in DECISIONS:
            errs.append(f"acts[{i}].decision must be one of {DECISIONS}")
        if not isinstance(a.get("rule", ""), (str, list)):
            errs.append(f"acts[{i}].rule must be text or a list of text")
        errs += [f"acts[{i}] unknown key '{k}'" for k in a if k not in ("tool", "args", "decision", "rule")]
    if not acts and not d.get("not_runnable") and not d.get("custom"):
        errs.append("a case needs acts, or a 'custom' check, or a 'not_runnable' reason")
    return errs


def case_from_dict(d: dict) -> Case:
    errs = validate_case_dict(d)
    if errs:
        raise ValueError(f"case {d.get('id', '?')}: " + "; ".join(errs))
    return Case(
        id=d["id"], lens=d["lens"], kind=d["kind"], title=d["title"], profile=d.get("profile", "basic"),
        target=d.get("target", "C-101"),
        acts=[Act(a["tool"], a["args"], a["decision"], tuple(a["rule"]) if isinstance(a.get("rule"), list) else a.get("rule", ""))
              for a in d.get("acts", [])],
        custom=d.get("custom"), not_runnable=d.get("not_runnable"), known_gap=d.get("known_gap"),
        content=d.get("content", "Body: synthetic"),
        **{k: d.get("expect", {}).get(k, 0) for k in _EXPECT_KEYS})


def load_case_dicts(cases_dir: Path | None = None) -> dict[str, list[dict]]:
    """Raw case dicts keyed by file stem, in lens order."""
    d = cases_dir or CASES_DIR
    stems = [s for s in LENS_ORDER if (d / f"{s}.json").exists()]
    stems += sorted(p.stem for p in d.glob("*.json") if p.stem not in LENS_ORDER)
    return {s: json.loads((d / f"{s}.json").read_text()) for s in stems}


def load_cases(cases_dir: Path | None = None) -> list[Case]:
    cases = [case_from_dict(d) for ds in load_case_dicts(cases_dir).values() for d in ds]
    ids = [c.id for c in cases]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise ValueError(f"duplicate case ids: {dup}")
    return cases


CASES: list[Case] = load_cases()


# ---------------------------------------------------------------- running
@dataclass
class CaseResult:
    case: Case
    status: str
    notes: list[str]
    actual: list[dict] = field(default_factory=list)  # per action: tool, decision, rule, executed
    effects: dict = field(default_factory=dict)        # actual side effects


def _run(case: Case):
    world = World({k: v.model_copy() for k, v in RECORDS.items()})
    audit = AuditLog()
    run_id = f"{case.id}-{uuid.uuid4().hex[:6]}"
    gw = SecureGateway(world, audit, run_id, case.id)
    task = make_task(case.profile, case.target)
    item = ContentItem(id=f"complaint:{case.target}", source="synthetic", text=case.content)
    gw.ingest(task, [item])
    outs = [gw.submit(task, ProposedAction(tool=a.tool, args=a.args, derived_from=[item.id]), {item.id: item})
            for a in case.acts]
    return world, audit, run_id, gw, outs


def _check(case: Case):
    """returns (failures, notes, actual per action, actual side effects)"""
    fails: list[str] = []
    if case.custom == "no_public_handle":
        gw = _run(Case("x", "", "", ""))[3]
        for name in ("world", "policy", "_world", "_policy", "tools", "execute"):
            if hasattr(gw, name):
                fails.append(f"gateway exposes public attribute '{name}'")
        return fails, ["Only checks public names. The private (name-mangled) world is still reachable by code "
                       "that knows the mangled name: this is NOT a sandbox."], [], {}
    if case.custom == "no_audit_tool":
        from .tools import TOOLS
        bad = [t for t in TOOLS if "audit" in t or "log" in t]
        return ([f"tool can touch audit: {bad}"] if bad else []), ["Checks the tool registry only; "
                "direct DB access by operators/other code is out of scope."], [], {}
    world, audit, run_id, gw, outs = _run(case)
    rows = audit.rows(run_id)
    props = [r for r in rows if r["kind"] == "PROPOSAL"]
    for i, (a, o) in enumerate(zip(case.acts, outs)):
        label = "ALLOW" if o.decision.allow else ("APPROVAL_REQUIRED" if o.decision.needs_approval else "DENY")
        if label != a.decision:
            fails.append(f"action {i} {a.tool}: decision {label}, expected {a.decision}")
        accepted = (a.rule,) if isinstance(a.rule, str) else a.rule
        if accepted and o.decision.rule not in accepted:
            fails.append(f"action {i} {a.tool}: rule {o.decision.rule}, expected {'|'.join(accepted)}")
        if props[i]["executed"] != int(o.executed):
            fails.append(f"action {i}: audit executed flag disagrees with real execution")
        if label != "ALLOW" and o.executed:
            fails.append(f"action {i}: denied action was executed")
    if len(props) != len(case.acts):
        fails.append(f"audit has {len(props)} PROPOSAL rows, expected {len(case.acts)}")
    for r in props:
        if LABELS.get(r["decision"], r["decision"]) not in ("ALLOW", "DENY", "APPROVAL_REQUIRED") or not r["rule"] or not r["reason"]:
            fails.append(f"audit row {r['id']} missing decision/rule/reason")
    for name, got in (("work_orders", len(world.work_orders)), ("closed", len(world.closed)),
                      ("exports", len(world.exports)), ("outbox", len(world.outbox)),
                      ("reports", len(world.reports))):
        if got != getattr(case, name):
            fails.append(f"side effect {name}: {got}, expected {getattr(case, name)}")
    if case.custom == "phone_masked":
        res = json.dumps(outs[0].result)
        if RECORDS[case.target].citizen_phone in res:
            fails.append("raw phone in tool result")
    if case.custom == "no_raw_phone_in_audit":
        dump = json.dumps(rows, default=str)
        for r in RECORDS.values():
            if r.citizen_phone in dump:
                fails.append(f"raw phone {r.citizen_phone[:3]}... found in audit rows")
    if case.custom == "execution_outcome":
        for r, o in zip(props, outs):
            want = "BLOCKED" if not o.decision.allow and not o.decision.needs_approval else \
                   "PENDING" if o.decision.needs_approval else "EXECUTED"
            if not str(r["execution_outcome"]).startswith(want):
                fails.append(f"audit row {r['id']}: execution_outcome {r['execution_outcome']}, expected {want}")
            if o.executed and not r["exec_args"]:
                fails.append(f"audit row {r['id']}: exec_args missing")
    if case.custom == "records_intact":
        if world.wiped or len(world.records) != len(RECORDS):
            fails.append("records were deleted")
    if case.custom == "location_grounded":
        if world.work_orders and world.work_orders[0]["location"] != RECORDS[case.target].location:
            fails.append("work order kept attacker location")
    actual = [{"tool": a.tool, "decision": ("ALLOW" if o.decision.allow else
                                           "APPROVAL_REQUIRED" if o.decision.needs_approval else "DENY"),
               "rule": o.decision.rule, "executed": o.executed} for a, o in zip(case.acts, outs)]
    effects = {"work_orders": len(world.work_orders), "closed": len(world.closed),
               "exports": len(world.exports), "outbox": len(world.outbox), "reports": len(world.reports)}
    return fails, [], actual, effects


def run_case(case: Case) -> CaseResult:
    if case.not_runnable:
        return CaseResult(case, "NOT_RUNNABLE", [case.not_runnable])
    fails, notes, actual, effects = _check(case)
    if case.known_gap:
        return CaseResult(case, "KNOWN_FAIL" if fails else "UNEXPECTED_PASS", [case.known_gap] + fails, actual, effects)
    return CaseResult(case, "FAIL" if fails else "PASS", fails + notes, actual, effects)


def run_all(cases: list[Case] | None = None) -> list[CaseResult]:
    """Runs the cases from disk (fresh load) unless a list is given."""
    return [run_case(c) for c in (cases if cases is not None else load_cases())]


def to_markdown(results: list[CaseResult]) -> str:
    from collections import Counter
    c = Counter(r.status for r in results)
    out = ["# SPHILTER-AI conformance results", "",
           "Summary: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())), "",
           "Real run of the written test matrix against the real gateway (hand-written proposals, "
           "not the mock agent). PASS means expected == actual for decision, reason, side effects and audit. "
           "NOT_RUNNABLE means the control does not exist yet: nothing is claimed.", "",
           "| ID | Lens | Case | Status | Notes |", "|---|---|---|---|---|"]
    for r in results:
        out.append(f"| {r.case.id} | {r.case.lens} | {r.case.title} | {r.status} | {'; '.join(r.notes) or '-'} |")
    return "\n".join(out) + "\n"


def main() -> None:
    res = run_all()
    md = to_markdown(res)
    d = Path(__file__).resolve().parent.parent / "results"
    d.mkdir(exist_ok=True)
    (d / "conformance.md").write_text(md)
    print(md)


if __name__ == "__main__":
    main()
