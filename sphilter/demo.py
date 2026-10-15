"""Terminal demo:  python -m sphilter.demo [SCENARIO_ID]   (default A1, the headline attack)"""
from __future__ import annotations

import sys

from .evaluate import run_scenario
from .scenarios import BY_ID, RECORDS


def effects(r) -> list[str]:
    w = r.world
    out = [f"work order drafted: {x['location']} / {x['priority']}" for x in w.work_orders]
    out += [f"COMPLAINT CLOSED: {c}" for c in w.closed]
    out += [f"CONTACTS EXPORTED to {e['destination']} ({len(e['rows'])} citizens)" for e in w.exports]
    out += [f"email sent to {m['to']}" for m in w.outbox]
    out += [f"read {c}" for c in w.access_log if c != r.scenario.target]
    return out or ["(no side effects)"]


def show(sid: str) -> None:
    scn = BY_ID[sid]
    print(f"=== {scn.id}: {scn.title}  [{scn.category}]  profile={scn.profile}\n")
    for it in scn.items():
        print(f"[{it.provenance.value}] {it.source}\n  {it.text.splitlines()[-1][:300]}\n")
    base, prot = run_scenario(scn, "baseline"), run_scenario(scn, "protected")
    print("--- BASELINE agent (wired straight to tools)")
    for e in effects(base):
        print("  *", e)
    print("\n--- PROTECTED agent (SPHILTER-AI gateway)")
    for o in prot.outcomes:
        d = o.decision
        mark = "EXECUTED" if o.executed else "BLOCKED "
        print(f"  {mark} {o.action.tool:<17} {d.rule:<24} {d.reason}")
    print("  side effects:")
    for e in effects(prot):
        print("  *", e)
    print(f"\nviolations  baseline={base.violations or 'none'}\n            protected={prot.violations or 'none'}")
    print(f"audit rows logged: {len(prot.audit.rows(prot.run_id))}")


if __name__ == "__main__":
    show(sys.argv[1] if len(sys.argv) > 1 else "A1")
