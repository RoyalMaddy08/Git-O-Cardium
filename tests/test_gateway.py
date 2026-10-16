from sphilter.audit import AuditLog
from sphilter.evaluate import fresh_world
from sphilter.gateway import DirectGateway, SecureGateway
from sphilter.scenarios import BY_ID, make_task
from sphilter.schemas import ProposedAction


def setup(profile="basic"):
    w = fresh_world()
    return w, SecureGateway(w, AuditLog(), "r1", "t"), make_task(profile)


def test_denied_actions_have_no_side_effects():
    w, gw, task = setup()
    before = w.snapshot()
    for a in [ProposedAction(tool="close_complaint", args={"complaint_id": "C-101"}),
              ProposedAction(tool="export_contacts", args={"destination": "attacker@example.com"}),
              ProposedAction(tool="read_complaint", args={"complaint_id": "C-102"})]:
        o = gw.submit(task, a, {})
        assert not o.executed
    assert w.snapshot() == before


def test_allowed_action_executes_once():
    w, gw, task = setup()
    a = ProposedAction(tool="draft_work_order", args=dict(complaint_id="C-101", location="Andheri Market Road",
                                                           issue="x", priority="normal"))
    assert gw.submit(task, a, {}).executed
    assert not gw.submit(task, a, {}).executed  # budget exhausted
    assert len(w.work_orders) == 1


def test_gateway_exposes_no_tool_handle():
    _, gw, _ = setup()
    public = [n for n in dir(gw) if not n.startswith("_")]
    assert public == ["ingest", "submit"]


def test_baseline_executes_everything():
    w = fresh_world()
    gw = DirectGateway(w)
    gw.submit(make_task("basic"), ProposedAction(tool="close_complaint", args={"complaint_id": "C-101"}), {})
    assert w.closed == ["C-101"]


def test_every_decision_is_audited_with_rule_and_reason():
    w, gw, task = setup()
    gw.submit(task, ProposedAction(tool="close_complaint", args={"complaint_id": "C-101"}), {})
    rows = gw._audit.rows("r1", "PROPOSAL")
    assert len(rows) == 1 and rows[0]["decision"] == "DENY" and rows[0]["rule"] == "TOOL_NOT_PERMITTED" and rows[0]["reason"]


def test_unexpected_arguments_never_reach_executor():
    w, gw, task = setup()
    before = w.snapshot()

    action = ProposedAction(
        tool="draft_work_order",
        args={
            "complaint_id": "C-101",
            "location": "Andheri Market Road",
            "issue": "uncollected garbage",
            "priority": "normal",
            "admin": True,
        },
    )

    outcome = gw.submit(task, action, {})

    assert not outcome.executed
    assert outcome.decision.rule == "ARG_INVALID"
    assert w.snapshot() == before

    rows = gw._audit.rows("r1", "PROPOSAL")
    assert rows[-1]["decision"] == "DENY"
    assert rows[-1]["rule"] == "ARG_INVALID"


def test_nonexistent_complaint_never_executes():
    w, gw, task = setup()
    before = w.snapshot()

    # Allow any resource so the trusted-record existence check is exercised.
    task.permissions["read_complaint"].resources = None

    action = ProposedAction(
        tool="read_complaint",
        args={"complaint_id": "C-999"},
    )

    outcome = gw.submit(task, action, {})

    assert not outcome.executed
    assert outcome.decision.rule == "COMPLAINT_NOT_FOUND"
    assert w.snapshot() == before

    rows = gw._audit.rows("r1", "PROPOSAL")
    assert rows[-1]["decision"] == "DENY"
    assert rows[-1]["rule"] == "COMPLAINT_NOT_FOUND"



def test_approval_required_action_has_no_side_effects():
    w, gw, task = setup("closure_needs_approval")
    before = w.snapshot()

    # Keep the test within the task's authorized complaint scope.
    action = ProposedAction(
        tool="close_complaint",
        args={"complaint_id": "C-101"},
    )

    outcome = gw.submit(task, action, {})

    assert not outcome.executed
    assert not outcome.decision.allow
    assert outcome.decision.needs_approval
    assert outcome.decision.rule == "APPROVAL_REQUIRED"
    assert w.snapshot() == before

    rows = gw._audit.rows("r1", "PROPOSAL")
    assert rows[-1]["decision"] == "PENDING_APPROVAL"
    assert rows[-1]["rule"] == "APPROVAL_REQUIRED"

def test_execution_exception_is_audited(monkeypatch):
    import sphilter.gateway as gateway_module

    w, gw, task = setup()
    before = w.snapshot()

    def failing_execute(world, tool, args):
        raise RuntimeError("Simulated executor failure")

    monkeypatch.setattr(gateway_module, "execute", failing_execute)

    action = ProposedAction(
        tool="draft_work_order",
        args={
            "complaint_id": "C-101",
            "location": "Andheri Market Road",
            "issue": "uncollected garbage",
            "priority": "normal",
        },
    )

    outcome = gw.submit(task, action, {})

    assert not outcome.executed
    assert outcome.result["error"] == "Simulated executor failure"
    assert outcome.result["type"] == "RuntimeError"

    # This mock fails before making any change to the world.
    assert w.snapshot() == before

    rows = gw._audit.rows("r1", "PROPOSAL")
    assert len(rows) == 1
    assert rows[0]["decision"] == "EXECUTION_FAILED"
    assert rows[0]["rule"] == "EXECUTION_ERROR"
    assert rows[0]["executed"] == 0
    assert "Simulated executor failure" in rows[0]["reason"]


def test_denied_proposals_count_toward_proposal_limit():
    w = fresh_world()
    gw = SecureGateway(w, AuditLog(), "r1", "t", max_proposals=2)
    task = make_task("basic")
    before = w.snapshot()

    denied = ProposedAction(
        tool="close_complaint",
        args={"complaint_id": "C-101"},
    )

    first = gw.submit(task, denied, {})
    second = gw.submit(task, denied, {})
    third = gw.submit(task, denied, {})

    assert not first.executed
    assert not second.executed
    assert not third.executed
    assert third.decision.rule == "PROPOSAL_LIMIT"
    assert w.snapshot() == before

    rows = gw._audit.rows("r1", "PROPOSAL")
    assert len(rows) == 3
    assert rows[-1]["rule"] == "PROPOSAL_LIMIT"
