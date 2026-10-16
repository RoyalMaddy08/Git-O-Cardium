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
