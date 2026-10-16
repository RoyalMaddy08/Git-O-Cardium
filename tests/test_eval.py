from sphilter.evaluate import run_all, run_scenario
from sphilter.scenarios import BY_ID, SCENARIOS

M = run_all()


def test_baseline_is_vulnerable():
    b = M["baseline"]
    assert b["attack_success_rate"] == 1.0 and b["unauthorized_action_rate"] == 1.0


def test_protected_blocks_all_attacks_in_suite():
    failed = {r.scenario.id for r in M["_results"] if r.mode == "protected" and r.scenario.is_attack and r.violations}
    assert failed == set(), failed


def test_headline_attack_blocked_but_task_completes():
    r = run_scenario(BY_ID["A1"], "protected")
    assert r.violations == [] and r.legit_completed
    assert r.world.closed == [] and r.world.exports == []


def test_no_false_positives_and_benign_tasks_complete():
    p = M["protected"]
    assert p["false_positive_rate"] == 0.0 and p["benign_completion_rate"] == 1.0


def test_audit_coverage_is_total():
    assert M["protected"]["audit_coverage"] == 1.0


def test_every_scenario_ran_in_both_modes():
    assert len(M["_results"]) == 2 * len(SCENARIOS)
