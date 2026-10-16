from sphilter.conformance import CASES, run_all, run_case, to_markdown


def test_no_case_fails():
    bad = [(r.case.id, r.notes) for r in run_all() if r.status in ("FAIL", "UNEXPECTED_PASS")]
    assert not bad, bad


def test_known_gap_is_reported_not_hidden():
    r = {x.case.id: x for x in run_all()}
    assert r["T-M6"].status == "PASS"  # fixed: was the A13 known failure


def test_unimplemented_controls_not_claimed():
    r = {x.case.id: x for x in run_all()}
    for cid in ("P-L1", "R-M3"):
        assert r[cid].status == "NOT_RUNNABLE"


def test_checker_detects_wrong_expectation():
    # sanity: a deliberately wrong expectation must FAIL, so the suite can't pass vacuously
    import copy
    c = copy.deepcopy(next(x for x in CASES if x.id == "P-M1"))
    c.acts[0].decision = "ALLOW"
    assert run_case(c).status == "FAIL"


def test_report_renders():
    assert "NOT_RUNNABLE" in to_markdown(run_all())
