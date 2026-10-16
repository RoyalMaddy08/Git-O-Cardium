import json
import py_compile
import shutil
import tempfile
from pathlib import Path

from sphilter import conformance as cf
from sphilter import rules_store as rs

ROOT = Path(__file__).resolve().parent.parent


def _tmp_copy():
    d = Path(tempfile.mkdtemp())
    shutil.copytree(ROOT / "rules", d / "rules")
    shutil.copytree(ROOT / "cases", d / "cases")
    rs.BACKUP_DIR = d / "bak"
    return d


def test_all_rule_files_valid_and_consistent():
    for s in rs.rule_stems():
        d, errs = rs.parse_rule_text(rs.read_rule_text(s))
        assert not errs, (s, errs)
        assert rs.consistency(s) == [], (s, rs.consistency(s))
    assert len(rs.rule_stems()) == 8


def test_all_case_files_load_and_ids_unique():
    cases = cf.load_cases()
    ids = [c.id for c in cases]
    assert len(ids) == len(set(ids)) and len(cases) == 47


def test_invalid_yaml_rejected_and_file_untouched():
    d = _tmp_copy()
    before = (d / "rules" / "social.yaml").read_text()
    errs = rs.save_rule_text("social", "lens: [unclosed", d / "rules")
    assert errs and (d / "rules" / "social.yaml").read_text() == before
    errs = rs.save_rule_text("social", "lens: Social\nrule_id: X\n", d / "rules")
    assert errs and (d / "rules" / "social.yaml").read_text() == before


def test_valid_rule_saved_with_backup():
    d = _tmp_copy()
    old = rs.read_rule_text("social", d / "rules")
    rule, _ = rs.parse_rule_text(old)
    new = rs.build_rule_text(rule, rule_id="SOC-001", description="Edited text", conditions="a\nb", action="DENY",
                             reason_codes=["TOOL_NOT_PERMITTED"], enforced_by="x", log_fields="decision", db_fields="")
    assert rs.save_rule_text("social", new, d / "rules") == []
    assert "Edited text" in rs.read_rule_text("social", d / "rules")
    assert list((d / "bak").glob("*social*"))


def test_bad_cases_rejected():
    d = _tmp_copy()
    cdir = d / "cases"
    assert rs.save_cases_text("social", "not json", cdir)
    assert rs.save_cases_text("social", "{}", cdir)
    data = json.loads((cdir / "social.json").read_text())
    bad = json.loads(json.dumps(data))
    bad[0]["acts"][0]["decision"] = "MAYBE"
    assert rs.save_cases_text("social", json.dumps(bad), cdir)
    dup = json.loads(json.dumps(data))
    dup[0]["id"] = "P-M1"  # belongs to political.json
    assert any("duplicate" in e for e in rs.save_cases_text("social", json.dumps(dup), cdir))
    assert json.loads((cdir / "social.json").read_text()) == data  # untouched


def test_new_case_roundtrip_and_runs():
    d = _tmp_copy()
    cdir = d / "cases"
    case, errs = rs.new_case_dict("Social", "S-X1", "extra export try", "malicious", "basic", "export_contacts",
                                  '{"destination": "a@example.com"}', "DENY", "TOOL_NOT_PERMITTED")
    assert not errs
    cur, _ = rs.parse_cases_text("social", rs.read_cases_text("social", cdir), cdir)
    assert rs.save_cases_text("social", json.dumps(cur + [case]), cdir) == []
    res = {r.case.id: r for r in cf.run_all(cf.load_cases(cdir))}
    assert res["S-X1"].status == "PASS"


def test_editing_expectation_in_file_flips_result_to_fail():
    d = _tmp_copy()
    cdir = d / "cases"
    data = json.loads((cdir / "political.json").read_text())
    for c in data:
        if c["id"] == "P-M1":
            c["acts"][0]["decision"] = "ALLOW"
    assert rs.save_cases_text("political", json.dumps(data), cdir) == []
    res = {r.case.id: r for r in cf.run_all(cf.load_cases(cdir))}
    assert res["P-M1"].status == "FAIL" and res["P-M1"].actual[0]["decision"] == "DENY"


def test_new_case_dict_validation():
    _, errs = rs.new_case_dict("Social", "", "t", "malicious", "basic", "send_email", "{bad", "DENY", "")
    assert errs
    _, errs = rs.new_case_dict("Social", "S-1", "t", "malicious", "basic", "send_email", "{}", "NOPE", "")
    assert errs


def test_rules_lab_compiles():
    py_compile.compile(str(ROOT / "rules_lab.py"), doraise=True)
