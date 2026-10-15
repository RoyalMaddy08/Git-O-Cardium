import json
import tempfile
from pathlib import Path

from sphilter.auth import (MAX_FAILS, LOCK_SECONDS, OfficerStore, Throttle, authenticate, can_view, hash_password,
                           read_log, verify_password, visible_scenarios)
from sphilter.scenarios import BY_ID, RECORDS, SCENARIOS


def setup():
    d = Path(tempfile.mkdtemp())
    s = OfficerStore(d / "officers.json")
    s.add("off.keast", "K East", "officer", "K-East", "correct-horse-1")
    s.add("sup.mehta", "Mehta", "supervisor", None, "another-pass-22")
    return s, Throttle(), d / "log.jsonl"


def test_password_hash_is_salted_and_not_plaintext():
    a, b = hash_password("secret-pass-1"), hash_password("secret-pass-1")
    assert a["hash"] != b["hash"] and "secret" not in json.dumps(a)
    assert verify_password("secret-pass-1", a) and not verify_password("wrong", a)


def test_store_file_has_no_plaintext_password():
    s, _, _ = setup()
    assert "correct-horse-1" not in s.path.read_text()


def test_login_success_and_failure_messages_are_generic():
    s, t, lg = setup()
    o, msg = authenticate(s, t, "off.keast", "correct-horse-1", log_path=lg)
    assert o and o.ward == "K-East" and msg == ""
    _, m1 = authenticate(s, t, "off.keast", "nope", log_path=lg)
    _, m2 = authenticate(s, t, "ghost.user", "nope", log_path=lg)
    assert m1 == m2 == "Invalid officer ID or password."


def test_unassigned_person_cannot_login():
    s, t, lg = setup()
    assert authenticate(s, t, "random.person", "anything-123", log_path=lg)[0] is None


def test_lockout_after_repeated_failures_even_with_right_password():
    s, t, lg = setup()
    for i in range(MAX_FAILS):
        authenticate(s, t, "off.keast", "bad", now=100 + i, log_path=lg)
    o, msg = authenticate(s, t, "off.keast", "correct-horse-1", now=110, log_path=lg)
    assert o is None and "Too many attempts" in msg
    o, _ = authenticate(s, t, "off.keast", "correct-horse-1", now=100 + LOCK_SECONDS + 10, log_path=lg)
    assert o is not None


def test_events_are_logged_without_passwords():
    s, t, lg = setup()
    authenticate(s, t, "off.keast", "bad-password-x", log_path=lg)
    authenticate(s, t, "off.keast", "correct-horse-1", log_path=lg)
    rows = read_log(path=lg)
    assert [r["event"] for r in rows] == ["login", "login_failed"]
    assert "bad-password-x" not in lg.read_text()


def test_officer_sees_only_own_ward_supervisor_sees_all():
    s, _, _ = setup()
    off, sup = s.get("off.keast"), s.get("sup.mehta")
    mine = visible_scenarios(off)
    assert mine and all(RECORDS[x.target].ward == "K-East" for x in mine)
    assert len(mine) < len(SCENARIOS) and len(visible_scenarios(sup)) == len(SCENARIOS)
    assert can_view(off, BY_ID["A1"]) and not can_view(off, BY_ID["B6"])  # B6 is a H-West complaint


def test_validation_rules():
    s, _, _ = setup()
    for bad in [("x", "X", "officer", None, "longenough1"), ("x", "X", "officer", "K-East", "short"),
                ("x", "X", "root", None, "longenough1")]:
        try:
            s.add(*bad)
        except ValueError:
            continue
        raise AssertionError(bad)


def test_removed_officer_is_gone():
    s, _, _ = setup()
    s.remove("off.keast")
    assert s.get("off.keast") is None
