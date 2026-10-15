import tempfile
from pathlib import Path

from sphilter.auth import OfficerStore, begin_second_factor, complete_second_factor, read_log
from sphilter.minimoth import MiniMoth, MiniMothError, mask_phone, normalize_phone
from tests.fake_minimoth import KEY, start


def officer(phone="+919876543210"):
    d = Path(tempfile.mkdtemp())
    s = OfficerStore(d / "o.json")
    s.add("off.keast", "K East", "officer", "K-East", "correct-horse-1", phone)
    return s.get("off.keast"), d / "log.jsonl"


def test_phone_normalization_and_masking():
    assert normalize_phone("98765 43210") == "+919876543210"
    assert normalize_phone("+91-98765-43210") == "+919876543210"
    for bad in ["12345", "+14155550123", "5876543210", ""]:
        try:
            normalize_phone(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
    assert mask_phone("+919876543210") == "+91******3210"


def test_client_send_verify_validate_refresh_logout():
    srv, st, url = start()
    c = MiniMoth(KEY, url)
    assert c.send_otp("+919876543210")["otp_id"] == "otp_1"
    t = c.verify_otp("+919876543210", "123456")
    assert t["access_token"] == "acc_1" and c.validate("acc_1")["valid"] is True
    assert c.validate("bogus")["valid"] is False
    assert c.refresh("ref_1")["access_token"] == "acc_2"
    c.logout("acc_2"); assert st.logged_out == ["acc_2"]
    srv.shutdown()


def test_api_errors_become_typed_exceptions():
    srv, st, url = start()
    try:
        MiniMoth("mm_test_wrong", url).send_otp("+919876543210")
    except MiniMothError as e:
        assert e.code == "INVALID_API_KEY" and e.status == 401
    else:
        raise AssertionError
    c = MiniMoth(KEY, url); c.send_otp("+919876543210")
    try:
        c.verify_otp("+919876543210", "000111")
    except MiniMothError as e:
        assert e.code == "INVALID_OTP"
    else:
        raise AssertionError
    srv.shutdown()


def test_network_failure_is_reported_not_bypassed():
    o, lg = officer()
    ok, msg = begin_second_factor(o, MiniMoth(KEY, "http://127.0.0.1:1", timeout=1), lg)
    assert not ok and "Could not reach" in msg


def test_second_factor_happy_path_sends_only_to_registered_phone():
    srv, st, url = start(); o, lg = officer(); c = MiniMoth(KEY, url)
    assert begin_second_factor(o, c, lg) == (True, "")
    assert st.sent == ["+919876543210"]
    tokens, msg = complete_second_factor(o, "123456", c, lg)
    assert tokens and tokens["access_token"] == "acc_1" and msg == ""
    assert [r["event"] for r in read_log(path=lg)] == ["otp_verified", "otp_sent"]
    srv.shutdown()


def test_wrong_code_and_bad_format_rejected():
    srv, st, url = start(); o, lg = officer(); c = MiniMoth(KEY, url)
    begin_second_factor(o, c, lg)
    assert complete_second_factor(o, "999999", c, lg)[0] is None
    assert complete_second_factor(o, "12ab56", c, lg)[0] is None
    assert complete_second_factor(o, "", c, lg)[0] is None
    assert "999999" not in lg.read_text()
    srv.shutdown()


def test_officer_without_phone_is_denied_not_skipped():
    srv, st, url = start(); o, lg = officer(phone=None)
    ok, msg = begin_second_factor(o, MiniMoth(KEY, url), lg)
    assert not ok and "No mobile number" in msg and st.sent == []
    srv.shutdown()


def test_service_errors_map_to_friendly_messages():
    srv, st, url = start(); o, lg = officer(); c = MiniMoth(KEY, url)
    st.fail_send = (429, "OTP_RATE_LIMITED")
    ok, msg = begin_second_factor(o, c, lg)
    assert not ok and "wait 10 minutes" in msg
    srv.shutdown()
