"""Officer authentication and ward-based access. Standard library only.

Design:
- Officers are provisioned by an admin via the CLI; there is no self sign-up.
- Passwords are never stored: PBKDF2-HMAC-SHA256 with a per-user random salt.
- Failed logins are throttled (5 tries, then 60 s lock), and unknown IDs look identical to wrong passwords.
- Every login, failure, lock and logout is appended to data/auth_log.jsonl.
- Officers see only scenarios whose complaint belongs to their assigned ward; supervisors see all.

This is app-level demo auth. For production use SSO/OIDC over HTTPS, not a JSON file.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from .scenarios import RECORDS, SCENARIOS, Scenario

ITER = 200_000
MAX_FAILS, LOCK_SECONDS, IDLE_SECONDS = 5, 60, 30 * 60
ROOT = Path(__file__).resolve().parent.parent
OFFICERS_PATH = Path(os.environ.get("SPHILTER_OFFICERS", ROOT / "data" / "officers.json"))
LOG_PATH = Path(os.environ.get("SPHILTER_AUTH_LOG", ROOT / "data" / "auth_log.jsonl"))
WARDS = sorted({r.ward for r in RECORDS.values()})


@dataclass(frozen=True)
class Officer:
    id: str
    name: str
    role: str  # "officer" (one ward) or "supervisor" (all wards)
    ward: str | None


def hash_password(password: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITER)
    return {"salt": salt.hex(), "hash": h.hex(), "iter": ITER}


def verify_password(password: str, rec: dict) -> bool:
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(rec["salt"]), rec["iter"])
    return hmac.compare_digest(h.hex(), rec["hash"])


_DUMMY = hash_password(secrets.token_hex(8))  # equalises timing for unknown IDs


class OfficerStore:
    def __init__(self, path: Path = OFFICERS_PATH):
        self.path = Path(path)

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def exists(self) -> bool:
        return bool(self._load())

    def ids(self) -> list[str]:
        return sorted(self._load())

    def add(self, uid: str, name: str, role: str, ward: str | None, password: str) -> None:
        uid = uid.strip().lower()
        if role not in ("officer", "supervisor"):
            raise ValueError("role must be 'officer' or 'supervisor'")
        if role == "officer" and ward not in WARDS:
            raise ValueError(f"an officer needs a ward from {WARDS}")
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        data = self._load()
        data[uid] = {"name": name, "role": role, "ward": ward if role == "officer" else None,
                     "pw": hash_password(password)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def remove(self, uid: str) -> None:
        data = self._load()
        data.pop(uid.strip().lower(), None)
        self.path.write_text(json.dumps(data, indent=2))

    def record(self, uid: str) -> dict | None:
        return self._load().get(uid.strip().lower())

    def get(self, uid: str) -> Officer | None:
        r = self.record(uid)
        return None if r is None else Officer(uid.strip().lower(), r["name"], r["role"], r["ward"])


class Throttle:
    def __init__(self):
        self._fails: dict[str, list[float]] = {}

    def locked_for(self, uid: str, now: float) -> float:
        recent = [t for t in self._fails.get(uid, []) if now - t < LOCK_SECONDS]
        self._fails[uid] = recent
        return (recent[0] + LOCK_SECONDS - now) if len(recent) >= MAX_FAILS else 0.0

    def fail(self, uid: str, now: float) -> None:
        self._fails.setdefault(uid, []).append(now)

    def reset(self, uid: str) -> None:
        self._fails.pop(uid, None)


def log_event(user: str, event: str, ok: bool, path: Path | None = None) -> None:
    p = Path(path or LOG_PATH)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a") as f:
            f.write(json.dumps({"ts": round(time.time(), 1), "user": user, "event": event, "ok": ok}) + "\n")
    except OSError:
        pass


def read_log(limit: int = 50, path: Path | None = None) -> list[dict]:
    p = Path(path or LOG_PATH)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text().splitlines()[-limit:]][::-1]


def authenticate(store: OfficerStore, throttle: Throttle, uid: str, password: str, now: float | None = None,
                 log_path: Path | None = None) -> tuple[Officer | None, str]:
    now = time.time() if now is None else now
    u = uid.strip().lower()
    wait = throttle.locked_for(u, now)
    if wait > 0:
        log_event(u, "login_locked", False, log_path)
        return None, f"Too many attempts. Try again in {int(wait) + 1} seconds."
    rec = store.record(u)
    ok = verify_password(password, rec["pw"] if rec else _DUMMY)
    if rec and ok:
        throttle.reset(u)
        log_event(u, "login", True, log_path)
        return store.get(u), ""
    throttle.fail(u, now)
    log_event(u, "login_failed", False, log_path)
    return None, "Invalid officer ID or password."


def visible_scenarios(officer: Officer) -> list[Scenario]:
    if officer.role == "supervisor":
        return list(SCENARIOS)
    return [s for s in SCENARIOS if RECORDS[s.target].ward == officer.ward]


def can_view(officer: Officer, scenario: Scenario) -> bool:
    return scenario in visible_scenarios(officer)


# ---------------------------------------------------------------- CLI
def _cli() -> None:
    ap = argparse.ArgumentParser(prog="python -m sphilter.auth", description="Provision officers")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create demo officers with random passwords (shown once)")
    a = sub.add_parser("add", help="add or update an officer")
    a.add_argument("id"); a.add_argument("--name", required=True)
    a.add_argument("--role", choices=["officer", "supervisor"], default="officer")
    a.add_argument("--ward", choices=WARDS)
    sub.add_parser("list"); r = sub.add_parser("remove"); r.add_argument("id")
    args = ap.parse_args()
    store = OfficerStore()
    if args.cmd == "init":
        demo = [("sup.mehta", "Supervisor Mehta", "supervisor", None),
                ("off.keast", "Officer K-East", "officer", "K-East"),
                ("off.hwest", "Officer H-West", "officer", "H-West"),
                ("off.gnorth", "Officer G-North", "officer", "G-North")]
        print(f"Writing {store.path}\nSave these now; passwords are not stored anywhere in readable form:\n")
        for uid, name, role, ward in demo:
            pw = secrets.token_urlsafe(9)
            store.add(uid, name, role, ward, pw)
            print(f"  {uid:<12} {pw:<14} {role:<10} {ward or 'all wards'}")
    elif args.cmd == "add":
        pw = getpass.getpass("Password (min 8 chars): ")
        store.add(args.id, args.name, args.role, args.ward, pw)
        print("saved", args.id)
    elif args.cmd == "list":
        for uid in store.ids():
            o = store.get(uid)
            print(f"{o.id:<14} {o.role:<10} {o.ward or 'all wards':<10} {o.name}")
    elif args.cmd == "remove":
        store.remove(args.id); print("removed", args.id)


if __name__ == "__main__":
    _cli()
