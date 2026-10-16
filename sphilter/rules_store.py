"""Load, validate and save the per-lens rule specs (rules/*.yaml) and test cases (cases/*.json).

Rule YAML is documentation of the intended rule: the gateway does NOT read it. Test cases ARE executed
by sphilter.conformance. All writes validate first and keep a timestamped backup under .backups/.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import yaml

from .conformance import CASES_DIR, case_from_dict, load_case_dicts, validate_case_dict

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
BACKUP_DIR = ROOT / ".backups"
KNOWN_CODES = {
    "UNKNOWN_TOOL", "TOOL_NOT_PERMITTED", "ARG_INVALID", "RESOURCE_OUT_OF_SCOPE", "DESTINATION_NOT_ALLOWED",
    "RATE_LIMIT", "APPROVAL_REQUIRED", "ALLOWED", "ALLOWED_GROUNDED", "PRIORITY_NOT_ALLOWED", "RUN_HALTED",
    "PII_MASKED", "AUTHORITY_FROM_UNTRUSTED", "SCOPE_NOT_ALLOWED", "SENSITIVE_FIELDS_NOT_ALLOWED",
    "FIELD_NOT_ALLOWED", "ARG_TAINTED",
}
RULE_ACTIONS = ("ALLOW", "DENY", "APPROVAL_REQUIRED", "n/a")


def rule_stems(rules_dir: Path | None = None) -> list[str]:
    from .conformance import LENS_ORDER
    d = rules_dir or RULES_DIR
    have = {p.stem for p in d.glob("*.yaml")}
    return [s for s in LENS_ORDER if s in have] + sorted(have - set(LENS_ORDER))


def validate_rule(d) -> list[str]:
    if not isinstance(d, dict):
        return ["The file must be a YAML mapping (key: value pairs)."]
    errs = []
    for k in ("lens", "rule_id", "description"):
        if not isinstance(d.get(k), str) or not d[k].strip():
            errs.append(f"'{k}' is required (text)")
    for k in ("conditions", "reason_codes"):
        v = d.get(k)
        if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
            errs.append(f"'{k}' must be a list of text")
    if d.get("action") not in RULE_ACTIONS:
        errs.append(f"'action' must be one of {RULE_ACTIONS}")
    aud = d.get("audit")
    if not isinstance(aud, dict) or not isinstance(aud.get("log_fields"), list) or not aud.get("log_fields"):
        errs.append("'audit.log_fields' must be a non-empty list")
    if isinstance(d.get("reason_codes"), list):
        unknown = [c for c in d["reason_codes"] if c not in KNOWN_CODES]
        if unknown:
            errs.append(f"unknown reason codes {unknown} (known: {sorted(KNOWN_CODES)})")
    return errs


def parse_rule_text(text: str):
    try:
        d = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return None, [f"Not valid YAML: {e}"]
    return d, validate_rule(d)


def _backup(path: Path) -> None:
    if path.exists():
        BACKUP_DIR.mkdir(exist_ok=True)
        shutil.copy2(path, BACKUP_DIR / f"{path.parent.name}-{path.stem}-{int(time.time())}{path.suffix}")


def save_rule_text(stem: str, text: str, rules_dir: Path | None = None) -> list[str]:
    """Returns a list of errors; empty list means saved."""
    _, errs = parse_rule_text(text)
    if errs:
        return errs
    path = (rules_dir or RULES_DIR) / f"{stem}.yaml"
    _backup(path)
    path.write_text(text if text.endswith("\n") else text + "\n")
    return []


def read_rule_text(stem: str, rules_dir: Path | None = None) -> str:
    return ((rules_dir or RULES_DIR) / f"{stem}.yaml").read_text()


def read_cases_text(stem: str, cases_dir: Path | None = None) -> str:
    return ((cases_dir or CASES_DIR) / f"{stem}.json").read_text()


def parse_cases_text(stem: str, text: str, cases_dir: Path | None = None):
    """-> (list of case dicts | None, errors). Checks structure and duplicate ids against the other files."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return None, [f"Not valid JSON: line {e.lineno}, column {e.colno}: {e.msg}"]
    if not isinstance(data, list):
        return None, ["The file must be a JSON list of cases."]
    errs, seen = [], set()
    others = {d["id"] for s, ds in load_case_dicts(cases_dir).items() if s != stem for d in ds if isinstance(d, dict) and "id" in d}
    for i, d in enumerate(data):
        errs += [f"case #{i + 1} ({d.get('id', '?') if isinstance(d, dict) else '?'}): {e}" for e in validate_case_dict(d)]
        cid = d.get("id") if isinstance(d, dict) else None
        if cid in seen or cid in others:
            errs.append(f"duplicate case id '{cid}'")
        seen.add(cid)
    return (None if errs else data), errs


def save_cases_text(stem: str, text: str, cases_dir: Path | None = None) -> list[str]:
    data, errs = parse_cases_text(stem, text, cases_dir)
    if errs:
        return errs
    for d in data:
        case_from_dict(d)  # final structural proof
    path = (cases_dir or CASES_DIR) / f"{stem}.json"
    _backup(path)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    return []


def consistency(stem: str, rules_dir: Path | None = None, cases_dir: Path | None = None) -> list[str]:
    """Warnings when the cases of a lens expect reason codes the rule spec does not list."""
    rp = (rules_dir or RULES_DIR) / f"{stem}.yaml"
    if not rp.exists():
        return []
    rule = yaml.safe_load(rp.read_text()) or {}
    listed = set(rule.get("reason_codes") or []) | {"ALLOWED", "ALLOWED_GROUNDED"}
    warns = []
    for d in load_case_dicts(cases_dir).get(stem, []):
        for a in d.get("acts", []):
            r = a.get("rule", "")
            for code in ([r] if isinstance(r, str) else r):
                if code and code not in listed:
                    warns.append(f"{d['id']} expects {code}, which {rule.get('rule_id', stem)} does not list in reason_codes")
    return sorted(set(warns))


RULE_HEADER = ("# Rule spec for this lens. DOCUMENTATION ONLY: the gateway does not read this file.\n"
               "# Enforcement lives in sphilter/policy.py and gateway.py (see enforced_by).\n")


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def build_rule_text(existing: dict, *, rule_id: str, description: str, conditions: str, action: str,
                    reason_codes: list[str], enforced_by: str, log_fields: str, db_fields: str) -> str:
    """Form values -> YAML text. Keeps any keys the form does not know about."""
    d = dict(existing)
    d.update(rule_id=rule_id.strip(), description=" ".join(description.split()), conditions=_lines(conditions),
             action=action, reason_codes=list(reason_codes), enforced_by=" ".join(enforced_by.split()))
    d["audit"] = {**(existing.get("audit") or {}), "log_fields": _lines(log_fields), "db_fields": _lines(db_fields)}
    return RULE_HEADER + yaml.safe_dump(d, sort_keys=False, allow_unicode=True, width=100)


def case_rows(stem: str, cases_dir: Path | None = None) -> list[dict]:
    rows = []
    for d in load_case_dicts(cases_dir).get(stem, []):
        acts = d.get("acts", [])
        rows.append({"ID": d["id"], "Type": d["kind"], "Case": d["title"], "Profile": d.get("profile", "basic"),
                     "Expected": " | ".join(f"{a['tool']}→{a['decision']}" for a in acts) or "(special check)"})
    return rows


def new_case_dict(lens: str, cid: str, title: str, kind: str, profile: str, tool: str, args_json: str,
                  decision: str, rule: str):
    """-> (case dict | None, errors)"""
    try:
        args = json.loads(args_json or "{}")
    except json.JSONDecodeError as e:
        return None, [f"Arguments are not valid JSON: {e.msg}"]
    d = {"id": cid.strip(), "lens": lens, "kind": kind, "title": title.strip(), "profile": profile, "target": "C-101",
         "acts": [{"tool": tool.strip(), "args": args, "decision": decision, "rule": rule.strip()}],
         "expect": {"work_orders": 0, "closed": 0, "exports": 0, "outbox": 0}}
    errs = validate_case_dict(d)
    return (None if errs else d), errs
