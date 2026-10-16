"""Rules Lab: a team tool to view/edit the per-lens rule specs and test cases, and run the conformance suite.

Run:  streamlit run rules_lab.py
Local team tool only: it writes files in rules/ and cases/. Do not deploy it next to the officer dashboard.
"""
from __future__ import annotations

import yaml
import streamlit as st

from sphilter import conformance as cf
from sphilter import rules_store as rs

st.set_page_config(page_title="SPHILTER Rules Lab", page_icon="🧪", layout="wide")

ICON = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "KNOWN_FAIL": "🟠 KNOWN_FAIL", "UNEXPECTED_PASS": "🟡 UNEXPECTED_PASS",
        "NOT_RUNNABLE": "⚪ NOT_RUNNABLE"}
TOOLS = ["read_complaint", "draft_work_order", "close_complaint", "export_contacts", "send_email"]


def rerun():
    (getattr(st, "rerun", None) or st.experimental_rerun)()


def flash(kind: str, msg: str):
    st.session_state["flash"] = (kind, msg)


def show_flash():
    f = st.session_state.pop("flash", None)
    if f:
        getattr(st, f[0])(f[1])


def show_errors(errs):
    for e in errs:
        st.error(e)


# ------------------------------------------------------------------ sidebar
st.sidebar.title("🧪 Rules Lab")
stems = cf.LENS_ORDER
names = {s: s.title() for s in stems}
lens = st.sidebar.radio("Lens", stems, format_func=lambda s: names[s])
st.sidebar.caption("Rule files are documentation of the intended rule. Test cases are executed against the real "
                   "gateway. A control counts as working only when a run shows PASS.")
if st.sidebar.button("▶ Run ALL tests", use_container_width=True):
    st.session_state["results"] = ("all", cf.run_all())
    st.session_state["jump_to_results"] = True

st.title(f"{names[lens]} lens")
show_flash()
tab_rule, tab_cases, tab_run = st.tabs(["📜 Rule", "🧾 Test cases", "▶ Run tests"])

# ------------------------------------------------------------------ rule tab
with tab_rule:
    if lens not in rs.rule_stems():
        st.info("The headline test has no separate rule; it exercises several lenses together.")
    else:
        text = rs.read_rule_text(lens)
        rule, errs = rs.parse_rule_text(text)
        show_errors(errs)
        rule = rule if isinstance(rule, dict) else {}
        st.warning("This file documents the rule. The gateway does **not** read it: enforcement is in "
                   "`sphilter/policy.py` and `gateway.py`. Changing a rule here does not change what is blocked.")
        for w in rs.consistency(lens):
            st.warning(w)
        c1, c2 = st.columns([2, 1])
        with c1:
            st.markdown(f"**{rule.get('rule_id', '?')}**: {rule.get('description', '')}")
            st.markdown("**Conditions**")
            for cnd in rule.get("conditions", []):
                st.markdown(f"- {cnd}")
        with c2:
            st.markdown(f"**When broken:** `{rule.get('action', '?')}`")
            st.markdown("**Reason codes:** " + (", ".join(f"`{c}`" for c in rule.get("reason_codes", [])) or "none"))
            st.markdown(f"**Enforced by:** {rule.get('enforced_by', '')}")

        with st.expander("✏️ Edit with a form", expanded=False):
            with st.form(f"rule_form_{lens}"):
                rid = st.text_input("Rule id", rule.get("rule_id", ""))
                desc = st.text_area("Description", rule.get("description", ""), height=100)
                cond = st.text_area("Conditions (one per line)", "\n".join(rule.get("conditions", [])), height=100)
                act = st.selectbox("Decision when broken", list(rs.RULE_ACTIONS),
                                   index=list(rs.RULE_ACTIONS).index(rule.get("action", "DENY"))
                                   if rule.get("action") in rs.RULE_ACTIONS else 0)
                codes = st.multiselect("Reason codes", sorted(rs.KNOWN_CODES),
                                       default=[c for c in rule.get("reason_codes", []) if c in rs.KNOWN_CODES])
                enf = st.text_area("Enforced by / current status (be honest)", rule.get("enforced_by", ""), height=80)
                a1, a2 = st.columns(2)
                logf = a1.text_area("Audit log fields (one per line)",
                                    "\n".join((rule.get("audit") or {}).get("log_fields", [])), height=160)
                dbf = a2.text_area("Extra database fields (one per line)",
                                   "\n".join((rule.get("audit") or {}).get("db_fields", [])), height=160)
                if st.form_submit_button("Save rule"):
                    new = rs.build_rule_text(rule, rule_id=rid, description=desc, conditions=cond, action=act,
                                             reason_codes=codes, enforced_by=enf, log_fields=logf, db_fields=dbf)
                    e = rs.save_rule_text(lens, new)
                    if e:
                        show_errors(e)
                    else:
                        flash("success", "Rule saved (backup kept in .backups/).")
                        rerun()
        with st.expander("🧩 Edit raw YAML", expanded=False):
            raw = st.text_area("YAML", text, height=380, key=f"raw_rule_{lens}")
            if st.button("Save YAML", key=f"save_raw_rule_{lens}"):
                e = rs.save_rule_text(lens, raw)
                if e:
                    show_errors(e)
                else:
                    flash("success", "YAML saved (backup kept in .backups/).")
                    rerun()

# ------------------------------------------------------------------ cases tab
with tab_cases:
    rows = rs.case_rows(lens)
    st.markdown(f"**{len(rows)} test cases** for this lens. Expected results are written before running anything.")
    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.caption("Decisions: ALLOW, DENY, APPROVAL_REQUIRED. Malicious cases must be stopped; legit cases must still work.")

    with st.expander("➕ Add a case (one action)", expanded=False):
        with st.form(f"add_case_{lens}"):
            a, b = st.columns(2)
            cid = a.text_input("Case id (unique), e.g. S-M9")
            title = b.text_input("Short title")
            k1, k2 = st.columns(2)
            kind = k1.selectbox("Type", ["malicious", "legit", "check"])
            profile = k2.selectbox("Task profile", ["basic", "notify", "closure_needs_approval", "reporting", "report_needs_approval"])
            t1, t2 = st.columns(2)
            tool = t1.selectbox("Proposed tool", TOOLS)
            decision = t2.selectbox("Expected decision", list(cf.DECISIONS))
            args = st.text_area("Arguments (JSON)", '{"complaint_id": "C-101"}', height=80)
            rule = st.text_input("Expected reason code (e.g. TOOL_NOT_PERMITTED)")
            st.caption("Expected side effects default to none. Use the JSON editor below for several actions "
                       "or for expecting a work order, email, etc.")
            if st.form_submit_button("Add case"):
                d, errs = rs.new_case_dict(names[lens], cid, title, kind, profile, tool, args, decision, rule)
                if errs:
                    show_errors(errs)
                else:
                    cur, e1 = rs.parse_cases_text(lens, rs.read_cases_text(lens))
                    new_text = rs.json.dumps((cur or []) + [d], indent=2, ensure_ascii=False)
                    e2 = rs.save_cases_text(lens, new_text)
                    if e1 or e2:
                        show_errors(e1 + e2)
                    else:
                        flash("success", f"Case {d['id']} added.")
                        rerun()

    with st.expander("🧩 Edit all cases as JSON", expanded=False):
        st.caption("Each case: id, lens, kind, title, profile, target, acts[{tool,args,decision,rule}], "
                   "expect{work_orders,closed,exports,outbox}. Optional: custom, not_runnable, known_gap.")
        raw = st.text_area("JSON", rs.read_cases_text(lens), height=420, key=f"raw_cases_{lens}")
        if st.button("Save cases", key=f"save_cases_{lens}"):
            e = rs.save_cases_text(lens, raw)
            if e:
                show_errors(e)
            else:
                flash("success", "Cases saved (backup kept in .backups/).")
                rerun()

# ------------------------------------------------------------------ run tab
with tab_run:
    r1, r2 = st.columns(2)
    if r1.button(f"▶ Run {names[lens]} tests"):
        cases = [c for c in cf.load_cases() if c.lens.lower() == lens]
        st.session_state["results"] = (lens, cf.run_all(cases))
    if r2.button("▶ Run ALL tests", key="run_all_tab"):
        st.session_state["results"] = ("all", cf.run_all())
    got = st.session_state.get("results")
    if not got:
        st.info("No run yet. Results below come only from a real run of the real gateway.")
    else:
        scope, results = got
        from collections import Counter
        cnt = Counter(r.status for r in results)
        st.markdown(f"**Last run: {'all lenses' if scope == 'all' else names[scope]}, {len(results)} cases**")
        cols = st.columns(5)
        for col, s in zip(cols, ["PASS", "FAIL", "KNOWN_FAIL", "UNEXPECTED_PASS", "NOT_RUNNABLE"]):
            col.metric(ICON[s], cnt.get(s, 0))
        if cnt.get("FAIL") or cnt.get("UNEXPECTED_PASS"):
            st.error("Some controls did NOT behave as specified. Send these to Person 1 with the evidence below.")
        elif cnt.get("PASS") and not cnt.get("FAIL"):
            st.success("Every runnable case matched its expected result. NOT_RUNNABLE items are not claimed.")
        st.dataframe([{"ID": r.case.id, "Lens": r.case.lens, "Case": r.case.title, "Status": ICON[r.status],
                       "Notes": "; ".join(r.notes)} for r in results], use_container_width=True, hide_index=True)
        for r in results:
            if r.status in ("FAIL", "UNEXPECTED_PASS", "KNOWN_FAIL"):
                with st.expander(f"{ICON[r.status]}  {r.case.id}: {r.case.title}", expanded=r.status == "FAIL"):
                    exp = [{"Tool": a.tool, "Expected": a.decision,
                            "Expected reason": a.rule if isinstance(a.rule, str) else " | ".join(a.rule)}
                           for a in r.case.acts]
                    act = [{"Tool": a["tool"], "Actual": a["decision"], "Actual reason": a["rule"],
                            "Executed": a["executed"]} for a in r.actual]
                    st.markdown("**Expected**")
                    st.dataframe(exp, hide_index=True, use_container_width=True)
                    st.markdown("**Actual**")
                    st.dataframe(act, hide_index=True, use_container_width=True)
                    st.markdown(f"**Expected side effects:** work_orders={r.case.work_orders}, closed={r.case.closed}, "
                                f"exports={r.case.exports}, outbox={r.case.outbox}  \n**Actual:** {r.effects}")
                    for n in r.notes:
                        st.write("• " + n)
        st.download_button("⬇ Download report (markdown)", cf.to_markdown(results), file_name="conformance.md")
