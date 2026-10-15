"""Streamlit demo:  streamlit run app.py"""
import streamlit as st

from sphilter.demo import effects
from sphilter.evaluate import run_all, run_scenario, to_markdown
from sphilter.scenarios import BY_ID, SCENARIOS

st.set_page_config(page_title="SPHILTER-AI", layout="wide")
st.title("SPHILTER-AI")
st.caption("The model proposes. Independent policy authorizes. Synthetic data and simulated tools only.")

tab_demo, tab_eval, tab_audit = st.tabs(["Live demo", "Evaluation", "Audit log"])

with st.sidebar:
    sid = st.selectbox("Scenario", [s.id for s in SCENARIOS], index=6,
                       format_func=lambda i: f"{i}: {BY_ID[i].title}")
scn = BY_ID[sid]
base, prot = run_scenario(scn, "baseline"), run_scenario(scn, "protected")

with tab_demo:
    st.subheader(f"{scn.id}: {scn.title}")
    st.write(f"Category: `{scn.category}` | Task profile: `{scn.profile}`")
    st.markdown("**Untrusted content the agent reads** (treated as data, never as authority)")
    for it in scn.items():
        st.code(f"[{it.provenance.value}] {it.source}\n{it.text.split('Body:', 1)[-1].strip()}", language="text")
    left, right = st.columns(2)
    with left:
        st.markdown("### Baseline agent")
        st.caption("Wired straight to its tools")
        for e in effects(base):
            st.write("- " + e)
        (st.error if base.violations else st.success)(f"Violations: {base.violations or 'none'}")
    with right:
        st.markdown("### Protected agent")
        st.caption("Every action goes through the policy gateway")
        st.dataframe([{"result": "EXECUTED" if o.executed else "BLOCKED", "tool": o.action.tool,
                       "rule": o.decision.rule, "why": o.decision.reason} for o in prot.outcomes],
                     use_container_width=True, hide_index=True)
        for e in effects(prot):
            st.write("- " + e)
        (st.error if prot.violations else st.success)(f"Violations: {prot.violations or 'none'}")
        if scn.known_limitation:
            st.warning("Known limitation: this manipulation stays inside the permitted tool and fields, "
                       "so the policy engine cannot tell it from a legitimate choice.")

with tab_eval:
    st.write("Runs every scenario against both agents. All numbers below come from this run.")
    if st.button("Run full evaluation"):
        m = run_all(reps=20)
        st.session_state["report"] = to_markdown({k: v for k, v in m.items() if k != "_results"})
    st.markdown(st.session_state.get("report", "_Press the button to run._"))

with tab_audit:
    st.write(f"Audit trail for the protected run of {scn.id}")
    st.dataframe([{k: r[k] for k in ("kind", "tool", "provenance", "decision", "rule", "executed", "reason")}
                  for r in prot.audit.rows(prot.run_id)], use_container_width=True, hide_index=True)
