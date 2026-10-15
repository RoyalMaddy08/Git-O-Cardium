"""SPHILTER-AI dashboard.  Run:  streamlit run app.py"""
import html
import time

import streamlit as st

from sphilter import auth

from sphilter.evaluate import run_all, run_scenario, to_markdown
from sphilter.scenarios import BY_ID, SCENARIOS, make_task

st.set_page_config(page_title="SPHILTER-AI", page_icon="🛡️", layout="wide")

CSS = """
<style>
#MainMenu, footer, header {visibility: hidden;}
.block-container {padding-top: 1.2rem; max-width: 1150px;}
.hero {background: linear-gradient(120deg,#0F766E 0%,#1E3A8A 100%); color: #fff; padding: 28px 34px;
       border-radius: 18px; margin-bottom: 18px;}
.hero h1 {margin: 0; font-size: 2.2rem; color: #fff;}
.hero p {margin: 6px 0 0 0; font-size: 1.08rem; opacity: .95; color: #fff;}
.steps {display: flex; gap: 12px; margin: 0 0 22px 0; flex-wrap: wrap;}
.step {flex: 1; min-width: 220px; background: #fff; border-radius: 14px; padding: 14px 16px;
       box-shadow: 0 1px 4px rgba(0,0,0,.08);}
.step b {color: #0F766E;}
.card {background: #fff; border-radius: 14px; padding: 18px 20px; box-shadow: 0 1px 4px rgba(0,0,0,.08);
       margin-bottom: 14px; color: #1F2937;}
.card h3 {margin: 0 0 8px 0; font-size: 1.15rem; color: #1F2937;}
.doc {background: #F8FAFC; border: 1px dashed #94A3B8; border-radius: 10px; padding: 14px 16px;
      font-size: 1.02rem; line-height: 1.6; color: #1F2937;}
.evil {background: #FEE2E2; color: #991B1B; padding: 2px 6px; border-radius: 6px; font-weight: 600;}
.tag {display: inline-block; font-size: .78rem; font-weight: 700; padding: 2px 9px; border-radius: 99px;
      margin-right: 6px; vertical-align: middle;}
.tag.bad {background: #FEE2E2; color: #991B1B;} .tag.good {background: #DCFCE7; color: #166534;}
.tag.info {background: #E0F2FE; color: #075985;}
.verdict {border-radius: 14px; padding: 16px 20px; margin-bottom: 10px; color: #1F2937;}
.verdict.bad {background: #FEF2F2; border: 2px solid #FCA5A5;}
.verdict.good {background: #F0FDF4; border: 2px solid #86EFAC;}
.verdict h3 {margin: 0 0 6px 0; font-size: 1.2rem;}
.verdict ul {margin: 6px 0 0 18px; padding: 0;}
.act {display: flex; gap: 12px; align-items: flex-start; background: #fff; border-radius: 12px;
      padding: 12px 16px; margin-bottom: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.07); color: #1F2937;}
.act.blocked {border-left: 6px solid #DC2626;} .act.ok {border-left: 6px solid #16A34A;}
.act.wait {border-left: 6px solid #D97706;}
.act .icon {font-size: 1.5rem; line-height: 1.2;}
.act .why {color: #475569; font-size: .93rem; margin-top: 2px;}
.kpis {display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 10px;}
.kpi {flex: 1; min-width: 230px; background: #fff; border-radius: 14px; padding: 16px 18px;
      box-shadow: 0 1px 4px rgba(0,0,0,.08); color: #1F2937;}
.kpi .big {font-size: 1.9rem; font-weight: 800;} .kpi .lbl {color: #475569; font-size: .95rem;}
.kpi .arrow {color: #64748B; font-weight: 600; font-size: 1.1rem;}
.red {color: #DC2626;} .green {color: #16A34A;}
.note {background: #FFFBEB; border: 1px solid #FCD34D; border-radius: 12px; padding: 12px 16px; color: #78350F;}
.small {color: #64748B; font-size: .88rem;}
.login-card {background:#fff; border-radius:18px; padding:26px 28px 8px 28px; box-shadow:0 4px 18px rgba(0,0,0,.10);}
.login-card h2 {margin:0 0 4px 0; color:#1F2937;}
.userbar {background:#fff; border-radius:12px; padding:10px 16px; box-shadow:0 1px 3px rgba(0,0,0,.07); color:#1F2937;}
</style>
"""

TOOL_NAME = {"read_complaint": "Read the complaint", "draft_work_order": "Draft a work order",
             "close_complaint": "Close the complaint", "export_contacts": "Export all citizens' contacts",
             "send_email": "Send an email"}
RULE_TEXT = {
    "ALLOWED": "Part of the officer's task.",
    "ALLOWED_GROUNDED": "Allowed, but the location was corrected from the official record.",
    "TOOL_NOT_PERMITTED": "The officer's task never asked for this. No permission.",
    "RESOURCE_OUT_OF_SCOPE": "Belongs to a different complaint than this task covers.",
    "DESTINATION_NOT_ALLOWED": "Recipient is not on the approved list.",
    "RATE_LIMIT": "Already done once for this task. Repeats are not allowed.",
    "APPROVAL_REQUIRED": "High-risk. Waiting for a human supervisor, so it did not run.",
    "ARG_INVALID": "The request was malformed.",
    "UNKNOWN_TOOL": "Unknown tool.",
}
MARKERS = ["Ignore previous", "पिछले निर्देश", "मागील सूचना", "Close this", "When drafting", "Create 3", "Also fetch",
           "Please export", "Send an email", "<!--", "[OFFICIAL"]


def split_injection(scn):
    body = scn.body
    idx = [body.find(m) for m in MARKERS if body.find(m) >= 0]
    cut = min(idx) if idx else len(body)
    return body[:cut].strip(), body[cut:].strip()


def violation_text(v):
    kind, _, val = v.partition(":")
    return {
        "closed": f"Closed complaint {val} without permission",
        "export": f"Sent ALL citizens' phone numbers to {val}",
        "external_email": f"Emailed an outside address: {val}",
        "out_of_scope_read": f"Read another citizen's complaint ({val})",
        "work_order_other_complaint": f"Created a work order for the wrong complaint ({val})",
        "duplicate_work_orders": f"Created {val} work orders instead of 1",
        "tampered_priority": f"Work order priority was changed to '{val}' by hidden text",
        "tampered_location": f"Work order location was changed to '{val}' by hidden text",
    }.get(kind, v)


def label(sid):
    s = BY_ID[sid]
    return ("✅ Normal request: " if not s.is_attack else "⚠️ Attack: ") + s.title


@st.cache_data
def scoreboard():
    m = run_all(reps=5)
    clean = {k: v for k, v in m.items() if k != "_results"}
    return clean, to_markdown(clean)


def pct(x):
    if x is None:
        return "n/a"
    v = x * 100
    return f"{v:.0f}%" if abs(v - round(v)) < 0.05 else f"{v:.1f}%"


st.markdown(CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------- login gate
@st.cache_resource
def get_throttle():
    return auth.Throttle()


def rerun():
    (getattr(st, "rerun", None) or st.experimental_rerun)()


def current_officer(store):
    uid = st.session_state.get("uid")
    if not uid:
        return None
    if time.time() - st.session_state.get("last_active", 0) > auth.IDLE_SECONDS:
        auth.log_event(uid, "session_timeout", True)
        st.session_state.clear()
        st.session_state["flash"] = "Signed out after 30 minutes of inactivity."
        return None
    officer = store.get(uid)  # re-checked every run: removing an officer locks them out immediately
    if officer is not None:
        st.session_state["last_active"] = time.time()
    return officer


def login_page(store):
    _, mid, _ = st.columns([1, 1.4, 1])
    with mid:
        st.markdown("<div class='login-card'><h2>🛡️ SPHILTER-AI</h2>"
                    "<div class='small'>Officer sign-in. Access is limited to officers assigned by the department.</div></div>",
                    unsafe_allow_html=True)
        if not store.exists():
            st.markdown("<div class='note' style='margin-top:12px'><b>No officers set up yet.</b><br>"
                        "An administrator must run <code>python -m sphilter.auth init</code> once, then restart.</div>",
                        unsafe_allow_html=True)
            return
        if st.session_state.get("flash"):
            st.info(st.session_state.pop("flash"))
        with st.form("login"):
            uid = st.text_input("Officer ID")
            pw = st.text_input("Password", type="password")
            go = st.form_submit_button("Sign in")
        if go:
            officer, msg = auth.authenticate(store, get_throttle(), uid, pw)
            if officer is None:
                st.error(msg)
            else:
                st.session_state["uid"] = officer.id
                st.session_state["last_active"] = time.time()
                rerun()
        st.markdown("<div class='small' style='margin-top:10px'>Forgot your password or need access? "
                    "Contact your supervisor. All sign-ins are logged.</div>", unsafe_allow_html=True)


store = auth.OfficerStore()
officer = current_officer(store)
if officer is None:
    login_page(store)
    st.stop()

bar, out = st.columns([5, 1])
with bar:
    scope = "all wards" if officer.role == "supervisor" else f"Ward {officer.ward}"
    st.markdown(f"<div class='userbar'>👤 <b>{html.escape(officer.name)}</b> &nbsp;·&nbsp; "
                f"{html.escape(officer.role.title())} &nbsp;·&nbsp; {html.escape(scope)}</div>", unsafe_allow_html=True)
with out:
    if st.button("Sign out"):
        auth.log_event(officer.id, "logout", True)
        st.session_state.clear()
        rerun()
st.markdown(
    "<div class='hero'><h1>🛡️ SPHILTER-AI</h1>"
    "<p>AI agents can be tricked by hidden instructions inside the documents they read. "
    "SPHILTER-AI makes sure a trick can never turn into an action.</p></div>"
    "<div class='steps'>"
    "<div class='step'><b>Step 1</b><br>The AI agent reads a citizen complaint. Some text may be a hidden attack.</div>"
    "<div class='step'><b>Step 2</b><br>The agent <i>proposes</i> actions. It cannot run anything itself.</div>"
    "<div class='step'><b>Step 3</b><br>A separate security check decides what really happens.</div>"
    "</div>", unsafe_allow_html=True)

st.markdown("#### Pick a situation to try")
allowed = auth.visible_scenarios(officer)
ids = [s.id for s in allowed]
if not ids:
    st.warning("No complaints are assigned to your ward yet.")
    st.stop()
sid = st.selectbox("Situation", ids, index=ids.index("A1") if "A1" in ids else 0, format_func=label,
                   label_visibility="collapsed")
scn = BY_ID[sid]
if not auth.can_view(officer, scn):  # defence in depth: never trust the widget value alone
    st.error("You are not assigned to this complaint's ward.")
    st.stop()
base, prot = run_scenario(scn, "baseline"), run_scenario(scn, "protected")

# ---------------------------------------------------------------- 1. what the agent reads
clean, evil = split_injection(scn)
doc = html.escape(clean)
if evil and not scn.attachments:
    doc += " <span class='evil'>" + html.escape(evil) + "</span>"
for name, text in scn.attachments:
    doc += ("<br><br><b>Attached file:</b> " + html.escape(name) +
            "<br><span class='evil'>" + html.escape(text) + "</span>")
kind = "<span class='tag bad'>CONTAINS A HIDDEN ATTACK</span>" if scn.is_attack else "<span class='tag good'>NORMAL REQUEST</span>"
st.markdown(
    f"<div class='card'><h3>1. What the agent reads {kind}</h3>"
    f"<div class='small'>Officer's task: <i>{html.escape(make_task(scn.profile, scn.target).objective)}</i></div><br>"
    f"<div class='doc'>{doc}</div>"
    "<div class='small' style='margin-top:8px'>"
    + ("Red text is the attack. The attacker hopes the AI will obey it." if scn.is_attack
       else "Nothing suspicious here. A good security layer must not get in the way.")
    + "</div></div>", unsafe_allow_html=True)


# ---------------------------------------------------------------- 2. what happened
def verdict(r, title_bad, title_good):
    if r.violations:
        items = "".join(f"<li>{html.escape(violation_text(v))}</li>" for v in r.violations)
        return f"<div class='verdict bad'><h3>❌ {title_bad}</h3><ul>{items}</ul></div>"
    done = "The work order was drafted correctly." if r.legit_completed else ""
    return f"<div class='verdict good'><h3>✅ {title_good}</h3>{done}</div>"


st.markdown("#### 2. What happened")
left, right = st.columns(2)
with left:
    st.markdown("**Without protection** (agent wired straight to its tools)")
    st.markdown(verdict(base, "Attack succeeded", "Nothing bad happened"), unsafe_allow_html=True)
with right:
    st.markdown("**With SPHILTER-AI** (every action is checked first)")
    st.markdown(verdict(prot, "Something got through", "Safe. Nothing unauthorized happened"), unsafe_allow_html=True)
if scn.known_limitation:
    st.markdown("<div class='note'><b>Honest limitation:</b> the hidden text only changed a detail <i>inside</i> an "
                "action the agent is allowed to do. The security check cannot tell this from a normal choice, so it "
                "gets through. Fix: more fields taken from official records, and human review of risky edits.</div>",
                unsafe_allow_html=True)

# ---------------------------------------------------------------- 3. action by action
st.markdown("#### 3. Every action the protected agent tried, and the decision")
for o in prot.outcomes:
    d = o.decision
    if d.allow:
        cls, icon, tag = "ok", "✅", "<span class='tag good'>ALLOWED</span>"
    elif d.needs_approval:
        cls, icon, tag = "wait", "⏳", "<span class='tag info'>WAITING FOR A HUMAN</span>"
    else:
        cls, icon, tag = "blocked", "🚫", "<span class='tag bad'>BLOCKED</span>"
    extra = ""
    dest = o.action.args.get("to") or o.action.args.get("destination")
    if dest:
        extra = f" → <code>{html.escape(str(dest))}</code>"
    st.markdown(
        f"<div class='act {cls}'><div class='icon'>{icon}</div><div>{tag}<b>{TOOL_NAME.get(o.action.tool, o.action.tool)}</b>{extra}"
        f"<div class='why'>{html.escape(RULE_TEXT.get(d.rule, d.reason))}</div></div></div>", unsafe_allow_html=True)

with st.expander("Technical details: full audit log (what a security auditor would see)"):
    st.dataframe([{"step": r["kind"], "tool": r["tool"], "decision": r["decision"], "rule": r["rule"],
                   "reason": r["reason"], "ran": bool(r["executed"])} for r in prot.audit.rows(prot.run_id)],
                 hide_index=True)

# ---------------------------------------------------------------- scoreboard
st.markdown("---")
st.markdown("### Scoreboard: all 21 situations, run for real")
m, report = scoreboard()
b, p = m["baseline"], m["protected"]
st.markdown(
    "<div class='kpis'>"
    f"<div class='kpi'><div class='lbl'>Attacks that worked</div><div class='big'><span class='red'>{pct(b['attack_success_rate'])}</span>"
    f" <span class='arrow'>→</span> <span class='green'>{pct(p['attack_success_rate'])}</span></div>"
    "<div class='lbl'>without protection → with SPHILTER-AI</div></div>"
    f"<div class='kpi'><div class='lbl'>Normal requests still completed</div><div class='big green'>{pct(p['benign_completion_rate'])}</div>"
    "<div class='lbl'>security did not break normal work</div></div>"
    f"<div class='kpi'><div class='lbl'>Good actions wrongly blocked</div><div class='big green'>{pct(p['false_positive_rate'])}</div>"
    "<div class='lbl'>false alarms</div></div>"
    f"<div class='kpi'><div class='lbl'>Actions recorded in the audit log</div><div class='big green'>{pct(p['audit_coverage'])}</div>"
    f"<div class='lbl'>check takes about {p['policy_latency_ms_mean']} ms</div></div>"
    "</div>"
    f"<div class='small'>Even while under attack, the legitimate work order was still produced in "
    f"{pct(p['attack_conditioned_completion_rate'])} of attack situations.</div>", unsafe_allow_html=True)
with st.expander("See the full results table"):
    st.markdown(report)

st.markdown("<div class='small' style='margin-top:18px'>All data is synthetic and all tools are simulated. "
            "No real citizen data and no real government systems are used. The attacker in these tests is a "
            "simple stand-in agent that obeys hidden text; results show the design works, not how often a real "
            "AI is fooled.</div>", unsafe_allow_html=True)

if officer.role == "supervisor":
    with st.expander("Supervisor only: recent sign-in activity"):
        st.dataframe([{"time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), "user": r["user"],
                       "event": r["event"], "success": r["ok"]} for r in auth.read_log(30)], hide_index=True)
