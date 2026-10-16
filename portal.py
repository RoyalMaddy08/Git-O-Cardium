"""Citizen portal (separate site).  Run:  streamlit run portal.py --server.port 8502

It can only do two things: drop a complaint into the shared inbox, and look up a one-word status.
It never talks to the gateway, tools or policy. Complaint text is handed over as untrusted data and
carries no authority, whatever it says.
"""
import time

import streamlit as st

from sphilter.auth import WARDS
from sphilter.inbox import LIMITS, Inbox, InboxError

st.set_page_config(page_title="Report a civic issue", page_icon="📮", layout="centered")
st.markdown("""<style>
#MainMenu, footer, header {visibility: hidden;}
.block-container {max-width: 760px; padding-top: 1.2rem;}
.hero {background: linear-gradient(120deg,#0F766E 0%,#1E3A8A 100%); color:#fff; padding:26px 30px;
       border-radius:18px; margin-bottom:16px;}
.hero h1 {margin:0; font-size:2rem; color:#fff;} .hero p {margin:6px 0 0 0; color:#fff; opacity:.95;}
.note {background:#FEF3C7; border-radius:12px; padding:10px 14px; color:#78350F; margin-bottom:14px;}
.ticket {background:#ECFDF5; border:1px solid #6EE7B7; border-radius:14px; padding:16px 20px; color:#065F46;}
.ticket b {font-size:1.5rem; letter-spacing:.08em;}
</style>""", unsafe_allow_html=True)


@st.cache_resource
def get_inbox() -> Inbox:
    return Inbox()


st.markdown("<div class='hero'><h1>📮 Report a civic issue</h1><p>Tell the municipal ward office about a "
            "garbage or waste problem near you. You get a tracking number.</p></div>", unsafe_allow_html=True)
st.markdown("<div class='note'><b>Demo site.</b> Please use made-up details only. No real names or real phone "
            "numbers.</div>", unsafe_allow_html=True)

with st.form("report", clear_on_submit=False):
    name = st.text_input("Your name", max_chars=LIMITS["name"][1])
    c1, c2 = st.columns(2)
    ward = c1.selectbox("Ward", WARDS)
    phone = c2.text_input("Mobile number", placeholder="e.g. 9000000101")
    location = st.text_input("Where is the problem?", max_chars=LIMITS["location"][1], placeholder="Street, landmark")
    body = st.text_area("What is the problem?", max_chars=LIMITS["body"][1], height=140,
                        placeholder="Describe the issue in English, Hindi or Marathi.")
    go = st.form_submit_button("Send to ward office")

if go:
    try:
        tid = get_inbox().submit(name, ward, location, phone, body)
        st.markdown(f"<div class='ticket'>Thank you. Your tracking number is<br><b>{tid}</b><br>"
                    "Keep it to check the status below.</div>", unsafe_allow_html=True)
    except InboxError as e:
        st.error(str(e))

st.markdown("#### Check status")
tid_in = st.text_input("Tracking number", placeholder="W-XXXXXXXX", key="track")
if tid_in:
    s = get_inbox().public_status(tid_in)
    if s is None:
        st.warning("No complaint found with that number.")
    else:
        when = time.strftime("%d %b %Y, %H:%M", time.localtime(s["submitted_at"]))
        st.success(f"**{s['status']}**  ·  Ward {s['ward']}  ·  sent {when}")
st.caption("Your text is passed to the ward office as plain information. It cannot trigger any action by itself.")
