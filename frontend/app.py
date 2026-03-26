"""Streamlit frontend — Agent Layer.

Two-state UI:
  Home  — upload files (starts new session) or resume a past session
  Active — view incidents, chat, add more files, end session
"""

import streamlit as st
import requests
import os

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

st.set_page_config(page_title="Cyber Analyst", page_icon="\U0001f6e1\ufe0f", layout="wide")

st.markdown("""<style>
/* Session card row: horizontal block in sidebar that contains a popover */
section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"]:has(div[data-testid="stPopover"]) {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 8px;
    padding: 0 2px;
    gap: 0 !important;
    margin-bottom: 6px;
    transition: background 0.2s ease, border-color 0.2s ease;
    align-items: center;
}
section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"]:has(div[data-testid="stPopover"]):hover {
    background: rgba(255,255,255,0.09);
    border-color: rgba(255,255,255,0.13);
}
/* Session load button — transparent inside card */
section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"]:has(div[data-testid="stPopover"]) > div:first-child button {
    border: none !important;
    background: transparent !important;
    box-shadow: none !important;
    text-align: left;
    padding: 0.4rem 0.55rem;
    font-size: 0.78rem;
    line-height: 1.4;
    color: inherit;
    width: 100%;
}
/* ⋮ hidden until row hover */
section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"]:has(div[data-testid="stPopover"]) div[data-testid="stPopover"] {
    opacity: 0;
    transition: opacity 0.15s ease;
}
section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"]:has(div[data-testid="stPopover"]):hover div[data-testid="stPopover"] {
    opacity: 1;
}
/* ⋮ trigger — minimal */
section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"]:has(div[data-testid="stPopover"]) div[data-testid="stPopover"] > div:first-child button {
    padding: 0.1rem 0.3rem;
    min-height: 0;
    line-height: 1;
    border: none !important;
    background: transparent !important;
    box-shadow: none !important;
    font-size: 1rem;
    opacity: 0.6;
}
section[data-testid="stSidebar"] div[data-testid="stHorizontalBlock"]:has(div[data-testid="stPopover"]) div[data-testid="stPopover"] > div:first-child button:hover {
    opacity: 1;
}
/* Popover dropdown body — compact, native menu rows */
div[data-testid="stPopoverBody"] {
    min-width: 130px !important;
    padding: 0 !important;
    overflow: hidden;
    border-radius: 8px;
}
div[data-testid="stPopoverBody"] [data-testid="stVerticalBlock"] {
    gap: 0 !important;
}
div[data-testid="stPopoverBody"] .stElementContainer {
    margin: 0 !important;
    width: 100% !important;
    max-width: 100% !important;
}
div[data-testid="stPopoverBody"] .stElementContainer > div {
    width: 100% !important;
}
div[data-testid="stPopoverBody"] button[kind="secondary"] {
    width: 100% !important;
    margin: 0 !important;
    display: block;
    text-align: left;
    padding: 0.4rem 0.65rem;
    font-size: 0.82rem;
    line-height: 1.35;
    border: none !important;
    background: transparent !important;
    box-shadow: none !important;
    border-radius: 0 !important;
    transform: none !important;
    transition: background 0.1s ease !important;
}
div[data-testid="stPopoverBody"] button[kind="secondary"]:hover {
    background: rgba(255,255,255,0.07) !important;
    box-shadow: none !important;
    transform: none !important;
    border: none !important;
}
div[data-testid="stPopoverBody"] button[kind="secondary"]:focus,
div[data-testid="stPopoverBody"] button[kind="secondary"]:focus-visible,
div[data-testid="stPopoverBody"] button[kind="secondary"]:active {
    box-shadow: none !important;
    transform: none !important;
    outline: none !important;
}
div[data-testid="stPopoverBody"] hr {
    margin: 0 !important;
    border: none;
    border-top: 1px solid rgba(255,255,255,0.12);
}
/* Pin chat input to bottom of viewport */
div[data-testid="stChatInput"] {
    position: fixed;
    bottom: 0;
    left: var(--sidebar-width, 21rem);
    right: 0;
    padding: 0.75rem 1rem;
    background: var(--background-color, #0e1117);
    z-index: 100;
    border-top: 1px solid rgba(255,255,255,0.08);
}
/* Space so messages don't hide behind fixed input */
div[data-testid="stChatMessageContainer"] {
    padding-bottom: 5rem;
}
</style>""", unsafe_allow_html=True)

if "active_session" not in st.session_state:
    st.session_state.active_session = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "ending_session" not in st.session_state:
    st.session_state.ending_session = False
if "session_name" not in st.session_state:
    st.session_state.session_name = None
if "renaming_session" not in st.session_state:
    st.session_state.renaming_session = None
if "deleting_session" not in st.session_state:
    st.session_state.deleting_session = None


def _load_chat_history(session_id):
    """Fetch persisted chat messages for a session from the backend."""
    try:
        resp = requests.get(f"{BACKEND_URL}/sessions/{session_id}/chat-history", timeout=10)
        return resp.json() if resp.status_code == 200 else []
    except requests.ConnectionError:
        return []


def _start_session(uploaded_files):
    """Ingest files into a new session, run analysis, switch to active view."""
    if not uploaded_files:
        return

    session_id = None
    total_events = 0

    with st.sidebar.status(f"Ingesting {len(uploaded_files)} file(s)..."):
        for f in uploaded_files:
            try:
                data = {"session_id": session_id} if session_id else {}
                resp = requests.post(
                    f"{BACKEND_URL}/ingest",
                    files={"file": (f.name, f.getvalue())},
                    data=data,
                    timeout=120,
                )
                if resp.status_code == 200:
                    body = resp.json()
                    total_events += body.get("events_parsed", 0)
                    if session_id is None:
                        session_id = body.get("session_id")
                else:
                    st.sidebar.error(f"Error ingesting {f.name}: {resp.text}")
            except requests.ConnectionError:
                st.sidebar.error("Cannot connect to backend.")
                return

    if total_events > 0 and session_id:
        with st.sidebar.status("Running analysis..."):
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/analyze-all",
                    params={"session_id": session_id},
                    timeout=300,
                )
                if resp.status_code == 200:
                    result = resp.json()
                    st.sidebar.success(
                        f"Ingested **{total_events}** events. "
                        f"Detected **{result['incidents_detected']}** incidents."
                    )
                else:
                    st.sidebar.error(f"Analysis error: {resp.text}")
            except requests.ConnectionError:
                st.sidebar.error("Cannot connect to backend.")
                return

        st.session_state.active_session = session_id
        st.session_state.session_name = None
        st.session_state.chat_history = _load_chat_history(session_id)
        st.rerun()
    else:
        st.sidebar.warning("No events parsed from uploaded files.")


def _add_files(uploaded_files):
    """Ingest additional files into the current active session and re-analyze."""
    session_id = st.session_state.active_session
    if not uploaded_files or not session_id:
        return

    total_events = 0
    with st.sidebar.status(f"Ingesting {len(uploaded_files)} file(s)..."):
        for f in uploaded_files:
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/ingest",
                    files={"file": (f.name, f.getvalue())},
                    data={"session_id": session_id},
                    timeout=120,
                )
                if resp.status_code == 200:
                    total_events += resp.json().get("events_parsed", 0)
                else:
                    st.sidebar.error(f"Error ingesting {f.name}: {resp.text}")
            except requests.ConnectionError:
                st.sidebar.error("Cannot connect to backend.")
                return

    if total_events > 0:
        with st.sidebar.status("Re-analyzing all session events..."):
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/analyze-all",
                    params={"session_id": session_id},
                    timeout=300,
                )
                if resp.status_code == 200:
                    result = resp.json()
                    st.sidebar.success(
                        f"Added **{total_events}** events. "
                        f"Now **{result['incidents_detected']}** incidents."
                    )
                    st.rerun()
                else:
                    st.sidebar.error(f"Analysis error: {resp.text}")
            except requests.ConnectionError:
                st.sidebar.error("Cannot connect to backend.")


def _end_session():
    """End the current session. Skip naming dialog if session already has a name."""
    if st.session_state.session_name:
        st.session_state.active_session = None
        st.session_state.session_name = None
        st.session_state.ending_session = False
        st.session_state.chat_history = []
        st.rerun()
    else:
        st.session_state.ending_session = True
        st.rerun()


def _finalize_session(name: str):
    """Call backend to finalize the session, then return to home."""
    sid = st.session_state.active_session
    try:
        requests.patch(
            f"{BACKEND_URL}/sessions/{sid}/finalize",
            json={"name": name if name.strip() else None},
            timeout=10,
        )
    except requests.ConnectionError:
        st.error("Cannot connect to backend.")
        return
    st.session_state.active_session = None
    st.session_state.session_name = None
    st.session_state.ending_session = False
    st.session_state.chat_history = []
    st.rerun()


def _cancel_end_session():
    st.session_state.ending_session = False
    st.rerun()


# ── Sidebar ──────────────────────────────────────────────────────────
st.sidebar.title("Cyber Analyst")
st.sidebar.markdown("AI-powered SIEM alert analysis")
st.sidebar.divider()

if st.session_state.active_session is None:
    # ── HOME STATE ───────────────────────────────────────────────────
    uploaded_files = st.sidebar.file_uploader(
        "Upload SIEM Logs",
        type=["json", "csv"],
        accept_multiple_files=True,
        help="Upload one or more JSON/CSV files to start a new investigation",
    )
    if uploaded_files and st.sidebar.button("Start Investigation", type="primary"):
        _start_session(uploaded_files)

    st.sidebar.divider()
    st.sidebar.subheader("Previous Sessions")
    try:
        resp = requests.get(f"{BACKEND_URL}/sessions", timeout=10)
        past_sessions = resp.json() if resp.status_code == 200 else []
    except requests.ConnectionError:
        past_sessions = []
        st.sidebar.warning("Cannot connect to backend.")

    if not past_sessions:
        st.sidebar.caption("No previous sessions.")
    else:
        for s in past_sessions:
            s_id = s["id"]
            label = s.get("name") or s_id[:8]
            events = s.get("event_count", 0)
            incidents = s.get("incident_count", 0)
            ts = (s.get("created_at") or "")[:10]

            col_info, col_menu = st.sidebar.columns([7, 1])
            with col_info:
                if st.button(
                    f"{label} · {events} events · {incidents} incidents · {ts}",
                    key=f"session_{s_id}",
                    use_container_width=True,
                ):
                    st.session_state.active_session = s_id
                    st.session_state.session_name = s.get("name")
                    st.session_state.chat_history = _load_chat_history(s_id)
                    st.session_state.renaming_session = None
                    st.session_state.deleting_session = None
                    st.rerun()
            with col_menu:
                with st.popover("\u22ee"):
                    if st.button("\u270f\ufe0f Rename", key=f"rename_{s_id}"):
                        st.session_state.renaming_session = {"id": s_id, "name": label}
                        st.session_state.deleting_session = None
                        st.rerun()
                    st.divider()
                    if st.button("\U0001f5d1 Delete", key=f"delete_{s_id}"):
                        st.session_state.deleting_session = {"id": s_id, "name": label}
                        st.session_state.renaming_session = None
                        st.rerun()

    # Home main area
    if st.session_state.renaming_session:
        info = st.session_state.renaming_session
        _, modal, _ = st.columns([1, 2, 1])
        with modal:
            st.subheader("Rename Session")
            new_name = st.text_input("New name", value=info["name"], key="rename_input", label_visibility="collapsed")
            c1, c2, _ = st.columns([1, 1, 2])
            with c1:
                if st.button("Save", type="primary", key="rename_save", use_container_width=True):
                    if new_name and new_name.strip():
                        try:
                            requests.patch(
                                f"{BACKEND_URL}/sessions/{info['id']}",
                                json={"name": new_name.strip()},
                                timeout=10,
                            )
                        except requests.ConnectionError:
                            st.error("Cannot connect to backend.")
                    st.session_state.renaming_session = None
                    st.rerun()
            with c2:
                if st.button("Cancel", key="rename_cancel", use_container_width=True):
                    st.session_state.renaming_session = None
                    st.rerun()

    elif st.session_state.deleting_session:
        info = st.session_state.deleting_session
        _, modal, _ = st.columns([1, 2, 1])
        with modal:
            st.subheader("Delete Session")
            st.warning(f"Are you sure you want to delete **{info['name']}** and all its data?")
            c1, c2, _ = st.columns([1, 1, 2])
            with c1:
                if st.button("Delete", type="primary", key="delete_confirm", use_container_width=True):
                    try:
                        requests.delete(
                            f"{BACKEND_URL}/sessions/{info['id']}",
                            timeout=10,
                        )
                    except requests.ConnectionError:
                        st.error("Cannot connect to backend.")
                    if st.session_state.active_session == info["id"]:
                        st.session_state.active_session = None
                        st.session_state.session_name = None
                        st.session_state.chat_history = []
                    st.session_state.deleting_session = None
                    st.rerun()
            with c2:
                if st.button("Cancel", key="delete_cancel", use_container_width=True):
                    st.session_state.deleting_session = None
                    st.rerun()

    else:
        st.header("Welcome to Cyber Analyst")
        st.info("Upload SIEM log files in the sidebar to start a new investigation, or resume a previous session.")

else:
    # ── ACTIVE SESSION STATE ─────────────────────────────────────────
    sid = st.session_state.active_session
    st.sidebar.caption(f"Session: `{sid[:8]}...`")

    if st.sidebar.button("End Session", type="secondary"):
        _end_session()

    st.sidebar.divider()
    add_files = st.sidebar.file_uploader(
        "Add More Files",
        type=["json", "csv"],
        accept_multiple_files=True,
        key="add_files_uploader",
        help="Add more log files to this investigation",
    )
    if add_files and st.sidebar.button("Upload & Re-analyze", type="primary"):
        _add_files(add_files)

    # ── Main Area ───────────────────────────────────────────────────
    if st.session_state.ending_session:
        st.header("Save Session")
        st.markdown("Enter a name for this session, or leave blank for a default name.")
        session_name = st.text_input("Session name", placeholder="e.g. Wazuh rootcheck investigation")

        col_save, col_cancel = st.columns(2)
        with col_save:
            if st.button("Save Session", type="primary"):
                _finalize_session(session_name)
        with col_cancel:
            if st.button("Cancel"):
                _cancel_end_session()

    else:
        tab_dashboard, tab_chat = st.tabs(["Dashboard", "Chat"])

        # ── Dashboard Tab ────────────────────────────────────────────
        with tab_dashboard:
            st.header("Security Incidents")

            try:
                resp = requests.get(
                    f"{BACKEND_URL}/incidents",
                    params={"session_id": sid},
                    timeout=10,
                )
                incidents = resp.json() if resp.status_code == 200 else []
            except requests.ConnectionError:
                incidents = []
                st.warning("Cannot connect to backend API.")

            if not incidents:
                st.info("No incidents detected yet. Upload logs to get started.")
            else:
                severity_colors = {
                    "critical": "\U0001f534",
                    "high": "\U0001f7e0",
                    "medium": "\U0001f7e1",
                    "low": "\U0001f7e2",
                }

                for inc in incidents:
                    sev = inc.get("severity", "medium")
                    icon = severity_colors.get(sev, "\u26aa")
                    with st.expander(
                        f"{icon} Incident #{inc.get('number', inc['id'])} \u2014 {sev.upper()} | "
                        f"Host: {inc.get('host', '?')} | "
                        f"User: {inc.get('user', '?')} | "
                        f"Events: {inc.get('event_count', 0)}"
                    ):
                        try:
                            detail_resp = requests.get(
                                f"{BACKEND_URL}/incidents/{inc['id']}", timeout=60
                            )
                            detail = detail_resp.json() if detail_resp.status_code == 200 else {}
                        except requests.ConnectionError:
                            detail = {}
                            st.error("Cannot load incident details.")
                            continue

                        col1, col2 = st.columns([2, 1])

                        with col1:
                            st.subheader("Attack Timeline")
                            timeline = detail.get("timeline", [])
                            if timeline:
                                for evt in timeline:
                                    stage = evt.get("mitre_stage", "Unknown")
                                    technique = evt.get("mitre_technique", "")
                                    rule = evt.get("rule_matched", "")
                                    anomaly = " \u26a0\ufe0f ANOMALY" if evt.get("is_anomaly") else ""
                                    tag = f" [{technique}]" if technique else ""
                                    rule_tag = f" (Rule: {rule})" if rule else ""

                                    st.markdown(
                                        f"**{evt['position'] + 1}. {stage}{tag}** \u2014 "
                                        f"`{evt.get('timestamp', '')}` on `{evt.get('host', '')}` "
                                        f"by `{evt.get('user', '?')}`{anomaly}{rule_tag}"
                                    )
                                    st.caption(
                                        f"  {evt.get('event_type', '')} \u2014 {evt.get('raw_message', '')}"
                                    )
                            else:
                                st.write("No timeline events.")

                        with col2:
                            st.subheader("AI Analysis")
                            if detail.get("summary"):
                                st.markdown(detail["summary"])
                            elif detail.get("explanation"):
                                st.markdown(detail["explanation"])
                            else:
                                st.info("Explanation not yet generated.")

                            st.subheader("Suggested Actions")
                            actions = detail.get("suggested_actions", [])
                            if actions:
                                for i, action in enumerate(actions, 1):
                                    st.markdown(f"**{i}.** {action}")
                            else:
                                st.info("No actions suggested yet.")

        # ── Chat Tab ─────────────────────────────────────────────────
        with tab_chat:
            st.header("Chat with Your Data")
            st.caption("Ask questions about incidents in this session.")

            for msg in st.session_state.chat_history:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

            if question := st.chat_input("Ask about your incidents..."):
                st.session_state.chat_history.append({"role": "user", "content": question})
                with st.chat_message("user"):
                    st.markdown(question)

                with st.chat_message("assistant"):
                    with st.spinner("Analyzing..."):
                        try:
                            resp = requests.post(
                                f"{BACKEND_URL}/chat",
                                json={"question": question, "session_id": sid},
                                timeout=60,
                            )
                            if resp.status_code == 200:
                                answer = resp.json().get("response", "No response.")
                            else:
                                answer = f"Error: {resp.text}"
                        except requests.ConnectionError:
                            answer = "Cannot connect to backend API."

                    st.markdown(answer)
                    st.session_state.chat_history.append({"role": "assistant", "content": answer})
