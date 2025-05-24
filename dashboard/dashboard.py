import os
import sys

# Set up Python import paths so submodules load cleanly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Streamlit for interactive dashboard UI
import streamlit as st
import pandas as pd
import time
import math

# Core project modules: simulate attacks, run defense logic, handle logs
from attack_simulator.attack_simulator import choose_persona
from attack_simulator.attack_simulator import AttackSimulator
from defense_simulator.defense_simulator import DefenseSimulator
from logger.logger import EventLogger

# Plotly for dynamic timeline/metrics visualization
import plotly.express as px

# Paths for local assets (avatar image for sidebar branding)
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
AVATAR_PATH = os.path.join(DASHBOARD_DIR, "assets", "soc_avatar.png")

# Streamlit page config: wide layout, page title
st.set_page_config(layout="wide", page_title="SOC Attack/Defense Command Center")

# Inject custom CSS for dark theme, badge colors, glass effect cards
st.markdown("""
    <style>
        .main {background: linear-gradient(120deg, #1b263b, #415a77);}
        .css-1aumxhk {background-color: #22223b !important;}
        .badge {
            display: inline-block; padding: 4px 12px; border-radius: 12px;
            color: white; font-weight: bold; font-size: 0.9em;
        }
        .critical {background: #e63946;}
        .high {background: #f1a208;}
        .medium {background: #f4d35e; color:#333;}
        .low {background: #43aa8b;}
        .glass {background: rgba(255,255,255,0.08); border-radius: 18px; box-shadow: 0 8px 24px rgba(0,0,0,0.14);}
    </style>
""", unsafe_allow_html=True)

DEFAULT_EVENTS = 25  # Default number of attack events per simulation run

def main():
    # Sidebar avatar (SOC analyst branding, optional image)
    if os.path.exists(AVATAR_PATH):
        st.sidebar.image(AVATAR_PATH, width=100)

    # Sidebar controls (SOC simulation controls and status)
    st.sidebar.markdown("<b>On-Shift Analyst: Alice</b>", unsafe_allow_html=True)
    generate = st.sidebar.button("Generate Events Now")  # Generate new batch of events
    campaign_view = st.sidebar.button("View Attack Campaign Sample")  # Simulate attack campaign
    st.sidebar.markdown("---")
    st.sidebar.markdown("🚨 <b>Live Feed</b>: Simulates SOC incidents with attacker/defense mapping.", unsafe_allow_html=True)

    # Logging controls: toggle, format, filter options
    st.sidebar.markdown("📝 <b>Logging Options</b>", unsafe_allow_html=True)
    enable_logging = st.sidebar.checkbox("Enable Logging", value=True)
    log_format = st.sidebar.radio("Log Format", ["jsonl", "csv"], index=0)
    filter_tp = st.sidebar.checkbox("Log Only True Positives", value=False)
    filter_failed = st.sidebar.checkbox("Log Only Failed Defenses", value=False)

    # Replay mode: load from previous log instead of simulating new data
    st.sidebar.markdown("---")
    replay_mode = st.sidebar.checkbox("Replay From Log File", value=False)
    replay_type = st.sidebar.radio("Replay Type", ["attack", "defense"], index=0)
    if replay_mode:
        st.sidebar.warning("Replay Mode: Disables simulation/generation. Loads from log file.")

    # Session state: which alert is selected for deep dive (persistent between reruns)
    if "selected_alert" not in st.session_state:
        st.session_state.selected_alert = 0

    # Function to generate new simulated attack/defense events (SOC activity)
    def load_events():
        atk_sim = AttackSimulator()
        def_sim = DefenseSimulator()
        logs = atk_sim.generate_realistic_log(DEFAULT_EVENTS)
        st.session_state.attack_logs = logs['attack_logs']
        st.session_state.defense_logs = def_sim.defend_events_bulk(st.session_state.attack_logs)
        st.session_state.selected_alert = 0

    # --- Main simulation/replay/campaign logic ---

    # If replay mode enabled: load logs from disk, map to defense if needed
    if replay_mode:
        logger = EventLogger(log_format=log_format)
        if replay_type == "attack":
            st.session_state.attack_logs = logger.load_log_replay("attack")
            def_sim = DefenseSimulator()
            st.session_state.defense_logs = def_sim.defend_events_bulk(st.session_state.attack_logs)
        else:
            st.session_state.attack_logs = logger.load_log_replay("attack")
            st.session_state.defense_logs = logger.load_log_replay("defense")
        st.warning("🔁 Log Replay Mode Active — data loaded from disk, not simulator.")

    # "Campaign View": runs a story arc simulation (shows chained, real-world attacks from a single threat actor)
    elif campaign_view:
        atk_sim = AttackSimulator()
        persona = atk_sim.choose_persona()
        st.session_state.attack_logs = atk_sim.generate_chained_attack(persona=persona)
        st.session_state.defense_logs = DefenseSimulator().defend_events_bulk(st.session_state.attack_logs)
        st.session_state.selected_alert = 0

    # On first run or "Generate Events Now" click: load new simulation events
    elif generate or "attack_logs" not in st.session_state or "defense_logs" not in st.session_state:
        load_events()

    # Logging: write simulated attack/defense events to disk in chosen format
    if enable_logging and not replay_mode:
        logger = EventLogger(
            log_format=log_format,
            filter_true_positive_only=filter_tp,
            filter_failed_defense_only=filter_failed
        )
        for atk in st.session_state.attack_logs:
            logger.log_attack(atk)
        for df in st.session_state.defense_logs:
            logger.log_defense(df)

    # Convert logs to Pandas DataFrames for analysis/visualization
    attack_logs = pd.DataFrame(st.session_state.attack_logs)
    defense_logs = pd.DataFrame(st.session_state.defense_logs)

    # --- Metrics section: shows SOC KPIs like incident count, blocks, escalations, analyst score ---
    col1, col2, col3, col4, col5 = st.columns([2,2,2,2,2])
    col1.metric("Incidents", len(attack_logs))  # Number of detected incidents
    col2.metric("Blocked", int(defense_logs['defense_success'].sum()))  # Blocked by defense
    col3.metric("Escalations", int(defense_logs['escalation_required'].sum()))  # Incidents escalated
    mean_time = defense_logs['defense_response_time_sec'].dropna().mean()
    col4.metric("Avg. Response (s)", f"{mean_time:.1f}" if mean_time and not math.isnan(mean_time) else "-")  # Analyst response time
    # Analyst Score: % of true positive incidents successfully handled
    total_tp = attack_logs[attack_logs["is_true_positive"] == True]
    if len(total_tp) > 0:
        analyst_score = int((defense_logs['defense_success'].sum() / len(total_tp)) * 100)
    else:
        analyst_score = 0
    col5.metric("Analyst Score", f"{analyst_score}%")

    # --- Timeline visualization: incidents by time, color by severity, escalation markers ---
    attack_logs['dt'] = pd.to_datetime(attack_logs['timestamp'])
    attack_logs['end_dt'] = attack_logs['dt'] + pd.to_timedelta(5, unit='s')  # 5-second visualization window
    fig = px.timeline(
        attack_logs,
        x_start='dt', x_end='end_dt',
        y='attack_type',
        color='severity',
        color_discrete_map={
            "critical": "#e63946", "high": "#f1a208", "medium": "#f4d35e", "low": "#43aa8b"
        },
        hover_data=['source_ip', 'destination_ip', 'persona', 'description'],
        height=350
    )
    # Add vertical markers where escalation was required
    for _, row in defense_logs[defense_logs["escalation_required"] == True].iterrows():
        try:
            fig.add_vline(
                x=pd.to_datetime(row["defense_timestamp"]),
                line_color="red",
                line_width=1,
                annotation_text="Escalation",
                annotation_position="top left"
            )
        except Exception:
            pass
    st.plotly_chart(fig, use_container_width=True)

    # --- Recent Attack Events: show last 6 attacks as clickable alert cards (like a SOC feed) ---
    st.subheader("Recent Attack Events")
    for idx, row in attack_logs.tail(6).reset_index().iterrows():
        sev_class = row['severity']
        clicked = st.button(
            f"{row['timestamp']} - {row['attack_type']}",
            key=f"alert_btn_{row['index']}",
            help=row['description']
        )
        if clicked:
            st.session_state.selected_alert = row['index']
        st.markdown(f"""
            <div class="glass" style="margin-bottom:12px; padding:14px;">
            <span class="badge {sev_class}">{sev_class.upper()}</span>
            <b>{row['timestamp']} - {row['attack_type']}</b><br>
            <i>{row['description']}</i><br>
            <small>Source: {row['source_ip']} --> Target: {row['destination_ip']}</small>
            </div>
        """, unsafe_allow_html=True)

    # --- Incident Deep Dive: show full details for selected alert/incident (for analyst triage, reporting) ---
    st.subheader("Incident Deep Dive")
    details = attack_logs.iloc[st.session_state.selected_alert]
    def_details = defense_logs.iloc[st.session_state.selected_alert]
    def badge(val, css_class): return f'<span class="badge {css_class}">{val}</span>'
    urgent_escalation = def_details.get('urgent_escalation', None)
    urgent_msg = ""
    if urgent_escalation and str(urgent_escalation).lower() not in ["nan", "none", ""]:
        urgent_msg = f"<b><span style='color:red'>URGENT: {urgent_escalation}</span></b>"

    st.markdown(f"""
        <div class="glass" style="margin-top:18px; padding:22px;">
        <h4>{details['attack_type']} {badge(details['severity'].upper(), details['severity'])}</h4>
        <b>Description:</b> {details['description']}<br>
        <b>MITRE:</b> {details['mitre_technique']}<br>
        <b>CVE:</b> {', '.join(details['cves']) if isinstance(details['cves'], list) else details['cves'] or "None"}<br>
        <b>Playbook:</b> {details['playbook_step']}<br>
        <b>Patch</b> {details['patch_required']} ({details['patch_instructions']})<br>
        <b>Persona:</b> {details['persona']} | <b>Source:</b> {details['source_ip']}<br>
        <hr>
        <b>Defense Action:</b> {def_details['defense_action']}<br>
        <b>Defense System:</b> {def_details['defense_system']}<br>
        <b>Success:</b> {def_details['defense_success']}<br>
        <b>Analyst:</b> {def_details['defense_analyst']}<br>
        <b>Response Time:</b> {def_details['defense_response_time_sec']} sec<br>
        <b>Defense Recommendation:</b> {def_details['recommendation']}<br>
        {urgent_msg}
        </div>
    """, unsafe_allow_html=True)

    # --- Analyst Notes: add persistent per-incident notes (demo SOC workflow, investigation, and reporting) ---
    st.subheader("Analyst Notes")
    note_key = f"notes_{details['event_id']}"
    note = st.text_area("Enter notes for this alert:", value=st.session_state.get(note_key, ""), height=120)
    st.session_state[note_key] = note

    # --- Download logs as CSV for later analysis, demo reporting workflow ---
    st.subheader("Download Logs")
    col_a, col_b = st.columns(2)
    with col_a:
        st.download_button("Download Attack Log (CSV)", attack_logs.to_csv(index=False).encode(), file_name="attack_logs.csv")
    with col_b:
        st.download_button("Download Defense Log (CSV)", defense_logs.to_csv(index=False).encode(), file_name="defense_logs.csv")

    # --- Full logs as expandable tables (for complete SOC event review, validation, troubleshooting) ---
    with st.expander("Full Attack Log Table"):
        st.dataframe(attack_logs, use_container_width=True)
    with st.expander("Full Defense Log Table"):
        st.dataframe(defense_logs, use_container_width=True)

# Entrypoint: run the Streamlit dashboard
if __name__ == "__main__":
    main()
