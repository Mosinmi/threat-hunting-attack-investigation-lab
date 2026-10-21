
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.detection_engine import detect_threats
from src.timeline_builder import build_timeline


st.set_page_config(
    page_title="Threat Hunting & Attack Investigation",
    page_icon="🛡️",
    layout="wide",
)

PROJECT_ROOT = Path(__file__).resolve().parent
SYNTHETIC_FILE = PROJECT_ROOT / "data" / "raw" / "sample_events.json"
WINDOWS_FILE = (
    PROJECT_ROOT / "data" / "normalized" / "windows_process_events.json"
)


@st.cache_data
def load_json_events(file_path, file_modified):
    """Load JSON events; file_modified refreshes the cache after collection."""
    del file_modified
    with file_path.open(encoding="utf-8-sig") as file:
        data = json.load(file)

    # A single event may be serialized as an object rather than a list.
    return data if isinstance(data, list) else [data]


st.title("🛡️ Threat Hunting & Attack Investigation Lab")
st.caption(
    "Python-first security analytics | Event correlation | "
    "Investigation support, not proof of compromise"
)

st.sidebar.header("Data Source")
data_mode = st.sidebar.radio(
    "Choose telemetry",
    ["Synthetic Lab Data", "Real Windows Telemetry"],
)

if data_mode == "Synthetic Lab Data":
    data_file = SYNTHETIC_FILE
    st.info(
        "Synthetic mode: these are fictional lab events used to validate "
        "detection rules. Findings are investigation leads, not proof "
        "of compromise."
    )
else:
    data_file = WINDOWS_FILE
    st.warning(
        "Windows mode: events were collected from this lab machine's "
        "Windows Security log. This dataset currently contains process "
        "creation events only. Command-line fields were empty in the "
        "collected batch, so command-line-based detections cannot be "
        "validated from these events. A detection is not proof of compromise."
    )

if not data_file.exists():
    st.error(f"Telemetry file not found: {data_file.name}")
    st.stop()

events = load_json_events(
    data_file,
    data_file.stat().st_mtime,
)

if not events:
    st.warning("The selected telemetry file contains no events.")
    st.stop()

findings = detect_threats(events)
timeline = build_timeline(events, findings)

events_df = pd.DataFrame(timeline)
findings_df = pd.DataFrame(findings)

# Ensure expected fields exist for consistent display across data sources.
event_columns = [
    "timestamp", "event_id", "host", "username", "source_ip",
    "event_type", "details", "detection_rules",
]
for column in event_columns:
    if column not in events_df.columns:
        events_df[column] = ""

if "severity" not in findings_df.columns:
    findings_df["severity"] = pd.Series(dtype="object")

# Summary metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Events Analyzed", len(events))

with col2:
    st.metric("Detections", len(findings))

with col3:
    high_count = sum(
        finding.get("severity") == "HIGH" for finding in findings
    )
    st.metric("High Severity", high_count)

with col4:
    st.metric("Hosts Observed", events_df["host"].nunique())

st.divider()

# Sidebar filters
st.sidebar.header("Hunt Filters")

hosts = sorted(events_df["host"].dropna().astype(str).unique().tolist())
users = sorted(events_df["username"].dropna().astype(str).unique().tolist())
event_types = sorted(
    events_df["event_type"].dropna().astype(str).unique().tolist()
)

selected_hosts = st.sidebar.multiselect("Host", hosts, default=hosts)
selected_users = st.sidebar.multiselect("Username", users, default=users)
selected_event_types = st.sidebar.multiselect(
    "Event Type", event_types, default=event_types
)

severity_options = sorted(
    findings_df["severity"].dropna().astype(str).unique().tolist()
)

selected_severities = st.sidebar.multiselect(
    "Detection Severity",
    severity_options,
    default=severity_options,
)

filtered_events = events_df[
    events_df["host"].astype(str).isin(selected_hosts)
    & events_df["username"].astype(str).isin(selected_users)
    & events_df["event_type"].astype(str).isin(selected_event_types)
].copy()

filtered_event_ids = set(filtered_events["event_id"].astype(str).tolist())

filtered_findings = [
    finding for finding in findings
    if finding.get("severity", "") in selected_severities
    and any(
        str(event_id) in filtered_event_ids
        for event_id in finding.get("event_ids", [])
    )
]
findings_view = pd.DataFrame(filtered_findings)

# Main dashboard sections
overview_tab, alerts_tab, timeline_tab, hunt_tab = st.tabs(
    ["Overview", "Detections", "Investigation Timeline", "Hunt Data"]
)

with overview_tab:
    st.subheader("Event Activity by Type")

    if filtered_events.empty:
        st.warning("No events match the selected filters.")
    else:
        event_counts = (
            filtered_events["event_type"]
            .value_counts()
            .rename_axis("Event Type")
            .reset_index(name="Count")
        )
        st.bar_chart(event_counts.set_index("Event Type"), y="Count")

    st.subheader("Filtered Security Events")
    st.dataframe(
        filtered_events[event_columns],
        use_container_width=True,
        hide_index=True,
    )

with alerts_tab:
    st.subheader("Detection Findings")

    if findings_view.empty:
        st.success("No detections match the selected filters.")
    else:
        alert_columns = [
            "rule_id", "title", "severity", "category", "host",
            "username", "source_ip", "description", "recommendation",
        ]
        for column in alert_columns:
            if column not in findings_view.columns:
                findings_view[column] = ""
        st.dataframe(
            findings_view[alert_columns],
            use_container_width=True,
            hide_index=True,
        )
        st.download_button(
            "Download findings as CSV",
            data=findings_view.to_csv(index=False).encode("utf-8"),
            file_name="threat_hunting_findings.csv",
            mime="text/csv",
        )

    st.caption(
        "Severity indicates investigation priority; it does not establish "
        "that an event is malicious."
    )

with timeline_tab:
    st.subheader("Chronological Investigation Timeline")
    if filtered_events.empty:
        st.warning("No timeline events match the selected filters.")
    else:
        st.dataframe(
            filtered_events[
                [
                    "timestamp", "event_id", "host", "username",
                    "event_type", "details", "detection_rules",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

with hunt_tab:
    st.subheader("Hunt Data and Evidence")
    if filtered_events.empty:
        st.warning("No events match the selected filters.")
    else:
        st.write(
            "Review individual events and their associated detection rules."
        )
        selected_event_id = st.selectbox(
            "Select an event",
            filtered_events["event_id"].astype(str).tolist(),
        )
        selected_event = next(
            event for event in timeline
            if str(event["event_id"]) == selected_event_id
        )
        st.json(selected_event)

    st.subheader("Detection Rule Summary")
    if findings_view.empty:
        st.write("No detection rules matched the current filters.")
    else:
        st.dataframe(
            findings_view[["rule_id", "title", "severity", "category"]],
            use_container_width=True,
            hide_index=True,
        )

st.divider()
st.caption(
    "Project 7 | Threat Hunting & Attack Investigation Lab | "
    "No live response actions are performed."
)
