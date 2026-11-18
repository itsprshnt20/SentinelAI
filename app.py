
"""Sentinel-SOC Streamlit interface."""
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

import streamlit as st

from triage import InputError, STATUSES, Settings, detect, export_incident, parse_csv, summarize, utc

DEMO = Path(__file__).resolve().parent / "samples" / "synthetic_logins.csv"


def ingest(raw, label):
    try:
        events, rejected = parse_csv(raw)
    except InputError as exc:
        st.session_state.dataset = None
        st.session_state.input_error = str(exc)
        return
    st.session_state.dataset = (sha256(raw).hexdigest(), label, events, rejected)
    st.session_state.input_error = None


def queue(alerts, statuses):
    entries = []
    for alert in alerts:
        trigger = alert.failures[-1]
        entries.append({
            "User": trigger.user,
            "Source IP": trigger.source_ip,
            "Triggered (UTC)": utc(trigger.timestamp),
            "Failures": len(alert.failures),
            "Correlation": "Success linked" if alert.success else "No linked success",
            "Status": statuses.get(alert.id, "Open"),
        })
    return entries


def review(incident, settings, statuses, dataset_id):
    first = incident.failures[0]
    st.subheader("Incident detail")
    st.text(f"User: {first.user}  |  Source IP: {first.source_ip}")
    st.caption(f"{settings.threshold} failures / {settings.failure_minutes} min · "
               f"success correlation / {settings.success_minutes} min")
    status_key = f"status_{dataset_id}_{incident.id}"
    if status_key not in st.session_state:
        st.session_state[status_key] = statuses.get(incident.id, "Open")

    def persist_status():
        statuses[incident.id] = st.session_state[status_key]

    status = st.selectbox("Incident status", STATUSES, index=None, key=status_key,
                          on_change=persist_status)
    st.subheader("Evidence timeline")
    st.dataframe([{"Source row": event.row, "Timestamp (UTC)": utc(event.timestamp),
                   "User": event.user, "Source IP": event.source_ip, "Outcome": event.outcome}
                  for event in incident.events], hide_index=True, use_container_width=True)
    st.subheader("Triage summary")
    st.caption("Local evidence template")
    for heading, items in summarize(incident).items():
        st.markdown(f"**{heading}**")
        for item in items:
            st.text(item)
    st.download_button("Download incident JSON", export_incident(incident, settings, status),
                       f"sentinel-{incident.id[:12]}.json", "application/json", on_click="ignore")


st.set_page_config(page_title="Sentinel-SOC", layout="wide")
st.html("""
<style>
.stMainBlockContainer { max-width: 72rem; padding-top: 3.5rem; }
.st-key-intro { border-left: 3px solid #82D8D2; padding-left: 1.2rem; }
.st-key-intro h1 { letter-spacing: -.04em; font-size: clamp(2.4rem, 6vw, 4rem); }
[data-testid="stMetric"] { background: #172331; border-radius: .75rem; padding: .75rem 1rem; }
</style>
""")
with st.container(key="intro"):
    st.title("Sentinel-SOC")
    st.write("Review repeated login failures, inspect matched evidence, and track incident status.")
    st.caption("Maintained by Prashant Chauhan")

left, right = st.columns([1, 1])
with left:
    st.subheader("Login data")
    if st.button("Load synthetic demo", type="primary"):
        with st.spinner("Loading synthetic login records…"):
            ingest(DEMO.read_bytes(), "Synthetic demo")
    with st.form("import"):
        uploaded = st.file_uploader("Upload login CSV (up to 2 MiB)", type=["csv"])
        if st.form_submit_button("Analyze CSV"):
            if not uploaded:
                st.warning("Choose a CSV before selecting Analyze CSV.")
            elif not uploaded.name.lower().endswith(".csv"):
                st.error("Choose a file with a .csv extension.")
            else:
                with st.spinner("Validating CSV…"):
                    ingest(uploaded.getvalue(), "Uploaded CSV")
with right:
    st.subheader("Detection settings")
    settings = Settings(
        st.number_input("Failure threshold", min_value=2, max_value=100, value=3),
        st.number_input("Failure window (minutes)", min_value=1, max_value=1440, value=10),
        st.number_input("Success correlation window (minutes)", min_value=1, max_value=1440, value=15),
    )
    st.caption("Rolling failure window and first subsequent success for the same user and IP.")

if st.session_state.get("input_error"):
    st.error(st.session_state.input_error)
elif not st.session_state.get("dataset"):
    st.info("Load the synthetic demo or upload a login CSV to populate the alert queue.")
else:
    dataset_id, label, events, rejected = st.session_state.dataset
    detection_key = (dataset_id, settings)
    if st.session_state.get("detection_key") != detection_key:
        with st.spinner("Matching login events…"):
            st.session_state.alerts = detect(events, settings)
            st.session_state.detection_key = detection_key
    alerts = st.session_state.alerts
    st.divider()
    st.caption(label)
    columns = st.columns(3)
    columns[0].metric("Valid events", len(events))
    columns[1].metric("Rejected records", len(rejected))
    columns[2].metric("Alerts", len(alerts))
    if rejected:
        st.warning("Some records could not be analyzed. Review their source rows below.")
        with st.expander("Rejected records", expanded=True):
            st.dataframe([asdict(row) for row in rejected], hide_index=True, use_container_width=True)
    st.subheader("Alert queue")
    if not alerts:
        st.info("No alert met the current settings.")
    else:
        statuses = st.session_state.setdefault("statuses", {}).setdefault(dataset_id, {})
        lookup = {alert.id: alert for alert in alerts}

        def option(alert_id):
            alert = lookup[alert_id]
            trigger = alert.failures[-1]
            correlation = "Success linked" if alert.success else "No linked success"
            return f"{trigger.user} / {trigger.source_ip} / {correlation} / row {trigger.row}"

        selected = st.selectbox("Select incident", list(lookup), format_func=option)
        st.dataframe(queue(alerts, statuses), hide_index=True, use_container_width=True)
        review(lookup[selected], settings, statuses, dataset_id)
