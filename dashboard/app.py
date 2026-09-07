"""AgentShield live dashboard - reads DynamoDB directly via boto3.
Run with: streamlit run dashboard/app.py
"""
import boto3
import pandas as pd
import streamlit as st

LOGS_TABLE = "AgentShieldLogs"
SESSIONS_TABLE = "AgentShieldSessions"

st.set_page_config(page_title="AgentShield", layout="wide")
st.title("AgentShield — live containment feed")

refresh_seconds = st.sidebar.slider("Auto-refresh (seconds)", 2, 30, 5)
st.sidebar.caption("Reads AgentShieldLogs / AgentShieldSessions directly from DynamoDB.")


@st.cache_resource
def get_dynamodb():
    return boto3.resource("dynamodb")


def scan_all(table, **kwargs) -> list:
    items = []
    while True:
        response = table.scan(**kwargs)
        items.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            break
        kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
    return items


dynamodb = get_dynamodb()
logs = scan_all(dynamodb.Table(LOGS_TABLE))
sessions = scan_all(dynamodb.Table(SESSIONS_TABLE))

frozen_sessions = {item["session_id"] for item in sessions if item.get("frozen")}

col1, col2, col3 = st.columns(3)
col1.metric("Total actions logged", len(logs))
col2.metric("Denied", sum(1 for item in logs if item.get("decision") == "denied"))
col3.metric("Frozen sessions", len(frozen_sessions))

st.subheader("Session status")
if sessions:
    session_df = pd.DataFrame(sessions).rename(columns={"frozen": "frozen"})
    st.dataframe(session_df, use_container_width=True)
else:
    st.caption("No sessions have been frozen yet.")

st.subheader("Action feed")
if logs:
    df = pd.DataFrame(logs).sort_values("timestamp", ascending=False)

    def highlight_denied(row):
        color = "background-color: #4a1414" if row["decision"] == "denied" else ""
        return [color] * len(row)

    st.dataframe(df.style.apply(highlight_denied, axis=1), use_container_width=True)
else:
    st.caption("No actions logged yet - run scripts/run_scenario.py to generate some.")

st.caption(f"Auto-refreshing every {refresh_seconds}s.")
st.markdown(f'<meta http-equiv="refresh" content="{refresh_seconds}">', unsafe_allow_html=True)
