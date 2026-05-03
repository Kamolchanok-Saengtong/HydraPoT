"""
dashboard.py — HydraPot Live Dashboard
Pages: Live Monitor | Session Explorer

Usage:
    pip install streamlit plotly pandas
    streamlit run dashboard.py
"""

import json
import os
import time
from collections import defaultdict
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

CSS = """

<style>

/* 🌼 pastel yellow background */

[data-testid="stAppViewContainer"] {

    background-color: #fff9db !important;

}

/* sidebar slightly different tone (optional but nice) */

[data-testid="stSidebar"] {

    background-color: #fff3bf !important;

}

/* optional: make main content card feel softer */

.block-container {

    padding-top: 2rem;

}

</style>

"""
LOG_FILE      = "session_log.json"
REFRESH_SEC   = 3
AUTO_REFRESH  = True

FI_LABEL = {
    0: "Read/Display",
    1: "Create/Install",
    2: "Modify/Navigate",
    3: "Service/Elevate",
    4: "High Impact",
}

FI_COLOR = {
    0: "#6c757d",
    1: "#0d6efd",
    2: "#ffc107",
    3: "#fd7e14",
    4: "#dc3545",
}

AGENT_COLOR = {
    "cowrie":    "#28a745",
    "on_device": "#ffc107",
    "cloud":     "#dc3545",
    "unknown":   "#6c757d",
}

THREAT_LEVEL = {
    0: ("LOW",      "#28a745", "🟢"),
    1: ("LOW",      "#28a745", "🟢"),
    2: ("MEDIUM",   "#ffc107", "🟡"),
    3: ("HIGH",     "#fd7e14", "🟠"),
    4: ("CRITICAL", "#dc3545", "🔴"),
}

# ── Data loader ────────────────────────────────────────────────────────────────

@st.cache_data(ttl=REFRESH_SEC)
def load_log() -> list[dict]:
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def to_df(entries: list[dict]) -> pd.DataFrame:
    if not entries:
        return pd.DataFrame()
    df = pd.DataFrame(entries)
    df["fi_score"]   = df.get("fi_score",   pd.Series([0]*len(df))).fillna(0).astype(int)
    df["latency_ms"] = df.get("latency_ms", pd.Series([0]*len(df))).fillna(0).astype(float)
    df["agent"]      = df.get("agent",      pd.Series(["unknown"]*len(df))).fillna("unknown")
    df["session_id"] = df.get("session_id", pd.Series(["default"]*len(df))).fillna("default")
    df["timestamp"]  = pd.to_datetime(df.get("timestamp", pd.Series([""]*len(df))), errors="coerce")
    return df

# ── Page setup ─────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="HydraPot Dashboard",
    page_icon="🪤",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Sidebar ────────────────────────────────────────────────────────────────────

LOGO_PATH = "/mnt/data-partition/honeypot/hydrapot_logo_icon.svg"

with st.sidebar:
    st.markdown("<h1 style='font-size:40px; margin-bottom: 0;'>What is HydraPoT?</h1>", unsafe_allow_html=True)

    # logo just below the title
    if os.path.exists(LOGO_PATH):
        with open(LOGO_PATH) as f:
            svg = f.read()
        st.markdown(
            f"<div style='margin: 8px 0 16px 0; max-width: 100%;'>{svg}</div>",
            unsafe_allow_html=True,
        )

    st.markdown("An Intelligent Honeypot Framework Using Large Language Models (LLM) for Interactive Attack Analysis")
    st.markdown("Created by Kamolchanok Saengtong")
    st.divider()
    page = st.radio("Navigate", ["Live Monitor", "Session Explorer"], label_visibility="collapsed")
    st.divider()
    auto = st.toggle("Auto-refresh", value=True)
    st.caption(f"Reads: `{LOG_FILE}`")
    if st.button("🔄 Refresh Now"):
        st.cache_data.clear()
        st.rerun()

# ── Load data ──────────────────────────────────────────────────────────────────

entries = load_log()
df      = to_df(entries)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE 1 — LIVE MONITOR
# ══════════════════════════════════════════════════════════════════════════════

if page == "Live Monitor":
    st.title("Live Monitor")

    if df.empty:
        st.info("No session data yet. Start the honeypot and wait for connections.")
        if auto:
            time.sleep(REFRESH_SEC)
            st.rerun()
        st.stop()

    # ── Threat level (based on latest 10 commands) ─────────────────────────
    recent     = df.tail(10)
    peak_fi    = int(recent["fi_score"].max()) if not recent.empty else 0
    t_label, t_color, t_icon = THREAT_LEVEL[peak_fi]

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""<div style='background:{t_color}22; border:2px solid {t_color};
            border-radius:12px; padding:16px; text-align:center'>
            <div style='font-size:2.2rem'>{t_icon}</div>
            <div style='font-size:1.4rem; font-weight:700; color:{t_color}'>{t_label}</div>
            <div style='font-size:0.8rem; color:#888'>Threat Level</div>
            </div>""",
            unsafe_allow_html=True,
        )

    with col2:
        st.metric("Total Commands", len(df))

    with col3:
        impactful = int((df["fi_score"] >= 2).sum())
        st.metric("Impactful (FI≥2)", impactful)

    with col4:
        sessions = df["session_id"].nunique()
        st.metric("Sessions", sessions)

    st.divider()

    # ── Two columns: command feed + pie chart ──────────────────────────────
    left, right = st.columns([3, 2])

    with left:
        st.subheader("🖥️ Live Command Feed")
        feed = df.tail(15).iloc[::-1]   # latest first

        for _, row in feed.iterrows():
            fi    = int(row["fi_score"])
            color = FI_COLOR[fi]
            ac    = AGENT_COLOR.get(row["agent"], "#6c757d")
            ts    = row["timestamp"].strftime("%H:%M:%S") if pd.notna(row["timestamp"]) else ""
            resp  = str(row.get("response", ""))[:80].replace("\n", " ")

            st.markdown(
                f"""<div style='background:#1e1e1e; border-left:4px solid {color};
                border-radius:6px; padding:8px 12px; margin-bottom:6px; font-family:monospace'>
                <div style='display:flex; justify-content:space-between; margin-bottom:2px'>
                    <span style='color:{color}; font-size:0.75rem'>FI:{fi} {FI_LABEL[fi]}</span>
                    <span style='color:{ac}; font-size:0.75rem'>▶ {row["agent"]}</span>
                    <span style='color:#555; font-size:0.75rem'>{ts}</span>
                </div>
                <div style='color:#fff; font-size:0.9rem'>$ {row.get("cmd","")}</div>
                <div style='color:#888; font-size:0.78rem; margin-top:2px'>{resp}</div>
                </div>""",
                unsafe_allow_html=True,
            )

    with right:
        st.subheader("Agent Distribution")
        agent_counts = df["agent"].value_counts().reset_index()
        agent_counts.columns = ["agent", "count"]
        colors = [AGENT_COLOR.get(a, "#6c757d") for a in agent_counts["agent"]]

        fig_pie = px.pie(
            agent_counts,
            names="agent",
            values="count",
            color="agent",
            color_discrete_map=AGENT_COLOR,
            hole=0.4,
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#ccc",
            margin=dict(t=10, b=10, l=10, r=10),
            legend=dict(orientation="h", y=-0.1),
            showlegend=True,
        )
        fig_pie.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(fig_pie, use_container_width=True)

    st.divider()

    # ── FI score over time ─────────────────────────────────────────────────
    st.subheader("FI Score Over Time")
    time_df = df[df["timestamp"].notna()].copy()

    if not time_df.empty:
        fig_line = go.Figure()
        fig_line.add_trace(go.Scatter(
            x=time_df["timestamp"],
            y=time_df["fi_score"],
            mode="lines+markers",
            line=dict(color="#dc3545", width=2),
            marker=dict(
                size=8,
                color=time_df["fi_score"].map(FI_COLOR),
                line=dict(color="#fff", width=1),
            ),
            hovertemplate="<b>%{x}</b><br>FI: %{y}<br>Cmd: %{customdata}<extra></extra>",
            customdata=time_df["cmd"],
        ))

        # danger zone shading
        fig_line.add_hrect(y0=3, y1=4.5, fillcolor="#dc3545", opacity=0.08,
                           annotation_text="High Risk", annotation_position="right")
        fig_line.add_hrect(y0=2, y1=3,   fillcolor="#fd7e14", opacity=0.06,
                           annotation_text="Elevated",  annotation_position="right")

        fig_line.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#ccc",
            xaxis=dict(showgrid=False, color="#555"),
            yaxis=dict(showgrid=True, gridcolor="#333", range=[-0.2, 4.5],
                       tickvals=[0,1,2,3,4],
                       ticktext=["0 Read","1 Create","2 Modify","3 Elevate","4 Critical"]),
            margin=dict(t=10, b=10, l=10, r=80),
            height=280,
        )
        st.plotly_chart(fig_line, use_container_width=True)
    else:
        st.caption("No timestamp data available.")

    # ── Auto refresh ───────────────────────────────────────────────────────
    if auto and page == "Live Monitor":
        time.sleep(REFRESH_SEC)
        st.cache_data.clear()
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 2 — SESSION EXPLORER
# ══════════════════════════════════════════════════════════════════════════════

elif page == "Session Explorer":
    st.title("Session Explorer")

    if df.empty:
        st.info("No session data yet.")
        st.stop()

    # ── Session list ───────────────────────────────────────────────────────
    sessions = df.groupby("session_id").agg(
        commands   = ("cmd",      "count"),
        peak_fi    = ("fi_score", "max"),
        start_time = ("timestamp","min"),
        end_time   = ("timestamp","max"),
    ).reset_index().sort_values("start_time", ascending=False)

    st.subheader("All Sessions")

    # build display table with threat badge
    display = sessions.copy()
    display["threat"] = display["peak_fi"].map(lambda x: THREAT_LEVEL[int(x)][0])
    display["start_time"] = display["start_time"].dt.strftime("%Y-%m-%d %H:%M:%S")
    display["end_time"]   = display["end_time"].dt.strftime("%Y-%m-%d %H:%M:%S")
    display = display.rename(columns={
        "session_id": "Session ID",
        "commands":   "Commands",
        "peak_fi":    "Peak FI",
        "start_time": "Start",
        "end_time":   "End",
        "threat":     "Threat",
    })

    st.dataframe(
        display[["Session ID","Commands","Peak FI","Threat","Start","End"]],
        use_container_width=True,
        hide_index=True,
    )

    st.divider()

    # ── Session drill-down ─────────────────────────────────────────────────
    st.subheader("🔎 Drill Into Session")
    session_ids = sessions["session_id"].tolist()
    selected    = st.selectbox("Select session", session_ids)

    sdf = df[df["session_id"] == selected].copy()

    if sdf.empty:
        st.warning("No data for this session.")
        st.stop()

    # session stats
    c1, c2, c3, c4 = st.columns(4)
    peak = int(sdf["fi_score"].max())
    tl, tc, ti = THREAT_LEVEL[peak]
    c1.metric("Commands", len(sdf))
    c2.metric("Peak FI", f"{peak} — {FI_LABEL[peak]}")
    c3.metric("Threat", f"{ti} {tl}")
    c4.metric("Agents Used", sdf["agent"].nunique())

    st.divider()
    left2, right2 = st.columns([2, 3])

    # ── FI distribution bar chart ──────────────────────────────────────────
    with left2:
        st.subheader("FI Distribution")
        fi_counts = sdf["fi_score"].value_counts().reindex([0,1,2,3,4], fill_value=0).reset_index()
        fi_counts.columns = ["FI", "Count"]
        fi_counts["Label"] = fi_counts["FI"].map(FI_LABEL)
        fi_counts["Color"] = fi_counts["FI"].map(FI_COLOR)

        fig_bar = px.bar(
            fi_counts,
            x="Count",
            y="Label",
            orientation="h",
            color="FI",
            color_discrete_map={i: FI_COLOR[i] for i in range(5)},
            text="Count",
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#ccc",
            showlegend=False,
            margin=dict(t=10, b=10, l=10, r=10),
            height=260,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=False, title=""),
        )
        fig_bar.update_traces(textposition="outside")
        st.plotly_chart(fig_bar, use_container_width=True)

    # ── Top dangerous commands ─────────────────────────────────────────────
    with right2:
        st.subheader("⚠️ Top Dangerous Commands")
        dangerous = sdf[sdf["fi_score"] >= 2].sort_values("fi_score", ascending=False).head(8)

        if dangerous.empty:
            st.caption("No dangerous commands (FI≥2) in this session.")
        else:
            for _, row in dangerous.iterrows():
                fi    = int(row["fi_score"])
                color = FI_COLOR[fi]
                ac    = AGENT_COLOR.get(row["agent"], "#6c757d")
                lat   = f"{row['latency_ms']:.0f}ms" if row.get("latency_ms") else "—"

                st.markdown(
                    f"""<div style='background:#1e1e1e; border-left:4px solid {color};
                    border-radius:6px; padding:8px 12px; margin-bottom:6px; font-family:monospace'>
                    <div style='display:flex; justify-content:space-between'>
                        <span style='color:{color}; font-size:0.75rem'>FI:{fi} {FI_LABEL[fi]}</span>
                        <span style='color:{ac}; font-size:0.75rem'>▶ {row["agent"]}</span>
                        <span style='color:#555; font-size:0.75rem'>{lat}</span>
                    </div>
                    <div style='color:#fff; font-size:0.9rem; margin-top:3px'>$ {row.get("cmd","")}</div>
                    </div>""",
                    unsafe_allow_html=True,
                )

    st.divider()

    # ── Full command history ───────────────────────────────────────────────
    st.subheader("📜 Full Command History")
    history = sdf[["timestamp","cmd","agent","fi_score","latency_ms","response"]].copy()
    history["timestamp"]  = history["timestamp"].dt.strftime("%H:%M:%S")
    history["fi_score"]   = history["fi_score"].map(lambda x: f"{x} — {FI_LABEL[int(x)]}")
    history["latency_ms"] = history["latency_ms"].map(lambda x: f"{x:.0f}ms")
    history["response"]   = history["response"].astype(str).str[:60] + "..."

    st.dataframe(
        history.rename(columns={
            "timestamp":  "Time",
            "cmd":        "Command",
            "agent":      "Agent",
            "fi_score":   "FI",
            "latency_ms": "Latency",
            "response":   "Response (preview)",
        }),
        use_container_width=True,
        hide_index=True,
    )