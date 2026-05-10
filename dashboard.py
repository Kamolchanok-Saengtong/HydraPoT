"""
dashboard.py — HydraPot SIEM Dashboard
Layout: live terminal | metric cards | world map | events over time | summary table

pip install streamlit plotly pandas geoip2
"""

import json
import os
import time
from datetime import datetime, timedelta
from collections import defaultdict

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ── GeoIP ─────────────────────────────────────────────────────────────────────

MMDB_PATH = "/mnt/data-partition/honeypot/geoip.mmdb"

@st.cache_resource
def _load_geo_reader():
    if not os.path.exists(MMDB_PATH):
        return None
    try:
        import geoip2.database
        return geoip2.database.Reader(MMDB_PATH)
    except Exception as e:
        print(f"[geo] failed: {e}")
        return None

_geo_cache: dict = {}

def geolocate(ip: str) -> dict | None:
    if not ip or ip in ("?", "127.0.0.1", "::1", ""):
        return None
    if ip in _geo_cache:
        return _geo_cache[ip]
    reader = _load_geo_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
        if r.location.latitude is None:
            _geo_cache[ip] = None
            return None
        result = {
            "lat":     r.location.latitude,
            "lon":     r.location.longitude,
            "country": r.country.name or "Unknown",
            "city":    r.city.name or "",
        }
        _geo_cache[ip] = result
        return result
    except Exception:
        _geo_cache[ip] = None
        return None

# ── Config ────────────────────────────────────────────────────────────────────

SESSION_DIR  = "data/logs/sessions"
AUTH_LOG     = "data/logs/auth_log.json"
REFRESH_SEC  = 10
LOGO_PATH    = "/mnt/data-partition/honeypot/production/logo.png"

FI_LABEL = {0:"Read/Display", 1:"Create/Install", 2:"Modify/Navigate",
            3:"Service/Elevate", 4:"High Impact"}
FI_COLOR = {0:"#6c757d", 1:"#0d6efd", 2:"#ffc107", 3:"#fd7e14", 4:"#dc3545"}
AGENT_COLOR = {"cowrie":"#28a745","on_device":"#ffc107","cloud":"#dc3545","unknown":"#6c757d"}
THREAT_LEVEL = {
    0:("LOW","#28a745","🟢"), 1:("LOW","#28a745","🟢"),
    2:("MEDIUM","#ffc107","🟡"), 3:("HIGH","#fd7e14","🟠"),
    4:("CRITICAL","#dc3545","🔴"),
}

# ── Data loader ───────────────────────────────────────────────────────────────

MAX_SESSION_FILES = 50

@st.cache_data(ttl=REFRESH_SEC)
def load_all() -> pd.DataFrame:
    if not os.path.exists(SESSION_DIR):
        return pd.DataFrame()
    rows = []
    files = sorted(
        (f for f in os.listdir(SESSION_DIR) if f.endswith(".json")),
        reverse=True
    )[:MAX_SESSION_FILES]
    for fname in files:
        try:
            with open(os.path.join(SESSION_DIR, fname)) as f:
                data = json.load(f)
            if isinstance(data, list):
                rows.extend(data)
            elif isinstance(data, dict):
                rows.append(data)
        except Exception:
            pass
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    df["fi_score"]   = df.get("fi_score",   0).fillna(0).astype(int)
    df["latency_ms"] = df.get("latency_ms", 0).fillna(0).astype(float)
    df["agent"]      = df.get("agent",      "unknown").fillna("unknown")
    df["session_id"] = df.get("session_id", "default").fillna("default")
    df["src_ip"]     = df.get("src_ip",     "?").fillna("?")
    df["timestamp"]  = pd.to_datetime(df.get("timestamp", ""), errors="coerce")
    return df

@st.cache_data(ttl=REFRESH_SEC)
def load_auth_log() -> list:
    if not os.path.exists(AUTH_LOG):
        return []
    try:
        with open(AUTH_LOG) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="HydraPoT",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme-aware CSS ───────────────────────────────────────────────────────────
# Uses Streamlit's built-in CSS variables so it adapts to light/dark automatically

st.markdown("""
<style>
/* ── Fix header spacing — push content below Streamlit toolbar ── */
.block-container {
    padding-top: 2rem !important;
    padding-bottom: 1rem !important;
}

/* ── Remove default Streamlit header bar background clash ── */
header[data-testid="stHeader"] {
    background: transparent !important;
}

/* ── Metric cards — theme-aware ── */
div[data-testid="metric-container"] {
    background: var(--secondary-background-color);
    border: 1px solid rgba(128,128,128,0.2);
    border-radius: 10px;
    padding: 16px;
}

/* ── Live terminal feed ── */
.terminal-feed {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px 16px;
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
    font-size: 0.78rem;
    line-height: 1.5;
    max-height: 280px;
    overflow-y: auto;
    color: #e6edf3;
}
.terminal-feed .term-header {
    color: #58a6ff;
    font-weight: 700;
    margin-bottom: 8px;
    font-size: 0.85rem;
}
.term-line {
    margin: 2px 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.term-time { color: #6e7681; }
.term-ip   { color: #f0883e; }
.term-cmd  { color: #e6edf3; }
.term-fi0  { color: #6c757d; }
.term-fi1  { color: #0d6efd; }
.term-fi2  { color: #ffc107; }
.term-fi3  { color: #fd7e14; }
.term-fi4  { color: #dc3545; font-weight: 700; }
.term-agent-cowrie    { color: #28a745; }
.term-agent-on_device { color: #ffc107; }
.term-agent-cloud     { color: #dc3545; }
.term-login { color: #28a745; }
.term-separator { color: #30363d; }

/* ── Section headers ── */
.section-header {
    font-size: 1.1rem;
    font-weight: 600;
    margin-top: 1rem;
    margin-bottom: 0.5rem;
}

/* ── Threat badge ── */
.threat-badge {
    border-radius: 10px;
    padding: 16px;
    text-align: center;
    margin-top: 4px;
}
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    if os.path.exists(LOGO_PATH):
        try:
            with open(LOGO_PATH) as f:
                st.markdown(f"<div style='max-width:100%'>{f.read()}</div>", unsafe_allow_html=True)
        except Exception:
            pass
    st.markdown("## HydraPoT")
    st.caption("An Intelligent Honeypot Framework Using Large Language Models (LLM) for Interactive Attack Analysis")
    st.divider()
    page = st.radio("View", ["Summary", "Session Explorer"], label_visibility="collapsed")
    st.divider()
    auto = st.toggle("Auto-refresh", value=True)
    st.caption(f"Source: `{SESSION_DIR}`")
    if st.button("🔄 Refresh"):
        st.cache_data.clear()
        st.rerun()
    if os.path.exists(MMDB_PATH):
        st.success("🌍 GeoIP ready")
    else:
        st.warning("⚠️ geoip.mmdb not found")

# ── Load ──────────────────────────────────────────────────────────────────────

df = load_all()
auth_entries = load_auth_log()

# ══════════════════════════════════════════════════════════════════════════════
# PAGE 1 — SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

if page == "Summary":
    st.markdown("### 🍯 HydraPoT Dashboard")

    if df.empty:
        st.info("No data yet. Start the honeypot with `hp run`.")
        if auto:
            time.sleep(REFRESH_SEC); st.rerun()
        st.stop()

    # ── Live Terminal Feed ────────────────────────────────────────────────
    recent = df[df["timestamp"].notna()].sort_values("timestamp", ascending=False).head(30)

    terminal_lines = []
    # show recent auth attempts first
    for entry in auth_entries[-5:]:
        ts = entry.get("timestamp", "")
        ip = entry.get("src_ip", "?")
        auth_type = entry.get("auth_type", "")

        if auth_type == "tcp_connect":
            terminal_lines.append(
                f'<div class="term-line">'
                f'<span class="term-time">[{ts}]</span> '
                f'<span class="term-fi3">SCAN</span> '
                f'<span class="term-ip">{ip}</span> '
                f'<span class="term-cmd">TCP connection (port probe)</span>'
                f'</div>'
            )
        else:
            user = entry.get("username", "?")
            pw = entry.get("password", "?")
            terminal_lines.append(
                f'<div class="term-line">'
                f'<span class="term-time">[{ts}]</span> '
                f'<span class="term-login">LOGIN</span> '
                f'<span class="term-ip">{ip}</span> '
                f'<span class="term-cmd">{user}:{pw}</span>'
                f'</div>'
            )

    if terminal_lines and not recent.empty:
        terminal_lines.append('<div class="term-line"><span class="term-separator">────────────────────────────────────────────</span></div>')

    # show recent commands
    for _, row in recent.iterrows():
        ts = row["timestamp"].strftime("%H:%M:%S") if pd.notna(row["timestamp"]) else "??:??:??"
        ip = row.get("src_ip", "?")
        cmd = str(row.get("cmd", ""))[:80]
        fi = int(row.get("fi_score", 0))
        agent = row.get("agent", "unknown")

        fi_class = f"term-fi{fi}"
        agent_class = f"term-agent-{agent}"

        terminal_lines.append(
            f'<div class="term-line">'
            f'<span class="term-time">[{ts}]</span> '
            f'<span class="term-ip">{ip}</span> '
            f'<span class="{fi_class}">FI:{fi}</span> '
            f'<span class="{agent_class}">[{agent}]</span> '
            f'<span class="term-cmd">$ {cmd}</span>'
            f'</div>'
        )

    if terminal_lines:
        feed_html = (
            '<div class="terminal-feed">'
            '<div class="term-header">▶ Live Session Feed</div>'
            + "\n".join(terminal_lines)
            + '</div>'
        )
        st.markdown(feed_html, unsafe_allow_html=True)
        st.markdown("")  # spacer

    # ── Top metric cards ─────────────────────────────────────────────────
    peak_fi = int(df["fi_score"].max()) if not df.empty else 0
    tl, tc, ti = THREAT_LEVEL[peak_fi]

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Commands",    len(df))
    c2.metric("Unique Sessions",   df["session_id"].nunique())
    c3.metric("Unique Attackers",  df["src_ip"].nunique())
    c4.metric("High Impact (FI≥3)", int((df["fi_score"] >= 3).sum()))
    c5.markdown(
        f"""<div class="threat-badge" style='background:{tc}22; border:1px solid {tc};'>
        <div style='font-size:2rem'>{ti}</div>
        <div style='font-weight:700; color:{tc}'>{tl}</div>
        <div style='font-size:0.75rem; opacity:0.7'>Peak Threat</div>
        </div>""", unsafe_allow_html=True,
    )

    st.divider()

    # ── Main layout: left=timeline+table, right=map ───────────────────────
    left, right = st.columns([3, 2])

    with left:
        st.markdown('<div class="section-header">Events Over Time</div>', unsafe_allow_html=True)
        tdf = df[df["timestamp"].notna()].copy()
        if not tdf.empty:
            tdf["bucket"] = tdf["timestamp"].dt.floor("30min")
            buckets = tdf.groupby("bucket").size().reset_index(name="count")
            fig_t = go.Figure()
            fig_t.add_trace(go.Scatter(
                x=buckets["bucket"], y=buckets["count"],
                fill="tozeroy", line=dict(color="#00d4aa", width=2),
                fillcolor="rgba(0,212,170,0.15)",
                hovertemplate="<b>%{x}</b><br>Events: %{y}<extra></extra>",
            ))
            fig_t.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#999", height=200, margin=dict(t=10,b=30,l=40,r=10),
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=True, gridcolor="rgba(128,128,128,0.15)"),
                xaxis_title="@timestamp per 30 minutes",
            )
            st.plotly_chart(fig_t, use_container_width=True)
        else:
            st.caption("No timestamp data.")

        st.markdown('<div class="section-header">Summary of Events</div>', unsafe_allow_html=True)
        summary_rows = []
        hi_fi = df[df["fi_score"] >= 2].copy()
        for fi in [4, 3, 2]:
            sub = hi_fi[hi_fi["fi_score"] == fi]
            if sub.empty:
                continue
            top = sub["cmd"].apply(lambda c: c.split()[0] if c else "").value_counts().head(5)
            for cmd_base, cnt in top.items():
                tl2, _, _ = THREAT_LEVEL[fi]
                summary_rows.append({
                    "Rule": f"FI-{fi}: {FI_LABEL[fi]} via `{cmd_base}`",
                    "Severity": tl2,
                    "Events": cnt,
                })
        if summary_rows:
            sdf2 = pd.DataFrame(summary_rows)
            def color_sev(val):
                colors = {"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745"}
                c = colors.get(val, "#6c757d")
                return f"color: {c}; font-weight: bold"
            st.dataframe(
                sdf2.style.map(color_sev, subset=["Severity"]),
                use_container_width=True, hide_index=True,
            )
        else:
            st.caption("No high-impact events yet.")

    with right:
        st.markdown('<div class="section-header">🌍 Attacker Origin Map</div>', unsafe_allow_html=True)

        ip_col = "public_ip" if "public_ip" in df.columns else "src_ip"
        unique_ips = df[ip_col].dropna().unique()
        geo_rows = []
        for ip in unique_ips:
            geo = geolocate(ip)
            if geo:
                count = int((df[ip_col] == ip).sum())
                geo_rows.append({
                    "ip": ip, "lat": geo["lat"], "lon": geo["lon"],
                    "country": geo["country"], "city": geo["city"],
                    "count": count,
                })

        if geo_rows:
            geo_df = pd.DataFrame(geo_rows)
            fig_map = px.scatter_geo(
                geo_df,
                lat="lat", lon="lon",
                size="count",
                color="count",
                hover_name="country",
                hover_data={"ip": True, "city": True, "count": True, "lat": False, "lon": False},
                color_continuous_scale=["#ffc107", "#fd7e14", "#dc3545"],
                size_max=40,
                projection="natural earth",
            )
            fig_map.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                geo=dict(
                    bgcolor="rgba(0,0,0,0)",
                    landcolor="#1c2333",
                    oceancolor="#0d1117",
                    showocean=True,
                    showland=True,
                    lakecolor="#0d1117",
                    coastlinecolor="#30363d",
                    countrycolor="#30363d",
                    showcoastlines=True,
                    showcountries=True,
                ),
                coloraxis_showscale=False,
                margin=dict(t=0, b=0, l=0, r=0),
                height=320,
            )
            st.plotly_chart(fig_map, use_container_width=True)

            st.markdown("**Top Attacker IPs**")
            ip_table = geo_df.sort_values("count", ascending=False).head(10)
            ip_table = ip_table[["ip","country","city","count"]].rename(columns={
                "ip":"IP","country":"Country","city":"City","count":"Events"
            })
            st.dataframe(ip_table, use_container_width=True, hide_index=True)

        else:
            fig_empty = go.Figure(go.Scattergeo())
            fig_empty.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                geo=dict(bgcolor="rgba(0,0,0,0)", landcolor="#1c2333",
                         showocean=True, oceancolor="#0d1117",
                         coastlinecolor="#30363d", showcountries=True,
                         countrycolor="#30363d"),
                height=320, margin=dict(t=0,b=0,l=0,r=0),
            )
            st.plotly_chart(fig_empty, use_container_width=True)
            if _load_geo_reader() is None:
                st.caption("⚠️ geoip.mmdb not found — map unavailable")
            else:
                st.caption("All connections from localhost — no geo data to plot")

        st.markdown('<div class="section-header">Agent Distribution</div>', unsafe_allow_html=True)
        ac = df["agent"].value_counts().reset_index()
        ac.columns = ["agent","count"]
        fig_donut = px.pie(
            ac, names="agent", values="count",
            color="agent", color_discrete_map=AGENT_COLOR, hole=0.55,
        )
        fig_donut.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", font_color="#999",
            margin=dict(t=10,b=10,l=10,r=10), height=220,
            legend=dict(orientation="v", x=1.0),
        )
        fig_donut.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(fig_donut, use_container_width=True)

    # Auto-refresh
    if auto:
        time.sleep(REFRESH_SEC)
        st.cache_data.clear()
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 2 — SESSION EXPLORER
# ══════════════════════════════════════════════════════════════════════════════

elif page == "Session Explorer":
    st.markdown("### 🔎 Session Explorer")

    if df.empty:
        st.info("No session data yet.")
        st.stop()

    sessions = df.groupby("session_id").agg(
        commands   = ("cmd",       "count"),
        peak_fi    = ("fi_score",  "max"),
        src_ip     = ("src_ip",    "first"),
        start_time = ("timestamp", "min"),
        end_time   = ("timestamp", "max"),
    ).reset_index().sort_values("start_time", ascending=False)

    sessions["threat"]     = sessions["peak_fi"].map(lambda x: THREAT_LEVEL[int(x)][0])
    sessions["start_time"] = sessions["start_time"].dt.strftime("%Y-%m-%d %H:%M:%S")

    st.dataframe(
        sessions.rename(columns={
            "session_id":"Session","commands":"Cmds",
            "peak_fi":"Peak FI","src_ip":"Src IP",
            "start_time":"Start","threat":"Threat",
        })[["Session","Src IP","Cmds","Peak FI","Threat","Start"]],
        use_container_width=True, hide_index=True,
    )

    st.divider()
    selected = st.selectbox("Drill into session", sessions["session_id"].tolist())
    sdf = df[df["session_id"] == selected].copy()

    if sdf.empty:
        st.stop()

    peak = int(sdf["fi_score"].max())
    tl, tc, ti = THREAT_LEVEL[peak]
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Commands", len(sdf))
    c2.metric("Peak FI",  f"{peak} — {FI_LABEL[peak]}")
    c3.metric("Threat",   f"{ti} {tl}")
    c4.metric("Agents",   sdf["agent"].nunique())

    st.divider()

    # ── Terminal replay for selected session ──────────────────────────────
    session_cmds = sdf.sort_values("timestamp")
    replay_lines = []
    for _, row in session_cmds.iterrows():
        ts = row["timestamp"].strftime("%H:%M:%S") if pd.notna(row["timestamp"]) else "??:??:??"
        cmd = str(row.get("cmd", ""))[:100]
        fi = int(row.get("fi_score", 0))
        agent = row.get("agent", "unknown")
        resp = str(row.get("response", ""))[:60].replace("<","&lt;").replace(">","&gt;")

        fi_class = f"term-fi{fi}"
        agent_class = f"term-agent-{agent}"

        replay_lines.append(
            f'<div class="term-line">'
            f'<span class="term-time">[{ts}]</span> '
            f'<span class="{fi_class}">FI:{fi}</span> '
            f'<span class="{agent_class}">[{agent}]</span> '
            f'<span class="term-cmd">$ {cmd}</span>'
            f'</div>'
        )
        if resp and resp.strip():
            short_resp = resp.replace("\n", " ")[:60]
            replay_lines.append(
                f'<div class="term-line">'
                f'<span class="term-time">       </span> '
                f'<span style="color:#8b949e">→ {short_resp}</span>'
                f'</div>'
            )

    replay_html = (
        '<div class="terminal-feed" style="max-height:350px">'
        f'<div class="term-header">▶ Session Replay — {selected}</div>'
        + "\n".join(replay_lines)
        + '</div>'
    )
    st.markdown(replay_html, unsafe_allow_html=True)
    st.markdown("")

    l2, r2 = st.columns([2, 3])

    with l2:
        st.markdown('<div class="section-header">FI Distribution</div>', unsafe_allow_html=True)
        fi_c = sdf["fi_score"].value_counts().reindex([0,1,2,3,4],fill_value=0).reset_index()
        fi_c.columns = ["FI","Count"]
        fi_c["Label"] = fi_c["FI"].map(FI_LABEL)
        fig_bar = px.bar(fi_c, x="Count", y="Label", orientation="h",
                         color="FI", color_discrete_map={i:FI_COLOR[i] for i in range(5)}, text="Count")
        fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font_color="#999", showlegend=False,
                              margin=dict(t=10,b=10,l=10,r=10), height=240,
                              xaxis=dict(showgrid=False), yaxis=dict(title=""))
        st.plotly_chart(fig_bar, use_container_width=True)

    with r2:
        st.markdown('<div class="section-header">⚠️ Dangerous Commands</div>', unsafe_allow_html=True)
        for _, row in sdf[sdf["fi_score"] >= 2].sort_values("fi_score", ascending=False).head(8).iterrows():
            fi = int(row["fi_score"])
            cmd_display = str(row.get("cmd","")).replace("<","&lt;").replace(">","&gt;")
            st.markdown(
                f"""<div style='background:var(--secondary-background-color);
                border-left:4px solid {FI_COLOR[fi]};
                border-radius:6px; padding:8px 12px; margin-bottom:5px; font-family:monospace'>
                <div style='display:flex;justify-content:space-between'>
                <span style='color:{FI_COLOR[fi]};font-size:0.75rem'>FI:{fi} {FI_LABEL[fi]}</span>
                <span style='color:{AGENT_COLOR.get(row["agent"],"#6c757d")};font-size:0.75rem'>▶ {row["agent"]}</span>
                </div>
                <div style='font-size:0.9rem'>$ {cmd_display}</div>
                </div>""", unsafe_allow_html=True,
            )

    st.divider()
    st.markdown('<div class="section-header">Full Command History</div>', unsafe_allow_html=True)
    hist = sdf[["timestamp","cmd","agent","fi_score","latency_ms","response"]].copy()
    hist["timestamp"]  = hist["timestamp"].dt.strftime("%H:%M:%S")
    hist["fi_score"]   = hist["fi_score"].map(lambda x: f"{x} {FI_LABEL[int(x)]}")
    hist["latency_ms"] = hist["latency_ms"].map(lambda x: f"{x:.0f}ms")
    hist["response"]   = hist["response"].astype(str).str[:80]
    st.dataframe(hist.rename(columns={"timestamp":"Time","cmd":"Command","agent":"Agent",
                                       "fi_score":"FI","latency_ms":"Latency","response":"Response"}),
                 use_container_width=True, hide_index=True)