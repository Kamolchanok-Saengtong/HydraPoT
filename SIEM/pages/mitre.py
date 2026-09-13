"""
SIEM/pages/mitre.py — MITRE ATT&CK page: coverage cards, top techniques,
attack chain analytics (Sankey/kill-chain flow/playbooks/session timeline).

Kept as ONE module per explicit instruction — this is the single biggest
page (kill-chain stages, Sankey, playbooks, session timeline, kill-chain
flow, drill-down sheet all live here) but it is one coherent concern (MITRE
ATT&CK visualization), not several.
"""
import collections

import pandas as pd
import plotly.graph_objects as go
from dash import html, dcc, dash_table, Input, Output, State, ctx, ALL, no_update
from dash.exceptions import PreventUpdate

import storage
from threat_intel.mitre_mapper import _load_catalog as _mitre_catalog

from SIEM.server import app
from SIEM.theme import theme_layout, GRAPH_CONFIG, TABLE_STYLE, INK, INK_3, PAPER, Y_50, LINE, AMBER_SCALE
from SIEM.data import load_all, _cached_page


def _technique_name(tid):
    """Technique ID -> display name, from the MITRE STIX-built catalog.

    Needed because the exploded chart groups on the bare ID; the scalar
    `technique` column belongs to the primary tag and would mislabel the rest
    of the chain.
    """
    return (_mitre_catalog().get(tid) or {}).get("name") or tid


# Kill-chain stages group MITRE's CURRENT tactic names (checked against the
# official STIX — several classic ones were renamed, e.g. there is no "Defense
# Evasion" any more, it's "Stealth"/"Defense Impairment"). Grouping on names
# that don't exist would render three empty columns.
MITRE_STAGES = [
    ("COMPROMISE",   ["Execution", "Persistence", "Privilege Escalation"],              "#7EB3C8"),
    ("INFILTRATION", ["Discovery", "Credential Access", "Lateral Movement"],            "#5B7FA6"),
    ("DATA LOSS",    ["Command And Control", "Impact", "Stealth", "Defense Impairment"], "#2F4A6B"),
]

# HydraPoT has no success/failure signal — it's a honeypot, every command
# "works" by design. Severity here is the FI band it already computes and
# defends in the evaluation, which is a real measured property rather than an
# invented outcome label.
SEV = [("High impact",   "high",   3, 4, "#C1443A"),
       ("State-changing", "medium", 1, 2, "#E07B39"),
       ("Reconnaissance", "low",    0, 0, "#AAAAAA")]


def _mitre_window(df, days):
    """Current window + the preceding window of equal length, for % change."""
    d = df[df["timestamp"].notna()]
    if d.empty:
        return d, d
    if not days:
        return d, d.iloc[0:0]
    end = d["timestamp"].max()
    start = end - pd.Timedelta(days=days)
    prev_start = start - pd.Timedelta(days=days)
    return d[d["timestamp"] > start], d[(d["timestamp"] > prev_start) & (d["timestamp"] <= start)]


def _stage_stats(cur, prev, tactics):
    s = cur[cur["tactic"].isin(tactics)]
    p = prev[prev["tactic"].isin(tactics)]
    counts = {key: int(((s["fi_score"] >= lo) & (s["fi_score"] <= hi)).sum())
              for _, key, lo, hi, _ in SEV}
    total, ptotal = len(s), len(p)
    pct = ((total - ptotal) / ptotal * 100) if ptotal else None
    return s, counts, total, pct


def _donut(counts, total, colors):
    vals = [counts[k] for _, k, _, _, _ in SEV]
    fig = go.Figure(go.Pie(
        values=vals or [1], hole=0.68, sort=False,
        marker=dict(colors=colors, line=dict(color=PAPER, width=2)),
        textinfo="none", hoverinfo="label+value",
        labels=[lbl for lbl, _, _, _, _ in SEV],
    ))
    fig.add_annotation(text=f"<b>{total:,}</b><br><span style='font-size:11px'>TOTAL</span>",
                       showarrow=False, font=dict(size=26, color=INK, family="Inter"))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
                      margin=dict(t=6, b=6, l=6, r=6), height=190)
    return fig


def _trend(sub, days=7):
    """Total vs high-impact per day over the last `days`."""
    fig = go.Figure()
    if not sub.empty:
        d = sub.copy()
        d["day"] = d["timestamp"].dt.floor("D")
        last = sorted(d["day"].unique())[-days:]
        d = d[d["day"].isin(last)]
        tot = d.groupby("day").size()
        hi = d[d["fi_score"] >= 3].groupby("day").size().reindex(tot.index, fill_value=0)
        lbl = [pd.Timestamp(x).strftime("%d %b") for x in tot.index]
        fig.add_trace(go.Scatter(x=lbl, y=tot.values, name="All", mode="lines+markers",
                                 line=dict(color="#AAAAAA", width=2), marker=dict(size=5)))
        fig.add_trace(go.Scatter(x=lbl, y=hi.values, name="High impact", mode="lines+markers",
                                 line=dict(color="#C1443A", width=2.5), marker=dict(size=5)))
    theme_layout(fig, height=140)
    fig.update_layout(margin=dict(t=6, b=4, l=4, r=4))
    return fig


def _pct_badge(pct):
    if pct is None:
        return html.Span("— no prior period", className="caption")
    if pct > 0:
        return html.Span(f"▲ {pct:+.0f}% vs previous", style={"color": "#C1443A", "fontWeight": 700})
    if pct < 0:
        return html.Span(f"▼ {pct:.0f}% vs previous", style={"color": "#1f7a3a", "fontWeight": 700})
    return html.Span("— unchanged", className="caption")


def _stage_card(name, tactics, color, cur, prev):
    sub, counts, total, pct = _stage_stats(cur, prev, tactics)
    return html.Div(className="stage-card", children=[
        html.Div(name, className="stage-head", style={"background": color}),
        html.Div(className="stage-body", children=[
            html.Div(className="stage-top", children=[
                html.Div([html.Div(t, className="stage-tactic") for t in tactics],
                         className="stage-tactics"),
                html.Div([
                    dcc.Graph(figure=_donut(counts, total, [c for *_, c in SEV]),
                              config=GRAPH_CONFIG),
                    # ring segments explained in place, so the donut reads on
                    # its own without scanning down to the badges
                    html.Div(className="donut-key", children=[
                        html.Span([html.Span(className="key-dot", style={"background": col}),
                                   short], className="key-item")
                        for short, col in (("High", "#C1443A"), ("State", "#E07B39"),
                                           ("Recon", "#AAAAAA"))
                    ]),
                    html.Div(_pct_badge(pct), style={"textAlign": "center", "fontSize": "0.76rem"}),
                ], style={"flex": "1"}),
            ]),
            html.Div(className="sev-row", children=[
                html.Div([html.Span(className="sev-dot", style={"background": col}),
                          html.Span(f"{counts[key]:,}", className="sev-n"),
                          html.Div(lbl, className="sev-lbl")], className="sev-badge")
                for lbl, key, _, _, col in SEV
            ]),
            dcc.Graph(figure=_trend(sub), config=GRAPH_CONFIG),
        ]),
    ])


def _top_table(rows, cols, widths=None, tooltip_col=None, row_padding="2px 6px"):
    """Sidebar list. maxWidth:0 + ellipsis is the dash idiom for "let the
    percentage widths win and clip overflow" — without it a long technique
    name ("Ingress Tool Transfer") pushes the Events column off the edge.
    The full value stays reachable on hover."""
    tips = None
    if tooltip_col:
        tips = [{tooltip_col: {"value": str(r[tooltip_col]), "type": "markdown"}} for r in rows]
    return dash_table.DataTable(
        data=rows, columns=[{"name": c, "id": c} for c in cols],
        style_data_conditional=[{"if": {"row_index": "odd"}, "backgroundColor": Y_50}],
        style_header={**TABLE_STYLE["style_header"], "fontSize": "10px", "padding": "4px 6px"},
        style_cell={
            "backgroundColor": PAPER, "color": INK_3,
            "fontFamily": "JetBrains Mono, monospace", "fontSize": "10.5px",
            "border": "none", "borderTop": f"1px solid {LINE}",
            "padding": row_padding, "textAlign": "left",
            "overflow": "hidden", "textOverflow": "ellipsis", "maxWidth": 0,
        },
        style_cell_conditional=widths or [],
        tooltip_data=tips, tooltip_duration=None,
        style_table={"overflowX": "hidden"},
    )


def build_mitre_body(days):
    df = load_all()
    if df.empty or "tactic" not in df.columns:
        return html.Div("No data yet.", className="empty-state")

    cur, prev = _mitre_window(df, days)
    tagged = cur[cur["tactic"].notna()]
    if tagged.empty:
        return html.Div("No ATT&CK-mapped commands in this period.", className="empty-state")

    top_ip = (tagged.groupby("src_ip").size().sort_values(ascending=False).head(10)
              .reset_index(name="Events").rename(columns={"src_ip": "Source IP"}))
    # Explode ONLY here. `tagged` keeps one row per command everywhere else, so
    # the coverage headline and the per-IP table below stay divided by commands;
    # this chart alone counts every technique in each command's chain.
    _exp = tagged.explode("technique_ids")
    _exp = _exp[_exp["technique_ids"].notna()]
    top_tech = (_exp.groupby("technique_ids").size()
                .sort_values(ascending=False).head(10).reset_index(name="Events")
                .rename(columns={"technique_ids": "ID"}))
    top_tech["Technique"] = top_tech["ID"].map(_technique_name)

    cov = f"{len(tagged):,} of {len(cur):,} commands mapped ({len(tagged)/max(len(cur),1)*100:.0f}%) · " \
          f"{tagged['technique_id'].nunique()} techniques · {tagged['tactic'].nunique()} tactics"

    # techniques render as a full-width horizontal bar chart below the cards:
    # long names get the whole page width instead of a 54%-of-330px column, so
    # nothing clips, and it fills the space the old sidebar entry left empty.
    tt = top_tech.sort_values("Events")
    fig_tech = go.Figure(go.Bar(
        x=tt["Events"], y=tt["ID"] + "  " + tt["Technique"], orientation="h",
        marker=dict(color=tt["Events"], colorscale=AMBER_SCALE,
                    line=dict(color=INK, width=1.2)),
        text=tt["Events"], textposition="outside",
        textfont=dict(size=11, family="JetBrains Mono, monospace"),
        hovertemplate="%{y}<br>%{x} events<extra></extra>",
    ))
    theme_layout(fig_tech, height=max(430, 46 * len(tt)))
    fig_tech.update_layout(coloraxis_showscale=False, margin=dict(t=8, b=8, l=8, r=48))
    fig_tech.update_yaxes(title="", tickfont=dict(size=11, family="JetBrains Mono, monospace"))
    fig_tech.update_xaxes(title="Commands")

    return html.Div([
        html.Div(cov, className="caption", style={"marginBottom": "8px"}),
        html.Div(className="mitre-grid", children=[
            html.Div(className="mitre-side", children=[
                html.Div("Top 10 Attacker Sources", className="side-head"),
                _top_table(top_ip.to_dict("records"), ["Source IP", "Events"],
                           widths=[{"if": {"column_id": "Source IP"}, "width": "68%"},
                                   {"if": {"column_id": "Events"}, "width": "32%",
                                    "textAlign": "right"}],
                           row_padding="9px 6px"),
            ]),
            html.Div(className="stage-grid", children=[
                _stage_card(n, t, c, tagged, prev[prev["tactic"].notna()])
                for n, t, c in MITRE_STAGES
            ]),
        ]),
        # full page width — spans the sidebar AND all three cards, no gap
        html.Div(className="stage-card tech-card", children=[
            html.Div("TOP 10 ATTACK TECHNIQUES", className="stage-head",
                     style={"background": "#5B7FA6"}),
            html.Div(dcc.Graph(figure=fig_tech, config=GRAPH_CONFIG,
                               style={"width": "100%"}),
                     className="stage-body"),
        ]),
        # Sequence views: how the attack unfolded, not just how much of it.
        *_attack_chain_section(days),
    ])



# ══════════════════════════════════════════════════════════════════════════════
# ATTACK CHAIN ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
# The panels above answer "how much". These answer "in what order". All three
# read the SAME per-session ordered sequence, so it is computed once per
# (window, cache generation) and memoised alongside the existing _cache TTL
# pattern used by load_all().
#
# Ordering key is `seq`, not `timestamp`: seq is the per-session monotonic
# counter storage.py assigns on insert (UNIQUE on instance+session_id+seq), so
# it is exact even when two commands share a timestamp to the second.

# Standard MITRE tactic order. Used for the timeline lanes so a session reads
# top-to-bottom the way the kill chain actually progresses.
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Stealth",
    "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

# Tactic -> colour, derived from MITRE_STAGES so the Sankey and timeline match
# the stage cards and donuts exactly. Keyed case-insensitively because
# MITRE_STAGES spells it "Command And Control" while the STIX-built catalog
# yields "Command and Control"; tactics in neither list fall back to ink.
TACTIC_COLOR = {t.lower(): c for _n, ts, c in MITRE_STAGES for t in ts}


def _tactic_color(tactic):
    return TACTIC_COLOR.get(str(tactic).lower(), INK_3)


def _tactic_rank(tactic):
    low = [t.lower() for t in TACTIC_ORDER]
    try:
        return low.index(str(tactic).lower())
    except ValueError:
        return len(low)


_chain_cache: dict = {}


def _session_chains(tagged):
    """-> {session_id: [ {seq,timestamp,tactic,technique_id,technique,fi,cmd}, ... ]}

    One time-ordered list per session, tagged rows only.
    """
    cols = ["session_id", "seq", "timestamp", "tactic", "technique_id",
            "technique", "fi_score", "src_ip", "cmd"]
    have = [c for c in cols if c in tagged.columns]
    d = tagged[have].sort_values(["session_id", "seq"])
    chains = {}
    for sid, grp in d.groupby("session_id", sort=False):
        chains[sid] = grp.to_dict("records")
    return chains


def _chain_analytics(days):
    """Transitions + n-grams + session index for the window. Memoised.

    Invalidated by the same generation counter as load_all()'s cache, so a
    refresh that reloads the dataframe also drops these.
    """
    from SIEM.data import _cache
    key = (days, _cache.get("all_ts"))
    hit = _chain_cache.get(key)
    if hit is not None:
        return hit

    df = load_all()
    empty = {"transitions": {}, "ngrams": {3: [], 4: []}, "chains": {},
             "sessions": [], "n_sessions": 0}
    if df.empty or "tactic" not in df.columns:
        _chain_cache[key] = empty
        return empty
    cur, _prev = _mitre_window(df, days)
    tagged = cur[cur["tactic"].notna()]
    if tagged.empty:
        _chain_cache[key] = empty
        return empty

    chains = _session_chains(tagged)

    # 1. tactic transitions, consecutive duplicates collapsed
    transitions = collections.Counter()
    for evs in chains.values():
        seq = []
        for e in evs:
            t = e.get("tactic")
            if t and (not seq or seq[-1] != t):
                seq.append(t)
        for a, b in zip(seq, seq[1:]):
            transitions[(a, b)] += 1

    # 2. technique n-grams. Consecutive duplicates collapsed here too, so a
    #    session that runs `ls` forty times does not manufacture a "playbook"
    #    of (T1083 -> T1083 -> T1083).
    ngrams = {}
    for n in (3, 4):
        counter = collections.Counter()
        sess_with = collections.defaultdict(set)
        for sid, evs in chains.items():
            tids = []
            for e in evs:
                t = e.get("technique_id")
                if t and (not tids or tids[-1] != t):
                    tids.append(t)
            for i in range(len(tids) - n + 1):
                g = tuple(tids[i:i + n])
                counter[g] += 1
                sess_with[g].add(sid)
        ngrams[n] = [(g, c, len(sess_with[g])) for g, c in counter.most_common(40)]

    sessions = sorted(chains.items(), key=lambda kv: -len(kv[1]))
    out = {"transitions": dict(transitions), "ngrams": ngrams, "chains": chains,
           "sessions": [(sid, len(evs)) for sid, evs in sessions],
           "n_sessions": len(chains)}
    _chain_cache[key] = out
    if len(_chain_cache) > 12:            # bounded; windows are few
        for k in list(_chain_cache)[:-12]:
            _chain_cache.pop(k, None)
    return out


def _sankey_fig(transitions, n_sessions=0):
    """Tactic A -> tactic B flow, laid out left-to-right in kill-chain order.

    Two things this has to work around:

    * CYCLES. Real sessions loop — Defense Impairment <-> Stealth runs 47 one
      way and 40 back. Plotly's Sankey has no cycle layout, so with automatic
      arrangement those ribbons overlap into a single opaque mass. Pinning
      node.x by MITRE tactic rank separates the columns so each ribbon is
      traceable, and back-edges read as visible right-to-left returns rather
      than disappearing into the pile.
    * ALPHA. Links inherit their SOURCE tactic colour at low alpha. Many
      ribbons stack in the same band, so alpha has to stay low or the overlap
      saturates back to opaque.
    """
    labels = sorted({t for pair in transitions for t in pair}, key=_tactic_rank)
    idx = {t: i for i, t in enumerate(labels)}

    # Pin x by kill-chain rank, normalised across the tactics actually present.
    # Plotly needs 0 < x < 1 strictly; exact 0/1 collapses a column onto the edge.
    ranks = [_tactic_rank(t) for t in labels]
    lo, hi = min(ranks), max(ranks)
    span = (hi - lo) or 1
    node_x = [0.03 + 0.94 * ((r - lo) / span) for r in ranks]
    # Spread nodes that share a column so their labels cannot collide.
    col = collections.defaultdict(list)
    for i, r in enumerate(ranks):
        col[r].append(i)
    node_y = [0.5] * len(labels)
    for _r, members in col.items():
        for k, i in enumerate(members):
            node_y[i] = (k + 1) / (len(members) + 1)

    src = [idx[a] for (a, _b) in transitions]
    dst = [idx[b] for (_a, b) in transitions]
    val = list(transitions.values())
    node_col = [_tactic_color(t) for t in labels]
    link_col = [_hex_alpha(_tactic_color(a), 0.30) for (a, _b) in transitions]
    denom = max(1, n_sessions)
    pct = [v / denom * 100 for v in val]

    fig = go.Figure(go.Sankey(
        arrangement="fixed",          # honour node.x / node.y exactly
        node=dict(label=labels, pad=26, thickness=22, x=node_x, y=node_y,
                  color=node_col, line=dict(color=INK, width=1.3),
                  hovertemplate="<b>%{label}</b><br>%{value} transitions"
                                "<extra></extra>"),
        link=dict(source=src, target=dst, value=val, color=link_col,
                  customdata=pct,
                  hovertemplate="<b>%{source.label} → %{target.label}</b>"
                                "<br>%{value} transitions"
                                "<br>%{customdata:.1f}% of sessions<extra></extra>"),
    ))
    theme_layout(fig, height=max(380, 34 * len(labels)))
    fig.update_layout(margin=dict(t=14, b=14, l=10, r=10),
                      font=dict(size=11, family="JetBrains Mono, monospace"))
    return fig


def _hex_alpha(hex_color, alpha):
    h = str(hex_color).lstrip("#")
    if len(h) != 6:
        return f"rgba(38,35,31,{alpha})"
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{alpha})"


def _playbook_rows(ngrams, n_sessions):
    """Top recurring technique sequences, n=3 then n=4, as table rows."""
    rows = []
    for n in (3, 4):
        for g, count, nsess in ngrams.get(n, [])[:6]:
            rows.append({
                "Sequence": " → ".join(g),
                "Count": count,
                "% sessions": f"{nsess / max(1, n_sessions) * 100:.0f}%",
            })
    rows.sort(key=lambda r: -r["Count"])
    return rows[:10]


def _session_timeline_fig(events):
    """Swimlane: x = time, y = tactic lane, one marker per event.

    Per-event technique labels are drawn only on sparse lanes. A busy session
    puts 321 of its 339 events on the Discovery lane; labelling every one turns
    that lane into an unreadable smear and, on the topmost lane, pushes text
    past the top of the plot where it clips. Dense lanes keep their markers and
    hover text and drop the printed label.
    """
    # A marker needs ~13px; a technique label like "T1059.004" needs ~65px. So
    # collision-free MARKERS do not imply collision-free LABELS, which is why
    # the Execution lane still printed "T1059T1059T1059.004" once the markers
    # were spread. Budget labels by the room the chart actually has rather than
    # by a per-lane count: at a typical panel width ~14 labels fit across, so a
    # label is only drawn when it is at least that many slots from the last one
    # drawn in its lane. Scales to any n — 8 events label every one, 300 events
    # label every 21st — with no per-case tuning.
    MAX_LABELS_ACROSS = 14

    # x is the event's POSITION IN THE SESSION, not its wall-clock time.
    #
    # Deriving x from the timestamp cannot be made collision-free. storage.py
    # records seconds, so events pile onto identical x values; and even with
    # distinct timestamps, whether two markers overlap depends on pixels-per-
    # second, which changes with the session's span and the panel's width.
    # Session 88cc4e0e3845 is the proof: 37 events over 4 distinct timestamps
    # inside 7 seconds, 29 of them on one lane -- no amount of sub-second
    # nudging fits those in a seventh of the plot.
    #
    # Integer positions are collision-free BY CONSTRUCTION for any n, any span,
    # any duplicate timestamps. This is a kill chain: the question it answers is
    # "in what order", and the exact clock time is still on every hover and on
    # the axis ticks below.
    order = sorted(range(len(events)),
                   key=lambda i: (events[i].get("timestamp"), i))
    xpos = {}
    for slot, i in enumerate(order):
        xpos[i] = slot
    events = [{**e, "_x": xpos[i], "_ts": e.get("timestamp")}
              for i, e in enumerate(events)]

    lanes = sorted({e["tactic"] for e in events if e.get("tactic")}, key=_tactic_rank)
    lane_y = {t: i for i, t in enumerate(lanes)}
    fig = go.Figure()
    label_gap = max(1, -(-len(events) // MAX_LABELS_ACROSS))
    for tactic in lanes:
        pts = [e for e in events if e.get("tactic") == tactic]
        # Keep a label only when it clears the last kept one by label_gap slots.
        labels, last = [], None
        for e in pts:
            if last is None or (e["_x"] - last) >= label_gap:
                labels.append(str(e.get("technique_id") or ""))
                last = e["_x"]
            else:
                labels.append("")
        dense = not any(labels)
        fig.add_trace(go.Scatter(
            x=[e["_x"] for e in pts],
            y=[lane_y[tactic]] * len(pts),
            mode="markers" if dense else "markers+text",
            text=labels,
            textposition="top center",
            textfont=dict(size=9, family="JetBrains Mono, monospace", color=INK_3),
            marker=dict(size=11 if dense else 13, color=_tactic_color(tactic),
                        opacity=0.75 if dense else 1.0,
                        line=dict(color=INK, width=1.2 if dense else 1.4),
                        symbol=["diamond" if int(e.get("fi_score") or 0) >= 3 else "circle"
                                for e in pts]),
            name=tactic, showlegend=False,
            customdata=[[str(e.get("technique") or ""), str(e.get("cmd") or "")[:90],
                         int(e.get("fi_score") or 0), str(e.get("technique_id") or ""),
                         (e["_ts"].strftime("%Y-%m-%d %H:%M:%S")
                          if e.get("_ts") is not None else "—")]
                        for e in pts],
            hovertemplate="<b>%{customdata[3]}</b> %{customdata[0]}"
                          "<br>%{customdata[4]}"
                          "<br>FI %{customdata[2]}"
                          "<br><span style='font-family:monospace'>%{customdata[1]}</span>"
                          "<extra></extra>",
        ))
    theme_layout(fig, height=max(260, 58 * len(lanes) + 110))
    # Top margin and the extra half-lane of headroom exist so "top center"
    # labels on the highest lane are not clipped by the plot edge.
    fig.update_layout(margin=dict(t=46, b=34, l=8, r=18))
    fig.update_yaxes(tickmode="array", tickvals=list(lane_y.values()),
                     ticktext=lanes, title="",
                     tickfont=dict(size=11, family="JetBrains Mono, monospace"),
                     range=[-0.75, len(lanes) - 1 + 0.75])
    # x is a sequence position, so the ticks must be relabelled with the real
    # clock time or the axis reads as meaningless integers. At most ~8 ticks,
    # evenly sampled, so a 300-event session does not stack its labels either.
    n = len(events)
    step = max(1, -(-n // 8))
    slots = list(range(0, n, step))
    by_slot = {e["_x"]: e for e in events}
    fig.update_xaxes(
        title="", type="linear",
        tickmode="array", tickvals=slots,
        ticktext=[(by_slot[i]["_ts"].strftime("%H:%M:%S")
                   if i in by_slot and by_slot[i].get("_ts") is not None else "")
                  for i in slots],
        tickfont=dict(size=10, family="JetBrains Mono, monospace"),
        range=[-0.8, max(n - 1, 1) + 0.8])
    return fig


def _session_meta(events):
    """Source IP / duration / event count / high-impact count strip."""
    ts = [e["timestamp"] for e in events if pd.notna(e.get("timestamp"))]
    dur = "—"
    if len(ts) >= 2:
        secs = (max(ts) - min(ts)).total_seconds()
        dur = f"{secs/60:.0f}m {secs%60:.0f}s" if secs >= 60 else f"{secs:.0f}s"
    high = sum(1 for e in events if int(e.get("fi_score") or 0) >= 3)
    ip = next((e.get("src_ip") for e in events if e.get("src_ip")), "—")
    items = [("SOURCE IP", str(ip)), ("DURATION", dur),
             ("MAPPED EVENTS", f"{len(events):,}"), ("HIGH IMPACT", f"{high:,}")]
    return html.Div(className="hp-tally", style={"marginBottom": "8px"}, children=[
        html.Div(className="hp-stat", children=[
            html.Div(lbl, className="hp-stat-l"),
            html.Div(val, className="hp-stat-v",
                     style={"color": "#C1443A"} if lbl == "HIGH IMPACT" and high else {}),
        ]) for lbl, val in items
    ])


def _attack_chain_section(days):
    """The three chain cards. Returns [] when the window has nothing to show."""
    a = _chain_analytics(days)
    if not a["chains"]:
        return []

    # ── Playbooks ────────────────────────────────────────────────────────────
    rows = _playbook_rows(a["ngrams"], a["n_sessions"])
    if rows:
        play_body = _top_table(rows, ["Sequence", "Count", "% sessions"],
                               widths=[{"if": {"column_id": "Sequence"}, "width": "62%"},
                                       {"if": {"column_id": "Count"}, "width": "18%",
                                        "textAlign": "right"},
                                       {"if": {"column_id": "% sessions"}, "width": "20%",
                                        "textAlign": "right"}],
                               row_padding="9px 6px")
    else:
        play_body = html.Div(
            "No repeated 3-technique sequence yet — sessions in this window are "
            "too short or too varied to form a playbook.", className="empty-state")

    # ── Session picker ───────────────────────────────────────────────────────
    opts = [{"label": f"{sid[:18]}  ·  {n} events", "value": sid}
            for sid, n in a["sessions"][:300]]
    default_sid = a["sessions"][0][0] if a["sessions"] else None

    return [
        # Kill-chain flow replaces the Sankey: same progression, read as
        # columns left-to-right instead of crossing ribbons.
        html.Div(className="stage-card tech-card", children=[
            html.Div("KILL CHAIN FLOW", className="stage-head",
                     style={"background": "#5B7FA6"}),
            html.Div(_killchain_flow(days), className="stage-body"),
        ]),
        html.Div(className="stage-card tech-card", children=[
            html.Div("TOP ATTACK PLAYBOOKS", className="stage-head",
                     style={"background": "#2F4A6B"}),
            html.Div(className="stage-body", children=[
                html.Div("Recurring 3- and 4-step technique sequences",
                         className="caption", style={"marginBottom": "6px"}),
                play_body,
            ]),
        ]),
        html.Div(className="stage-card tech-card", children=[
            html.Div("SESSION KILL CHAIN", className="stage-head",
                     style={"background": "#7EB3C8"}),
            html.Div(className="stage-body", children=[
                html.Div(className="chain-pick", children=[
                    html.Span("Session", className="caption"),
                    dcc.Dropdown(id="chain-session-dd", options=opts,
                                 value=default_sid, clearable=False,
                                 searchable=True, style={"minWidth": "320px"}),
                ]),
                dcc.Store(id="chain-days-store", data=days),
                html.Div(id="chain-timeline-body"),
            ]),
        ]),
        dcc.Store(id="kc-detail-store"),
        html.Div(id="kc-sheet", className="kc-sheet", children=[
            html.Button("✕", id="kc-close", n_clicks=0, className="kc-close",
                        **{"aria-label": "Close detail"}),
            html.Div(id="kc-sheet-body", className="kc-sheet-body"),
        ]),
    ]


@app.callback(
    Output("chain-timeline-body", "children"),
    Input("chain-session-dd", "value"),
    State("chain-days-store", "data"),
    prevent_initial_call=False,
)
def render_session_chain(session_id, days):
    """Timeline for one session. Reads the memoised chain index, so switching
    sessions never touches the database."""
    if not session_id:
        return html.Div("Select a session.", className="empty-state")
    a = _chain_analytics(days)
    events = a["chains"].get(session_id)
    if not events:
        return html.Div("That session has no ATT&CK-mapped events in this "
                        "period.", className="empty-state")
    return html.Div([
        _session_meta(events),
        dcc.Graph(figure=_session_timeline_fig(events), config=GRAPH_CONFIG,
                  style={"width": "100%"}),
        html.Div("◆ = high impact (FI ≥ 3)   ● = other mapped events",
                 className="caption", style={"marginTop": "2px"}),
    ])



# ══════════════════════════════════════════════════════════════════════════════
# KILL CHAIN FLOW
# ══════════════════════════════════════════════════════════════════════════════
# A linear left-to-right read of the attack, replacing the Sankey. The Sankey
# was accurate but unreadable: 14 of its 38 links were bidirectional, and
# Plotly has no cycle layout, so the ribbons piled into one mass. A column per
# tactic in kill-chain order says the same thing without any crossing lines.
#
# Everything here is real: tactics and techniques come from the mapper, counts
# from the DB, severity from the FI band main.py already computed. Nothing is
# simulated.

# FI band -> incident severity. FI_RULES in prompt/fi_manager.py is the source
# of the band, so this is a relabelling for the SOC vocabulary, not a new score.
KC_SEVERITY = [
    (4, "CRITICAL", "#C1443A"),
    (3, "HIGH",     "#D4622C"),
    (2, "MEDIUM",   "#E07B39"),
    (1, "LOW",      "#B99A4A"),
    (0, "MONITORED", "#7E96A6"),
]


def _kc_severity(fi):
    fi = int(fi or 0)
    for band, label, colour in KC_SEVERITY:
        if fi >= band:
            return label, colour
    return "MONITORED", "#7E96A6"


def _killchain_columns(tagged):
    """-> [ {tactic, order, alerts, techniques:[...]} ] in kill-chain order.

    A technique's severity is the HIGHEST FI seen for it: a tactic column has
    to surface its worst event, not its average, or a single destructive
    command hides behind fifty recon ones.
    """
    if tagged.empty:
        return []
    d = tagged[tagged["technique_id"].notna()]
    if d.empty:
        return []
    cols = {}
    for (tactic, tid), grp in d.groupby(["tactic", "technique_id"], sort=False):
        col = cols.setdefault(tactic, {"tactic": tactic, "alerts": 0, "techniques": []})
        top_fi = int(grp["fi_score"].max()) if "fi_score" in grp else 0
        col["alerts"] += len(grp)
        col["techniques"].append({
            "id": tid,
            "name": _technique_name(tid),
            "count": len(grp),
            "fi": top_fi,
            "sessions": grp["session_id"].nunique(),
        })
    out = []
    for tactic in sorted(cols, key=_tactic_rank):
        c = cols[tactic]
        c["techniques"].sort(key=lambda t: (-t["fi"], -t["count"]))
        out.append(c)
    for i, c in enumerate(out, 1):
        c["order"] = i
    return out


def _kc_card(tactic, t):
    """One technique card. Severity drives the left stripe and the count chip."""
    label, colour = _kc_severity(t["fi"])
    return html.Button(
        id={"type": "kc-card", "tid": t["id"], "tactic": tactic},
        n_clicks=0, className="kc-card", style={"borderLeftColor": colour},
        children=[
            html.Div(className="kc-card-top", children=[
                html.Span(t["id"], className="kc-tid"),
                html.Span(f"{t['count']:,}", className="kc-count",
                          style={"background": colour}),
            ]),
            html.Div(t["name"], className="kc-tname"),
            html.Div(className="kc-card-foot", children=[
                html.Span(label, className="kc-sev", style={"color": colour}),
                html.Span(f"{t['sessions']} sess", className="kc-sess"),
            ]),
        ])


def _kc_column(col):
    worst = max((t["fi"] for t in col["techniques"]), default=0)
    _lbl, colour = _kc_severity(worst)
    return html.Div(className="kc-col", children=[
        html.Div(className="kc-head", style={"borderBottomColor": colour}, children=[
            html.Div(className="kc-head-top", children=[
                html.Span(f"{col['order']:02d}", className="kc-ord"),
                html.Span(f"{col['alerts']:,}", className="kc-badge",
                          style={"background": colour}),
            ]),
            html.Div(col["tactic"], className="kc-tactic"),
        ]),
        html.Div(className="kc-stack", children=[
            _kc_card(col["tactic"], t) for t in col["techniques"]
        ]),
    ])


def _killchain_flow(days):
    """The full rail. Empty-state when the window has no mapped commands."""
    df = load_all()
    if df.empty or "tactic" not in df.columns:
        return html.Div("No data yet.", className="empty-state")
    cur, _prev = _mitre_window(df, days)
    tagged = cur[cur["tactic"].notna()]
    cols = _killchain_columns(tagged)
    if not cols:
        return html.Div("No ATT&CK-mapped commands in this period.",
                        className="empty-state")

    rail = []
    for i, c in enumerate(cols):
        if i:
            rail.append(html.Div("›", className="kc-chevron", **{"aria-hidden": "true"}))
        rail.append(_kc_column(c))

    total = sum(c["alerts"] for c in cols)
    ntech = sum(len(c["techniques"]) for c in cols)
    return html.Div([
        html.Div(f"{total:,} mapped events · {ntech} techniques across "
                 f"{len(cols)} tactics · ordered by MITRE kill chain · "
                 f"click a technique for detail",
                 className="caption", style={"marginBottom": "10px"}),
        html.Div(className="kc-rail", children=rail),
    ])


def _kc_detail(tid, tactic, days):
    """Drill-down body: the real events behind one technique card."""
    df = load_all()
    cur, _prev = _mitre_window(df, days)
    d = cur[(cur["technique_id"] == tid) & (cur["tactic"] == tactic)]
    if d.empty:
        return html.Div("No events for this technique in the current window.",
                        className="empty-state")
    d = d.sort_values("timestamp", ascending=False)
    worst = int(d["fi_score"].max()) if "fi_score" in d else 0
    label, colour = _kc_severity(worst)

    # Usernames come from the auth table, matched on src_ip. auth has no
    # session_id column, so this is "accounts seen from these sources", not
    # "the account that ran this command" — labelled as such rather than
    # implying a join the schema cannot support.
    users = []
    try:
        ips = tuple(str(x) for x in d["src_ip"].dropna().unique()[:40])
        if ips:
            with storage.connect_readonly() as conn:
                q = ("SELECT username, COUNT(*) c FROM auth WHERE src_ip IN "
                     f"({','.join('?' * len(ips))}) AND username IS NOT NULL "
                     "GROUP BY username ORDER BY c DESC LIMIT 6")
                users = [r[0] for r in conn.execute(q, ips)]
    except Exception:
        users = []

    rows = [{
        "Time": (r["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                 if pd.notna(r["timestamp"]) else "—"),
        "Sensor": r.get("instance") or "—",
        "Source": str(r.get("src_ip") or "—")[:16],
        "Sev": _kc_severity(r.get("fi_score"))[0],
        "Command": str(r.get("cmd") or "")[:120],
    } for _i, r in d.head(40).iterrows()]

    facts = [("TECHNIQUE", tid), ("TACTIC", tactic), ("SEVERITY", label),
             ("EVENTS", f"{len(d):,}"), ("SESSIONS", f"{d['session_id'].nunique():,}"),
             ("SENSORS", ", ".join(sorted(map(str, d['instance'].dropna().unique()))[:3]) or "—"),
             ("ACCOUNTS SEEN", ", ".join(users) if users else "none recorded")]

    return html.Div([
        html.Div(className="kc-detail-head", children=[
            html.Div([html.Span(tid, className="kc-detail-id"),
                      html.Span(label, className="kc-detail-sev",
                                style={"background": colour})]),
            html.Div(_technique_name(tid), className="kc-detail-name"),
        ]),
        html.Div(className="kc-facts", children=[
            html.Div(className="kc-fact", children=[
                html.Div(k, className="kc-fact-l"), html.Div(v, className="kc-fact-v")])
            for k, v in facts
        ]),
        html.Div("MOST RECENT EVENTS", className="side-head",
                 style={"marginTop": "14px"}),
        _top_table(rows, ["Time", "Sensor", "Source", "Sev", "Command"],
                   widths=[{"if": {"column_id": "Time"}, "width": "17%"},
                           {"if": {"column_id": "Sensor"}, "width": "14%"},
                           {"if": {"column_id": "Source"}, "width": "14%"},
                           {"if": {"column_id": "Sev"}, "width": "11%"},
                           {"if": {"column_id": "Command"}, "width": "44%"}],
                   row_padding="7px 6px"),
        html.Div(f"Showing {min(40, len(d))} of {len(d):,} events. Response "
                 "playbooks are not wired to this deployment — no automated "
                 "remediation status is available to display.",
                 className="caption", style={"marginTop": "8px"}),
    ])


@app.callback(
    Output("kc-detail-store", "data"),
    Input({"type": "kc-card", "tid": ALL, "tactic": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def _kc_open(clicks):
    """Which card was clicked. Dash fires this for every card on render, so a
    click is only real when that card's own n_clicks is non-zero."""
    tid = ctx.triggered_id
    # Dash delivers a LIST for an ALL pattern, but a bare int when exactly one
    # component matches. Normalise rather than assume, or the callback 500s the
    # first time a tactic column holds a single technique.
    if isinstance(clicks, (int, float)):
        clicks = [clicks]
    if not tid or not any(c for c in (clicks or []) if c):
        raise PreventUpdate
    if not isinstance(tid, dict):
        raise PreventUpdate
    return {"tid": tid.get("tid"), "tactic": tid.get("tactic")}


@app.callback(
    Output("kc-sheet", "className"),
    Output("kc-sheet-body", "children"),
    Input("kc-detail-store", "data"),
    Input("kc-close", "n_clicks"),
    State("mitre-window", "value"),
    prevent_initial_call=True,
)
def _kc_sheet(sel, _close, days):
    if ctx.triggered_id == "kc-close" or not sel:
        return "kc-sheet", no_update
    return "kc-sheet kc-open", _kc_detail(sel["tid"], sel["tactic"], days)


def build_mitre_page():
    return [
        html.Div(style={"display": "flex", "justifyContent": "space-between",
                        "alignItems": "center", "flexWrap": "wrap", "gap": "12px"},
                 children=[
            html.Div([
                html.H3("⚔ MITRE ATT&CK Summary"),
                html.Div("Attacker activity mapped to ATT&CK tactics and techniques",
                         className="caption"),
            ]),
            html.Div([
                html.Div("Time period", className="metric-label"),
                dcc.Dropdown(id="mitre-window", clearable=False, value=30,
                             options=[{"label": "Last 7 days", "value": 7},
                                      {"label": "Last 30 days", "value": 30},
                                      {"label": "Last 90 days", "value": 90},
                                      {"label": "All time", "value": 0}],
                             style={"width": "190px", "fontFamily": "JetBrains Mono, monospace"}),
            ]),
        ]),
        html.Div(id="mitre-content", children=build_mitre_body(30)),
    ]


@app.callback(Output("mitre-content", "children"),
              Input("mitre-window", "value"), prevent_initial_call=True)
def _refresh_mitre(days):
    # ~170ms and 7 Plotly figures per rebuild; the window dropdown gets toggled
    # back and forth, so cache each window rather than redrawing it every time
    return _cached_page(("mitre-body", days), lambda: build_mitre_body(days))
