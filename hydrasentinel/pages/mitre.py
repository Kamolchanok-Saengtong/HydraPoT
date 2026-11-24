"""
hydrasentinel/pages/mitre.py — MITRE ATT&CK page: coverage cards, top techniques,
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

from core import storage
from threat_intel.mitre_mapper import _load_catalog as _mitre_catalog

from hydrasentinel.server import app
from hydrasentinel.theme import theme_layout, GRAPH_CONFIG, TABLE_STYLE, INK, INK_2, INK_3, LINE
from hydrasentinel.data import load_all, _cached_page


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
        style_data_conditional=[],
        style_header={**TABLE_STYLE["style_header"], "backgroundColor": "#fff", "color": INK_3,
                      "fontSize": "11.5px", "fontWeight": "600", "padding": "8px 10px",
                      "borderBottom": f"1px solid {LINE}"},
        style_cell={
            "backgroundColor": "#fff", "color": INK_2,
            "fontFamily": "JetBrains Mono, monospace", "fontSize": "12px",
            "border": "none", "borderTop": f"1px solid {LINE}",
            "padding": "8px 10px", "textAlign": "left",
            "overflow": "hidden", "textOverflow": "ellipsis", "maxWidth": 0,
        },
        style_cell_conditional=widths or [],
        tooltip_data=tips, tooltip_duration=None,
        style_table={"overflowX": "hidden"},
    )


def _fmt_delta(now, before):
    """'+12% vs previous period', or '' when there is nothing earlier to compare with."""
    if not before:
        return ""
    pct = (now - before) / before * 100
    return f"{pct:+.0f}% vs previous period" if abs(pct) >= 1 else "unchanged vs previous period"


def _kpi(label, value, sub=""):
    return html.Div(className="mx-kpi", children=[
        html.Div(label, className="mx-kpi-l"),
        html.Div(value, className="mx-kpi-v"),
        html.Div(sub or "\u00a0", className="mx-kpi-s"),
    ])


def _panel(title, note, body, extra_class=""):
    return html.Div(className=f"mx-panel {extra_class}".strip(), children=[
        html.Div(className="mx-panel-head", children=[
            html.Div(title, className="mx-panel-title"),
            html.Div(note, className="mx-panel-note") if note else None,
        ]),
        html.Div(body, className="mx-panel-body"),
    ])


def _bars(rows, limit=None):
    """Ranked list with an inline bar. rows: [(label, sublabel, count)], already ordered.

    The first row is emphasised so the eye lands on the leader; limit keeps the
    list short enough to read at a glance."""
    if not rows:
        return html.Div("Nothing in this period.", className="empty-state")
    total = len(rows)
    rows = rows[:limit] if limit else rows
    top = max(c for *_, c in rows) or 1
    more = (html.Div(f"Top {len(rows)} of {total}", className="mx-bar-more")
            if total > len(rows) else None)
    return html.Div(className="mx-bars", children=[
        html.Div(className="mx-bar-row" + (" mx-first" if i == 0 else ""), children=[
            html.Div(className="mx-bar-label", children=[
                html.Span(sub, className="mx-bar-sub") if sub else None,
                html.Span(label, className="mx-bar-name", title=label),
            ]),
            html.Div(className="mx-bar-track", children=[
                html.Div(className="mx-bar-fill", style={"width": f"{max(c / top * 100, 2):.1f}%"})]),
            html.Div(f"{c:,}", className="mx-bar-val"),
        ]) for i, (label, sub, c) in enumerate(rows)
    ] + ([more] if more else []))


def _hero(n_mapped, n_all, by_tactic, top_tech, top_ip, days):
    """One sentence that says what this page found, before any chart does.

    Counts only: what the data shows, never how serious it is (that belongs to
    the detection layer)."""
    window = "all time" if not days else f"the last {days} days"
    facts = []
    if by_tactic:
        t, _, c = by_tactic[0]
        facts.append(html.Span(["Most activity: ", html.Strong(t), f" ({c:,})"]))
    if top_tech:
        name, tid, c = top_tech[0]
        facts.append(html.Span(["Top technique: ", html.Strong(f"{tid} {name}"), f" ({c:,})"]))
    if top_ip:
        ip, _, c = top_ip[0]
        facts.append(html.Span(["Busiest source: ", html.Strong(ip), f" ({c:,})"]))
    return html.Div(className="mx-hero", children=[
        html.Div(className="mx-hero-line", children=[
            html.Span(f"{n_mapped:,}", className="mx-hero-num"),
            f" command{'s' if n_mapped != 1 else ''} mapped to ATT&CK",
        ]),
        html.Div(f"{n_mapped / max(n_all, 1) * 100:.0f}% of {n_all:,} commands in {window}",
                 className="mx-hero-sub"),
        html.Div(facts, className="mx-hero-facts"),
    ])


def build_mitre_body(days):
    df = load_all()
    if df.empty or "tactic" not in df.columns:
        return html.Div("No data yet.", className="empty-state")

    cur, prev = _mitre_window(df, days)
    tagged = cur[cur["tactic"].notna()]
    if tagged.empty:
        return html.Div("No ATT&CK-mapped commands in this period.", className="empty-state")
    ptagged = prev[prev["tactic"].notna()]

    # Counts only. What a technique MEANS (severity) is decided by the detection layer,
    # never here: this page shows what was observed.
    _exp = tagged.explode("technique_ids")
    _exp = _exp[_exp["technique_ids"].notna()]
    top_tech = [(_technique_name(t), t, int(n)) for t, n in
                _exp.groupby("technique_ids").size().sort_values(ascending=False).head(8).items()]
    top_ip = [(ip, "", int(n)) for ip, n in
              tagged.groupby("src_ip").size().sort_values(ascending=False).head(8).items()]
    by_tactic = [(t, "", int(n)) for t, n in
                 tagged.groupby("tactic").size().sort_values(ascending=False).items()]

    kpis = html.Div(className="mx-kpis mx-kpis-tight", children=[
        _kpi("Techniques", f"{tagged['technique_id'].nunique():,}",
             _fmt_delta(tagged["technique_id"].nunique(), ptagged["technique_id"].nunique())),
        _kpi("Tactics", f"{tagged['tactic'].nunique():,}", f"of {len(TACTIC_ORDER)} in ATT&CK"),
        _kpi("Attacker sources", f"{tagged['src_ip'].nunique():,}",
             _fmt_delta(tagged["src_ip"].nunique(), ptagged["src_ip"].nunique())),
    ])

    return html.Div(className="mx", children=[
        _hero(len(tagged), len(cur), by_tactic, top_tech, top_ip, days),
        kpis,
        _panel("ATT&CK matrix", "Tactics left to right in kill-chain order. Darker = more events. "
               "Select a technique for its events.", _killchain_flow(days), "mx-wide"),
        html.Div(className="mx-grid3", children=[
            _panel("Activity by tactic", f"{len(by_tactic)} observed", _bars(by_tactic)),
            _panel("Top techniques", "by commands", _bars(top_tech, limit=5)),
            _panel("Top attacker sources", "by mapped commands", _bars(top_ip, limit=5)),
        ]),
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
    from hydrasentinel.data import _cache
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
                "Sequence": " → ".join(_technique_name(t) for t in g),
                "Techniques": " → ".join(g),
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
                        symbol=["circle"
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
    """Source / duration / events / techniques for one session."""
    ts = [e["timestamp"] for e in events if pd.notna(e.get("timestamp"))]
    dur = "\u2014"
    if len(ts) >= 2:
        secs = (max(ts) - min(ts)).total_seconds()
        dur = f"{secs/60:.0f}m {secs%60:.0f}s" if secs >= 60 else f"{secs:.0f}s"
    ip = next((e.get("src_ip") for e in events if e.get("src_ip")), "\u2014")
    techs = len({e.get("technique_id") for e in events if e.get("technique_id")})
    items = [("Source IP", str(ip)), ("Duration", dur),
             ("Mapped events", f"{len(events):,}"), ("Techniques", f"{techs:,}")]
    return html.Div(className="mx-kpis mx-kpis-tight", children=[_kpi(l, v) for l, v in items])


def _attack_chain_section(days):
    """The three chain cards. Returns [] when the window has nothing to show."""
    a = _chain_analytics(days)
    if not a["chains"]:
        return []

    # ── Playbooks ────────────────────────────────────────────────────────────
    rows = _playbook_rows(a["ngrams"], a["n_sessions"])
    if rows:
        play_body = _top_table(rows, ["Sequence", "Techniques", "Count", "% sessions"], tooltip_col="Sequence",
                               widths=[{"if": {"column_id": "Sequence"}, "width": "46%"},
                                       {"if": {"column_id": "Techniques"}, "width": "28%"},
                                       {"if": {"column_id": "Count"}, "width": "12%",
                                        "textAlign": "right"},
                                       {"if": {"column_id": "% sessions"}, "width": "14%",
                                        "textAlign": "right"}],
                               row_padding="9px 6px")
    else:
        play_body = html.Div(
            "No repeated sequence yet: sessions in this window are too short or too varied.", className="empty-state")

    # ── Session picker ───────────────────────────────────────────────────────
    opts = [{"label": f"{sid[:18]}  ·  {n} events", "value": sid}
            for sid, n in a["sessions"][:300]]
    default_sid = a["sessions"][0][0] if a["sessions"] else None

    return [
        _panel("Common attack sequences", "recurring 3- and 4-technique runs", play_body, "mx-wide"),
        _panel("Session timeline", "one attacker session, command by command", html.Div([
            html.Div(className="chain-pick", children=[
                html.Span("Session", className="caption"),
                dcc.Dropdown(id="chain-session-dd", options=opts, value=default_sid,
                             clearable=False, searchable=True, style={"minWidth": "320px"}),
            ]),
            dcc.Store(id="chain-days-store", data=days),
            html.Div(id="chain-timeline-body"),
        ]), "mx-wide"),
        dcc.Store(id="kc-detail-store"),
        html.Div(id="kc-sheet", className="kc-sheet", children=[
            html.Button("\u2715", id="kc-close", n_clicks=0, className="kc-close",
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
        html.Div("Each point is one mapped command, in the order it was typed.",
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
# Everything here is real: tactics and techniques come from the mapper, counts from the DB.

def _killchain_columns(tagged):
    """-> [ {tactic, alerts, techniques:[...]} ] in kill-chain order, techniques by event count."""
    d = tagged[tagged["technique_id"].notna()] if not tagged.empty else tagged
    if d.empty:
        return []
    cols = {}
    for (tactic, tid), grp in d.groupby(["tactic", "technique_id"], sort=False):
        col = cols.setdefault(tactic, {"tactic": tactic, "alerts": 0, "techniques": []})
        col["alerts"] += len(grp)
        col["techniques"].append({"id": tid, "name": _technique_name(tid), "count": len(grp),
                                  "sessions": grp["session_id"].nunique()})
    out = []
    for tactic in sorted(cols, key=_tactic_rank):
        c = cols[tactic]
        c["techniques"].sort(key=lambda t: -t["count"])
        out.append(c)
    return out


def _kc_card(tactic, t, peak):
    """One technique cell. Colour intensity is its share of the busiest technique."""
    share = t["count"] / max(peak, 1)
    return html.Button(
        id={"type": "kc-card", "tid": t["id"], "tactic": tactic},
        n_clicks=0, className="kc-card", style={"--heat": f"{0.10 + 0.55 * share:.2f}"},
        children=[
            html.Div(className="kc-card-top", children=[
                html.Span(t["id"], className="kc-tid"),
                html.Span(f"{t['count']:,}", className="kc-count"),
            ]),
            html.Div(t["name"], className="kc-tname"),
            html.Div(f"{t['sessions']} session{'s' if t['sessions'] != 1 else ''}", className="kc-sess"),
        ])


def _kc_column(col, peak):
    return html.Div(className="kc-col", children=[
        html.Div(className="kc-head", children=[
            html.Div(col["tactic"], className="kc-tactic"),
            html.Div(f"{col['alerts']:,} events \u00b7 {len(col['techniques'])} technique"
                     f"{'s' if len(col['techniques']) != 1 else ''}", className="kc-head-sub"),
        ]),
        html.Div(className="kc-stack", children=[_kc_card(col["tactic"], t, peak)
                                                 for t in col["techniques"]]),
    ])


def _killchain_flow(days):
    """The matrix. Tactics with no activity are listed underneath so coverage is clear."""
    df = load_all()
    if df.empty or "tactic" not in df.columns:
        return html.Div("No data yet.", className="empty-state")
    cur, _prev = _mitre_window(df, days)
    cols = _killchain_columns(cur[cur["tactic"].notna()])
    if not cols:
        return html.Div("No ATT&CK-mapped commands in this period.", className="empty-state")
    peak = max(t["count"] for c in cols for t in c["techniques"])
    seen = {c["tactic"].lower() for c in cols}
    quiet = [t for t in TACTIC_ORDER if t.lower() not in seen]
    return html.Div([
        html.Div(className="kc-rail", children=[_kc_column(c, peak) for c in cols]),
        html.Div(className="mx-quiet", children=[
            html.Span("No activity observed:", className="mx-quiet-l"),
            *[html.Span(t, className="mx-chip") for t in quiet]]) if quiet else None,
    ])


def _kc_detail(tid, tactic, days):
    """Drill-down body: the real events behind one technique."""
    df = load_all()
    cur, _prev = _mitre_window(df, days)
    d = cur[(cur["technique_id"] == tid) & (cur["tactic"] == tactic)]
    if d.empty:
        return html.Div("No events for this technique in the current window.",
                        className="empty-state")
    d = d.sort_values("timestamp", ascending=False)

    # Usernames come from the auth table, matched on src_ip. auth has no session_id column,
    # so this is "accounts seen from these sources", not "the account that ran this command".
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
        "Time": (r["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if pd.notna(r["timestamp"]) else "\u2014"),
        "Source": str(r.get("src_ip") or "\u2014")[:16],
        "Command": str(r.get("cmd") or "")[:120],
    } for _i, r in d.head(40).iterrows()]

    facts = [("Tactic", tactic), ("Events", f"{len(d):,}"), ("Sessions", f"{d['session_id'].nunique():,}"),
             ("Sources", f"{d['src_ip'].nunique():,}"),
             ("Accounts seen", ", ".join(users) if users else "none recorded")]

    return html.Div([
        html.Div(className="kc-detail-head", children=[
            html.Span(tid, className="kc-detail-id"),
            html.Div(_technique_name(tid), className="kc-detail-name"),
        ]),
        html.Div(className="kc-facts", children=[
            html.Div(className="kc-fact", children=[
                html.Div(k, className="kc-fact-l"), html.Div(v, className="kc-fact-v")])
            for k, v in facts
        ]),
        html.Div("Most recent events", className="mx-panel-title", style={"margin": "16px 0 6px"}),
        _top_table(rows, ["Time", "Source", "Command"],
                   widths=[{"if": {"column_id": "Time"}, "width": "34%"},
                           {"if": {"column_id": "Source"}, "width": "17%"},
                           {"if": {"column_id": "Command"}, "width": "49%"}],
                   row_padding="7px 6px"),
        html.Div(f"Showing {min(40, len(d))} of {len(d):,} events.",
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
                html.H3("MITRE ATT&CK"),
                html.Div("What attackers did, mapped to ATT&CK tactics and techniques",
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
