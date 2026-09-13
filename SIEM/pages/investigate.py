"""
SIEM/pages/investigate.py — SOC investigation workspace.

Not a dashboard and not a report. One screen an analyst works in, laid out in
the order the questions actually get asked:

    what should I investigate   ->  queue (left rail, 28%)
    why did this trigger        ->  headline + "why this matters"
    how are they related        ->  the relationship, DRAWN
    what ATT&CK activity        ->  tactic progression + named techniques
    what exact evidence         ->  tabbed workspace, last

The information architecture, not the styling, is what this file is for:

  * ONE surface. The previous version nested panels inside panels inside
    cards; every box drew a border that said "new thing" without a new thing
    behind it. Here the workspace is a single plane and hierarchy comes from
    type weight, spacing and rules between sections.
  * The queue carries ONLY what picking a detection requires -- title, type,
    counts, tactic chain, last seen. No explanation paragraph, no commands, no
    technique list. Those are why the old list was unscannable.
  * Evidence is TABBED, not stacked. Four stacked <details> meant the analyst
    scrolled past sessions to reach commands; tabs make them peers, and the
    panel scrolls on its own so the detection header never leaves the screen.
  * Raw JSON is evidence, not UX. It is one tab, never the default.

RENDERING ONLY. Every value comes from SIEM/investigation.py's view model,
which joins detection/correlation/aggregation output. Nothing is counted or
decided here; an absent field prints "Not available" rather than a zero.

SEVERITY: detection.detect() emits none, and threat_intel/severity.py is built
but not wired -- that decision is still open. The layout HAS the severity slot
(_severity_chip), and it renders only when a rating exists. Today none does, so
nothing is drawn there. A placeholder "HIGH" would be indistinguishable from a
real rating once the layer lands.
"""
import json

from dash import html, dcc, Input, Output, State, ctx, ALL
from dash.exceptions import PreventUpdate

from SIEM.server import app
from SIEM.data import load_overview, load_detections, load_session_commands
from SIEM.investigation import build_investigation, technique_name
from SIEM.pages.mitre import _tactic_color

QUEUE_LIMIT = 25       # rows in the rail; it scrolls independently
TECH_VISIBLE = 8       # techniques before "+N more techniques"
GRAPH_NODES = 4        # session nodes drawn before the graph summarises
CMD_LIMIT = 200        # commands rendered in one timeline
SESSION_ROWS = 50      # rows in the sessions evidence table

# "Command and Control" is four words of chip in a 320px rail. C2 is the
# standard analyst contraction, not an abbreviation invented here, and only
# the cramped contexts use it -- the detail header spells tactics out.
TACTIC_SHORT = {"Command and Control": "C2"}

EVIDENCE_TABS = [("sessions", "Sessions"), ("commands", "Commands"),
                 ("techniques", "Techniques"), ("raw", "Raw evidence")]
DEFAULT_TAB = "sessions"


def _na(value, fmt=str):
    """Absent stays absent. A missing count rendered as 0 is a measurement
    nobody made."""
    return fmt(value) if value not in (None, "") else "Not available"


def _count(n, word):
    """"1 command", not "1 commands"."""
    return f"{n:,} {word}" if n == 1 else f"{n:,} {word}s"


def _facts_line(v):
    return " · ".join(filter(None, [
        _count(v["member_count"], "session"),
        _count(v["distinct_sources"], "source"),
        _count(v["command_count"], "command") if v["command_count"] else None,
        _count(len(v["tactics"]), "tactic") if v["tactics"] else None,
    ]))


def _tactic_chain(tactics, limit=6, short=False, cls="iv-chain"):
    """Tactics as a progression. Insertion order survives all the way from
    aggregator._chain, so this is the kill chain rather than a sorted list."""
    out = []
    for i, t in enumerate(tactics[:limit]):
        if i:
            out.append(html.Span("→", className="iv-arrow"))
        out.append(html.Span(TACTIC_SHORT.get(t, t) if short else t,
                             className="iv-tac", title=t,
                             style={"background": _tactic_color(t)}))
    if len(tactics) > limit:
        out.append(html.Span(f"+{len(tactics) - limit}", className="iv-more-inline"))
    return html.Div(out, className=cls)


def _chevrons(tactics, limit=8):
    """Tactic progression as interlocking chevrons.

    The chips-and-arrows version read as a list of labels that happened to have
    arrows between them. Chevrons that slot into one another read as a single
    directed path, which is what a kill chain IS -- the shape carries the
    meaning so the analyst does not have to assemble it.

    Colours stay the app-wide tactic mapping (SIEM/pages/mitre.py), so a tactic
    is the same colour here, on the MITRE page and on Summary.
    """
    items = []
    for i, t in enumerate(tactics[:limit]):
        items.append(html.Div(t, className="iv-chev" + (" first" if i == 0 else ""),
                              title=t, style={"background": _tactic_color(t)}))
    if len(tactics) > limit:
        items.append(html.Div(f"+{len(tactics) - limit}", className="iv-chev iv-chev-more"))
    return html.Div(items, className="iv-chevs")


def _severity_chip(v):
    """The rating from threat_intel/severity.py, or an explicit UNRATED.

    UNRATED is shown rather than hidden: a blank where every other row has a
    level reads as a rendering bug, and silence about a rating is easily
    mistaken for "nothing to worry about". It means the behaviour ruleset had
    no shared command sequence to read -- which the detail panel says in
    words.
    """
    sev = v.get("severity")
    if not sev:
        return html.Span("UNRATED", className="iv-sev iv-sev-unrated")
    return html.Span(sev.upper(), className=f"iv-sev iv-sev-{sev}")


ALERT_LABEL = {"new": "NEW", "acknowledged": "ACK", "closed": "CLOSED"}


def _alert_chip(v):
    """Analyst state, shown only when an alert record exists.

    Most detections never become alerts -- alerting is deliberately narrower
    than detection -- so a chip on every row would say nothing. Its presence IS
    the signal that this one crossed the bar.
    """
    a = v.get("alert")
    if not a:
        return None
    st = a.get("state") or "new"
    return html.Span(ALERT_LABEL.get(st, st.upper()),
                     className=f"iv-alert iv-alert-{st}")


def _alert_block(v):
    """The alert record and the actions that move it.

    Buttons carry the alert key rather than a row index: the queue re-sorts and
    re-filters constantly, and an index would acknowledge whatever happened to
    be in that position.
    """
    a = v.get("alert")
    if not a:
        return html.Div(className="iv-block", children=[
            html.Div("ALERT", className="iv-h"),
            html.Div("No alert raised — this detection did not meet any rule in "
                     "alert_rules.yml. It stays on the investigation queue; "
                     "alerting is deliberately narrower than detection.",
                     className="iv-muted"),
        ])

    st = a.get("state") or "new"
    facts = [("State", st.capitalize()), ("Raised", _na(a.get("created_at"))),
             ("Rule", a.get("alert_rule") or "—"),
             ("Delivered", a.get("routed_at") or "Not sent")]
    if a.get("acknowledged_by"):
        facts.append(("Acknowledged by", a["acknowledged_by"]))

    def act(label, state, cls=""):
        return html.Button(label, n_clicks=0, className="iv-act " + cls,
                           id={"type": "iv-alert-act", "key": v["key"],
                               "state": state})

    actions = []
    if st == "new":
        actions = [act("Acknowledge", "acknowledged", "primary"), act("Close", "closed")]
    elif st == "acknowledged":
        actions = [act("Close", "closed", "primary"), act("Reopen", "new")]
    else:
        actions = [act("Reopen", "new")]

    return html.Div(className="iv-block", children=[
        html.Div(className="iv-ev-head", children=[
            html.Div("ALERT", className="iv-h"),
            html.Div(actions, className="iv-acts")]),
        html.Div([html.Div([html.Span(k, className="iv-k"),
                            html.Span(val, className="iv-v")]) for k, val in facts],
                 className="iv-meta"),
        html.Div(a["note"], className="iv-muted", style={"marginTop": "8px"})
        if a.get("note") else html.Span(),
    ])


# ── queue ───────────────────────────────────────────────────────────────────

def _queue_row(v, i, selected_key):
    """Compact enough to scan twenty of them.

    Deliberately absent: the explanation paragraph, the command text, the
    technique list. Each was in the previous row and each is the reason the
    list could not be scanned. Choosing what to work on needs the title, the
    shape of the activity and its size -- nothing else.
    """
    chip = _severity_chip(v)
    return html.Button(
        id={"type": "iv-select", "key": v["key"]}, n_clicks=0,
        className="iv-row" + (" active" if v["key"] == selected_key else ""),
        children=[
            html.Div(className="iv-row-top", children=[
                html.Span(f"{i:02d}", className="iv-row-n"),
                chip if chip is not None else html.Span(),
                html.Span(v["title"], className="iv-row-title"),
                _alert_chip(v) or html.Span(),
            ]),
            html.Div(_facts_line(v), className="iv-row-facts"),
            _tactic_chain(v["tactics"], limit=4, short=True, cls="iv-chain-sm")
            if v["tactics"] else html.Span(),
            html.Div(className="iv-row-foot", children=[
                html.Span(v["link_type"], className="iv-type"),
                html.Span(v["last_seen"] or "—", className="iv-row-seen"),
            ]),
        ])


# Triage order, worst first. "unrated" is last and is NOT a severity level --
# it is the absence of one.
SEV_FILTERS = ["critical", "high", "medium", "low", "info", "unrated"]


def _matches(v, q):
    """Free-text search across what an analyst would actually type: the
    detection title, the correlation type, any member session id, any source
    address, and any technique name or ID."""
    if not q:
        return True
    q = q.lower()
    hay = [v["title"], v["link_type"], v["rule_id"] or ""]
    hay += [str(m) for m in v["member_ids"]]
    hay += [str(ip) for ip in v["src_ips"]]
    hay += [t["name"] for t in v["techniques"]] + [t["id"] for t in v["techniques"]]
    hay += v["tactics"]
    return any(q in str(h).lower() for h in hay)


def _queue_toolbar(by_severity, active, q, total):
    """Triage filter: severity first, because that is how a queue gets worked.

    Only levels that actually occur get a pill -- a "Critical (0)" pill is a
    button that does nothing, and a row of them makes the real ones harder to
    find. Correlation type is still filterable through the search box, which
    matches link_type.
    """
    pills = [html.Button(f"All ({total})", id={"type": "iv-filter", "f": "all"},
                         n_clicks=0, className="active" if active == "all" else "")]
    for lvl in SEV_FILTERS:
        n = by_severity.get(lvl, 0)
        if not n:
            continue
        pills.append(html.Button(f"{lvl.capitalize()} ({n})",
                                 id={"type": "iv-filter", "f": lvl}, n_clicks=0,
                                 className="iv-pill-" + lvl +
                                 (" active" if active == lvl else "")))
    return html.Div(className="iv-tools", children=[
        html.Div(pills, className="iv-pills"),
        dcc.Input(id="iv-search", type="search", value=q or "",
                  placeholder="Search detections, sessions, sources…",
                  debounce=True, className="iv-search"),
    ])


def _queue(views, selected_key):
    if not views:
        return html.Div("Nothing matches. Clear the filter or search to see the "
                        "full queue.", className="iv-empty")
    rows = [_queue_row(v, i, selected_key)
            for i, v in enumerate(views[:QUEUE_LIMIT], 1)]
    extra = ([html.Div(f"{len(views) - QUEUE_LIMIT} further detection(s) not listed.",
                       className="iv-foot")] if len(views) > QUEUE_LIMIT else [])
    return html.Div(rows + extra, className="iv-queue")


# ── relationship graph ──────────────────────────────────────────────────────

LINK_LABEL = {
    "same_sequence": "SAME COMMAND SEQUENCE",
    "shared_indicator": "SHARED INDICATOR",
    "same_source_address": "SAME SOURCE ADDRESS",
}


def _correlation_graph(v):
    """The detection's derivation, drawn:

        session ─┐
        session ─┼──► SHARED BEHAVIOUR ──► CORRELATION RULE ──► DETECTION
        session ─┘

    This is the one thing in the product that a paragraph genuinely cannot do.
    Text can state that 22 sessions share a sequence; only the picture shows
    that the sessions are the many and the detection is the one, and that the
    rule sits between them rather than over them.

    Real members only, and honest about scale: past GRAPH_NODES it draws the
    first few and labels the remainder rather than implying it drew them all.
    CSS boxes and border connectors, not SVG, so it reflows instead of
    scrolling on a narrower monitor.
    """
    shown = v["member_ids"][:GRAPH_NODES]
    hidden = v["member_count"] - len(shown)
    nodes = [html.Div(str(s)[:12], className="iv-node", title=str(s)) for s in shown]
    if hidden > 0:
        nodes.append(html.Div(f"+{hidden} more", className="iv-node iv-node-more"))

    label = LINK_LABEL.get(v["link_type"],
                           v["link_type"].replace("_", " ").upper())

    def stage(cap, node, sub=None):
        return html.Div(className="iv-stage", children=[
            html.Div(cap, className="iv-stage-cap"),
            node,
            html.Div(sub, className="iv-stage-sub") if sub else html.Span(),
        ])

    arrow = html.Div("►", className="iv-flow-arrow")
    return html.Div(className="iv-graph", children=[
        html.Div(className="iv-stage", children=[
            html.Div("SESSIONS", className="iv-stage-cap"),
            html.Div(className="iv-nodes-wrap", children=[
                html.Div(nodes, className="iv-nodes"),
                html.Div(className="iv-brace"),
            ]),
        ]),
        arrow,
        stage("SHARED BEHAVIOUR",
              html.Div(label, className="iv-node-shared"), v["statement"]),
        arrow,
        stage("CORRELATION RULE",
              html.Div(v["link_type"], className="iv-node-rule")),
        arrow,
        stage("DETECTION",
              html.Div(v["title"], className="iv-node-det"), v["rule_id"] or None),
    ])


# ── ATT&CK story ────────────────────────────────────────────────────────────

def _tech_rows(techs):
    return [html.Div(className="iv-tech", children=[
        html.Span(t["name"], className="iv-tech-name"),
        html.Span(t["id"], className="iv-tech-id"),
    ]) for t in techs]


def _attack_story(v):
    """Techniques grouped under the stage they belong to.

    Deliberately NOT another tactic chain: the detection header already shows
    the progression, and repeating it here was the page telling the analyst the
    same thing twice. Grouping is what makes this a story rather than a
    restatement -- it answers "what did they actually DO at each stage", which
    the chain alone cannot.

    Stage order follows the relationship's own tactic order, which survives
    from aggregator._chain as execution order, so the groups read down the kill
    chain rather than alphabetically.
    """
    if not v["tactics"] and not v["techniques"]:
        return html.Div("No ATT&CK tags on this relationship's shared value — "
                        "indicator and source-address links carry no command "
                        "sequence to tag.", className="iv-muted")

    remaining = list(v["techniques"])
    groups = []
    for tac in v["tactics"]:
        hit = [t for t in remaining if t["tactic"] == tac]
        if hit:
            groups.append((tac, hit))
            remaining = [t for t in remaining if t not in hit]
    # Techniques the catalog files under a stage this sequence did not reach,
    # plus any with no catalogued stage at all. Shown, never dropped.
    if remaining:
        groups.append((None, remaining))

    shown, overflow, budget = [], [], TECH_VISIBLE
    for tac, techs in groups:
        if budget <= 0:
            overflow.append((tac, techs))
        elif len(techs) <= budget:
            shown.append((tac, techs))
            budget -= len(techs)
        else:
            shown.append((tac, techs[:budget]))
            overflow.append((tac, techs[budget:]))
            budget = 0

    def column(tac, techs):
        """One stage, with what was actually done at it underneath."""
        head = (html.Div(tac, className="iv-chev first", title=tac,
                         style={"background": _tactic_color(tac)}) if tac
                else html.Div("Other", className="iv-chev iv-chev-more"))
        return html.Div(className="iv-att-col", children=[
            head,
            html.Div([html.Div(className="iv-att-t", children=[
                html.Div(t["name"], className="iv-att-name"),
                html.Div(t["id"], className="iv-att-id"),
            ]) for t in techs], className="iv-att-list"),
        ])

    cols = [column(t, g) for t, g in shown]
    n_more = sum(len(g) for _, g in overflow)
    body = [html.Div(cols, className="iv-att")]
    if n_more:
        body.append(html.Details(className="iv-disc", children=[
            html.Summary(f"+{n_more} more technique" + ("" if n_more == 1 else "s")),
            html.Div([column(t, g) for t, g in overflow], className="iv-att"),
        ]))
    return html.Div(body)


# ── evidence tabs ───────────────────────────────────────────────────────────

def _ev_sessions(v):
    if not v["members"]:
        return html.Div("Session details are not available for these members "
                        "in the current window.", className="iv-muted")
    rows = []
    for m in v["members"][:SESSION_ROWS]:
        tac = m.get("tactics") or []
        rows.append(html.Tr([
            html.Td(str(m["session_id"])[:16], className="iv-mono-b"),
            html.Td(str(m.get("src_ip") or "—"), className="iv-mono"),
            html.Td(_na(m.get("commands"), lambda x: f"{x:,}"), className="iv-num"),
            html.Td(_tactic_chain(tac, limit=4, short=True, cls="iv-chain-sm")
                    if tac else html.Span("—", className="iv-muted")),
            html.Td(_na(m.get("last_seen")), className="iv-mono"),
        ]))
    more = ([html.Div(f"{len(v['members']) - SESSION_ROWS} more sessions not listed.",
                      className="iv-foot")]
            if len(v["members"]) > SESSION_ROWS else [])
    return html.Div([
        html.Table(className="iv-tbl", children=[
            html.Thead(html.Tr([html.Th("SESSION"), html.Th("SOURCE"),
                                html.Th("COMMANDS"), html.Th("TACTICS"),
                                html.Th("LAST SEEN")])),
            html.Tbody(rows)])] + more)


def _ev_commands(v):
    """Timeline for ONE representative session.

    One transcript, not twenty-two: in a same_sequence relationship every
    member ran the identical sequence by construction, so concatenating them
    would repeat the same lines N times. The caption names the session read,
    so the sample is never mistaken for the whole.
    """
    if not v["member_ids"]:
        return html.Div("No session to read commands from.", className="iv-muted")
    sid = v["member_ids"][0]
    rows = load_session_commands(sid)
    if not rows:
        return html.Div(f"No stored commands for session {str(sid)[:16]}.",
                        className="iv-muted")

    lines = []
    for i, r in enumerate(rows[:CMD_LIMIT], 1):
        tid = r.get("technique_id")
        lines.append(html.Div(className="iv-cmd", children=[
            html.Span(f"{i:02d}", className="iv-cmd-n"),
            html.Span(r.get("timestamp") or "—", className="iv-cmd-ts"),
            html.Code(r.get("cmd") or "", className="iv-cmd-t"),
            html.Span(technique_name(tid), className="iv-cmd-tech", title=tid)
            if tid else html.Span(),
        ]))

    note = f"Session {str(sid)[:16]} · {_count(len(rows), 'command')}"
    if v["link_type"] == "same_sequence" and v["member_count"] > 1:
        note += f" · all {v['member_count']} sessions ran this identical sequence"
    if len(rows) > CMD_LIMIT:
        note += f" · first {CMD_LIMIT} shown"
    return html.Div([html.Div(note, className="iv-foot",
                              style={"marginBottom": "8px"}),
                     html.Div(lines, className="iv-cmds")])


def _ev_techniques(v):
    if not v["techniques"]:
        return html.Div("No techniques tagged on this relationship's shared "
                        "value.", className="iv-muted")
    return html.Div(_tech_rows(v["techniques"]), className="iv-techs")


def _ev_raw(v):
    return html.Div([
        html.Div("The relationship object exactly as the correlation engine "
                 "produced it, before any presentation.", className="iv-muted"),
        html.Pre(json.dumps(v["relationship"], indent=2, default=str,
                            ensure_ascii=False), className="iv-raw"),
    ])


EVIDENCE_BODY = {"sessions": _ev_sessions, "commands": _ev_commands,
                 "techniques": _ev_techniques, "raw": _ev_raw}


def _tab_counts(v):
    """Real counts beside each tab, so the analyst knows what is behind it
    before paying a click. Commands is the representative session's length,
    which is what that tab actually shows -- not the sum across members, which
    would promise a transcript this page deliberately does not concatenate."""
    return {"sessions": v["member_count"],
            "commands": v["command_count"],
            "techniques": len(v["techniques"]),
            "raw": None}


def _evidence(v, tab):
    tab = tab if tab in EVIDENCE_BODY else DEFAULT_TAB
    counts = _tab_counts(v)
    seg = html.Div(className="iv-seg", children=[
        html.Button(id={"type": "iv-tab", "tab": key}, n_clicks=0,
                    className="active" if key == tab else "",
                    children=[html.Span(label),
                              html.Span(f"{counts[key]:,}", className="iv-seg-n")
                              if counts.get(key) else html.Span()])
        for key, label in EVIDENCE_TABS
    ])
    return html.Div([
        html.Div(className="iv-ev-head", children=[
            html.Div("EVIDENCE", className="iv-h"), seg]),
        html.Div(EVIDENCE_BODY[tab](v), className="iv-ev-body"),
    ])


def _severity_block(v):
    """What the rating is based on.

    A severity with no visible basis is exactly the opaque number this
    architecture keeps refusing to produce, so the rules that fired are shown,
    highest first, each with the level it contributed. The overall rating is
    the HIGHEST of them -- not a sum, not an average.
    """
    rules = v.get("severity_rules") or []
    if not rules:
        return html.Div(className="iv-block", children=[
            html.Div("SEVERITY", className="iv-h"),
            html.Div("Unrated — this relationship's members share a value, not a "
                     "command sequence, so the behaviour ruleset has nothing to "
                     "read. Absence of a rating is not a judgement that it is "
                     "harmless.", className="iv-muted"),
        ])
    return html.Div(className="iv-block", children=[
        html.Div("WHY THIS SEVERITY", className="iv-h"),
        html.Div(f"Rated {(v['severity'] or '').upper()} — the highest of "
                 f"{len(rules)} rule{'' if len(rules) == 1 else 's'} that fired "
                 f"on the shared sequence.", className="iv-muted",
                 style={"marginBottom": "9px"}),
        html.Div([html.Div(className="iv-sevrule", children=[
            html.Span(r["severity"].upper(),
                      className=f"iv-sev iv-sev-{r['severity']}"),
            html.Div([html.Div(r["title"], className="iv-sevrule-t"),
                      html.Div(r.get("description") or "",
                               className="iv-sevrule-d")]),
        ]) for r in rules]),
    ])


# ── selected detection ──────────────────────────────────────────────────────

def _detail(v, tab=DEFAULT_TAB):
    if v is None:
        return html.Div("No detection selected — nothing in the queue matches the "
                        "current filter or search.", className="iv-empty")

    chip = _severity_chip(v)
    meta = [("Sessions", f"{v['member_count']:,}"),
            ("Sources", f"{v['distinct_sources']:,}"),
            ("Commands", _na(v["command_count"], lambda x: f"{x:,}")),
            ("Tactics", str(len(v["tactics"])) if v["tactics"] else "Not available"),
            ("First seen", _na(v["first_seen"])),
            ("Last seen", _na(v["last_seen"]))]

    return html.Div([
        html.Div(className="iv-head", children=[
            html.Div(className="iv-head-top", children=[
                chip if chip is not None else html.Span(),
                html.H2(v["title"], className="iv-title"),
                _alert_chip(v) or html.Span(),
                html.Span(v["link_type"], className="iv-type"),
            ]),
            html.Div([html.Div([html.Span(k, className="iv-k"),
                                html.Span(val, className="iv-v")])
                      for k, val in meta], className="iv-meta"),
            _chevrons(v["tactics"]) if v["tactics"] else html.Span(),
        ]),

        html.Div(className="iv-block", children=[
            html.Div("WHY THIS DETECTION MATTERS", className="iv-h"),
            html.Div(v["why"], className="iv-why"),
            # Implementation terminology, kept reachable but never leading.
            html.Div(className="iv-why-meta", children=[
                html.Span("Correlation rule", className="iv-k"),
                html.Span(v["link_type"], className="iv-v-mono"),
                html.Span("Detection rule", className="iv-k"),
                html.Span(v["rule_id"] or "—", className="iv-v-mono"),
            ]),
            html.Details(className="iv-disc", children=[
                html.Summary("What these rules say"),
                html.Div([html.Div(f"“{v['statement']}”", className="iv-quote"),
                          html.Div(v["rule_reason"], className="iv-rule-text")],
                         className="iv-rule-box"),
            ]),
        ]),

        _alert_block(v),
        _severity_block(v),

        html.Div(className="iv-block", children=[
            html.Div("HOW THESE SESSIONS ARE RELATED", className="iv-h"),
            _correlation_graph(v),
        ]),

        html.Div(className="iv-block", children=[
            html.Div("ATT&CK STORY", className="iv-h"),
            _attack_story(v),
        ]),

        html.Div(className="iv-block", children=[_evidence(v, tab)]),
    ])


# ── page ────────────────────────────────────────────────────────────────────

def _investigation(preset, instance):
    return build_investigation(
        load_detections(preset=preset, instance=instance),
        load_overview(preset=preset, instance=instance),
        instance=instance)


def _summary_strip(s):
    """Five figures with what each is a share OF underneath.

    The sub-line is the part that makes a headline number mean something --
    "209 sessions involved" is only informative next to how many the window
    holds. Every sub-line is a real aggregation figure or an omission; none is
    a trend this system does not compute.
    """
    def kpi(icon, value, label, sub):
        return html.Div(className="iv-kpi", children=[
            html.Div(icon, className="iv-kpi-ico"),
            html.Div(className="iv-kpi-body", children=[
                html.Div(f"{value:,}", className="iv-kpi-v"),
                html.Div(label, className="iv-kpi-l"),
                html.Div(sub, className="iv-kpi-s") if sub else html.Span(),
            ]),
        ])

    sev = s.get("by_severity") or {}
    breakdown = " · ".join(f"{sev[k]} {k}" for k in
                           ("critical", "high", "medium", "low", "info", "unrated")
                           if sev.get(k))
    win_sess = s.get("window_sessions")
    tagged = s.get("tagged_commands")
    return html.Div(className="iv-kpis", children=[
        kpi("◈", s["detections"], "Detections", breakdown or None),
        kpi("▤", s["sessions"], "Sessions involved",
            f"of {win_sess:,} in window" if win_sess else None),
        kpi("⛓", s["relationships"], "Relationships",
            f"{s['suppressed']:,} suppressed · {s['unmatched']:,} unmatched"),
        kpi("◆", s["techniques"], "Techniques",
            f"from {tagged:,} tagged commands" if tagged else None),
        kpi("◉", s["tactics"], "Tactics", "ATT&CK stages reached"),
        kpi("⚑", s.get("alerts_open", 0), "Open alerts", "awaiting an analyst"),
    ])


def _apply_filters(views, flt, q):
    """Filter is presentation only -- it narrows what the rail lists, never
    what the pipeline found. The summary strip keeps reporting the unfiltered
    totals so a filter can never make the board look quieter than it is."""
    out = [v for v in views
           if flt in (None, "all") or (v["severity"] or "unrated") == flt]
    return [v for v in out if _matches(v, q)]


def build_investigate_page(sensor_filter="all", rng="ALL", selected=None,
                           tab=DEFAULT_TAB, flt="all", q=""):
    inst = None if sensor_filter in (None, "all") else sensor_filter
    iv = _investigation(rng or "ALL", inst)
    views, summary = iv["queue"], iv["summary"]
    listed = _apply_filters(views, flt, q)

    # Open on the first detection rather than an empty pane: the page should
    # arrive showing an investigation, not asking for one to be started.
    chosen = next((v for v in listed if v["key"] == selected), None) or \
        (listed[0] if listed else None)

    header = html.Div(className="iv-topbar", children=[
        html.Div(className="iv-brand", children=[
            html.Div([html.Span("HydraPoT", className="iv-brand-1"),
                      html.Span(" / ", className="iv-brand-sep"),
                      html.Span("Investigation", className="iv-brand-2")]),
            html.Div("Correlated activity requiring analyst attention",
                     className="iv-sub"),
        ]),
        html.Div(className="hp-range", children=[
            html.Button(r, id={"type": "range-btn", "r": r}, n_clicks=0,
                        className="active" if r == (rng or "ALL") else "")
            for r in ["15m", "1h", "24h", "7d", "ALL"]
        ]),
    ])

    return [
        dcc.Store(id="iv-state",
                  data={"key": chosen["key"] if chosen else None, "tab": tab,
                        "filter": flt, "q": q}),
        header,
        _summary_strip(summary),
        html.Div(className="iv-ws", children=[
            html.Div(className="iv-rail", children=[
                html.Div(className="iv-rail-h", children=[
                    html.Span("Investigation Queue"),
                    html.Span(f"{len(listed)}/{len(views)}"
                              if len(listed) != len(views) else f"{len(views)}",
                              id="iv-rail-count", className="iv-rail-n")]),
                _queue_toolbar(summary.get("by_severity") or {}, flt, q, len(views)),
                html.Div(_queue(listed, chosen["key"] if chosen else None),
                         id="iv-queue-wrap", className="iv-rail-body"),
            ]),
            html.Div(_detail(chosen, tab), id="iv-detail", className="iv-main"),
        ]),
    ]


@app.callback(
    Output("iv-detail", "children"),
    Output("iv-queue-wrap", "children"),
    Output("iv-rail-count", "children"),
    Output("iv-state", "data"),
    Input({"type": "iv-select", "key": ALL}, "n_clicks"),
    Input({"type": "iv-tab", "tab": ALL}, "n_clicks"),
    Input({"type": "iv-filter", "f": ALL}, "n_clicks"),
    Input({"type": "iv-alert-act", "key": ALL, "state": ALL}, "n_clicks"),
    Input("iv-search", "value"),
    State("iv-state", "data"),
    State("range-store", "data"),
    State("sensor-filter-store", "data"),
    prevent_initial_call=True,
)
def _investigate_interact(_sel, _tabs, _flt, _acts, q, state, rng, sensor_filter):
    """Every in-page interaction, in one callback.

    One callback rather than four so the pieces of state stay consistent:
    changing detection keeps the tab, changing filter keeps the selection when
    it survives the filter, and searching never silently strands the analyst on
    a detection the rail no longer lists.

    A pattern-matching Input also fires when its components are CREATED with
    n_clicks=0, and this callback re-renders the components it listens to --
    so without the guard it would retrigger itself in a loop. The search box is
    exempt: it is a plain value Input, and typing must go through.
    """
    if not ctx.triggered:
        raise PreventUpdate
    trig = ctx.triggered_id
    from_search = trig == "iv-search"
    if not from_search:
        if not ctx.triggered[0].get("value") or not isinstance(trig, dict):
            raise PreventUpdate

    state = dict(state or {})
    if from_search:
        state["q"] = q or ""
    elif trig.get("type") == "iv-select":
        state["key"] = trig.get("key")
    elif trig.get("type") == "iv-tab":
        state["tab"] = trig.get("tab")
    elif trig.get("type") == "iv-filter":
        state["filter"] = trig.get("f")
    elif trig.get("type") == "iv-alert-act":
        # The one interaction on this page that WRITES. Everything else
        # re-reads the pipeline; this records what a person decided, so it must
        # happen before the view is rebuilt or the page would show the old
        # state for a second and look like the click was lost.
        import storage
        inst = None if sensor_filter in (None, "all") else sensor_filter
        try:
            storage.set_alert_state(trig.get("key"), trig.get("state"),
                                    instance=inst or "default")
        except Exception as e:
            print(f"[alerts] state change failed: {e}")
        state["key"] = trig.get("key")
    else:
        raise PreventUpdate

    inst = None if sensor_filter in (None, "all") else sensor_filter
    iv = _investigation(rng or "ALL", inst)
    views = iv["queue"]
    listed = _apply_filters(views, state.get("filter", "all"), state.get("q", ""))

    chosen = next((v for v in listed if v["key"] == state.get("key")), None) or \
        (listed[0] if listed else None)
    state["key"] = chosen["key"] if chosen else None

    count = (f"{len(listed)}/{len(views)}" if len(listed) != len(views)
             else f"{len(views)}")
    return (_detail(chosen, state.get("tab", DEFAULT_TAB)),
            _queue(listed, state["key"]), count, state)
