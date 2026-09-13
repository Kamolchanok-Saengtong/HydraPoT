"""
SIEM/theme.py — color palette, Plotly/Dash chrome, and the app's CSS.

Shared across pages/*.py: colors, TABLE_STYLE, theme_layout()/GRAPH_CONFIG,
FI_LABEL/FI_COLOR/THREAT_LEVEL, AGENT_LABEL/AGENT_COLOR. Importing this module
also sets app.index_string as a side effect (the CSS has to live on the app
object somewhere, and this is the "how things look" module).
"""
import plotly.graph_objects as go

from SIEM.server import app

INK         = "#171512"   # primary text / borders
INK_2       = "#3A342C"
INK_3       = "#6F685C"   # muted text
PAPER       = "#FFFCF2"   # page background — the original HydraPoT cream
CARD        = "#FFFFFF"   # cards sit lighter than the page so panels lift off it
Y_50        = "#FDF6E3"
Y_100       = "#FBEFC9"
Y_200       = "#F7E3A1"
Y_300       = "#F6CF5C"
Y_400       = "#F5B21B"   # primary HydraPoT accent
Y_500       = "#E09B10"
Y_700       = "#9A6B08"
LINE        = "rgba(38, 35, 31, 0.14)"

# FI_LABEL/FI_COLOR/THREAT_LEVEL: referenced throughout this file (session
# detail, danger cards, MITRE body, full history table) but never defined --
# every one of those call sites raised NameError the moment it actually ran.
# Reuses fi_manager.FI_LABELS (the one real definition of what each FI score
# 0-4 means) rather than inventing separate wording here.
from prompt.fi_manager import FI_LABELS as FI_LABEL
FI_COLOR = {0: "#9aa3ad", 1: "#6fb1ff", 2: Y_300, 3: "#ff9f5a", 4: "#ff6b6b"}
# {fi: (label, color, icon)} -- same 0-4 scale, phrased as a threat level for
# the session-level "peak FI reached" summary rather than a single command.
THREAT_LEVEL = {
    0: ("Low", FI_COLOR[0], "🟢"),
    1: ("Elevated", FI_COLOR[1], "🔵"),
    2: ("Moderate", FI_COLOR[2], "🟡"),
    3: ("High", FI_COLOR[3], "🟠"),
    4: ("Critical", FI_COLOR[4], "🔴"),
}
LINE_STRONG = "rgba(38, 35, 31, 0.28)"

# Semantic colours — used ONLY for what they mean, never decoratively.
ORANGE      = "#C45A0A"   # attack / activity volume
CRITICAL    = "#D92D20"   # critical + high severity only
SUCCESS     = "#159447"   # healthy / online / savings
SIDEBAR_BG  = "#171512"   # dark charcoal rail
SIDEBAR_FG  = "#CFC7B8"
SIDEBAR_MUT = "#8A8175"
TERMINAL_BG = "#171512"

AMBER_SCALE = [Y_300, Y_500, Y_700]
AGENT_COLOR_AMBER = {"cowrie": Y_500, "on_device": Y_300, "cloud": INK, "unknown": INK_3}

# Agent identity — one label and one colour per agent, shared by every panel.
# These were previously inlined in both _hydrapot_intel() and _agent_donut(),
# where the colour maps had silently diverged (cowrie grey in one, amber in
# the other, side by side on the same screen).
AGENT_LABEL = {"cowrie": "Cowrie (Traditional)",
               "on_device": "On-device LLM",
               "cloud": "Cloud LLM"}
AGENT_COLOR = {"cowrie": Y_300, "on_device": Y_400, "cloud": ORANGE}

# ── Plotly chart chrome helper (consistent ink/amber theme) ───────────────────

# Every dcc.Graph uses this. `responsive` is the important half: without it
# Plotly measures the container ONCE at mount and bakes that pixel width into
# the SVG. Collapsing the sidebar widens the content area via CSS, but the
# chart keeps its old width — which is why bars looked lopsided (chart offset
# inside a container that had grown around it). With responsive:True Plotly
# watches the container and re-lays out on resize.
GRAPH_CONFIG = {"displayModeBar": False, "responsive": True}

# The world map is a fixed reference view, not something to explore: scrolling
# past it would otherwise zoom the globe instead of the page, and a stray drag
# would leave it rotated with no visible way to reset. Hover/tooltips still
# work — only zoom and pan are off. `staticPlot` would kill hover too, which is
# why this disables the two interactions specifically.
GEO_CONFIG = {"displayModeBar": False, "responsive": True,
              "scrollZoom": False, "doubleClick": False}


def theme_layout(fig, height=None, legend=False):
    layout_kwargs = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="JetBrains Mono, monospace", color=INK_3, size=12),
        margin=dict(t=10, b=10, l=10, r=10),
        # let the figure take its width from the container instead of pinning
        # whatever width happened to exist at first render
        autosize=True,
    )
    if height:
        layout_kwargs["height"] = height
    if not legend:
        layout_kwargs["showlegend"] = False
    fig.update_layout(**layout_kwargs)
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor=LINE_STRONG, tickfont=dict(color=INK_3))
    fig.update_yaxes(showgrid=True, gridcolor=LINE, zeroline=False, linecolor=LINE_STRONG, tickfont=dict(color=INK_3))
    return fig

def empty_geo_fig():
    fig = go.Figure(go.Scattergeo())
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        geo=dict(bgcolor="rgba(0,0,0,0)", landcolor=Y_100, showocean=True,
                  oceancolor=PAPER, coastlinecolor=LINE_STRONG, showcountries=True,
                  countrycolor=LINE_STRONG),
        height=320, margin=dict(t=0, b=0, l=0, r=0),
    )
    return fig

app.index_string = """
<!DOCTYPE html>
<html>
<head>
  {%metas%}
  <title>{%title%}</title>
  {%favicon%}
  {%css%}
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --y-50: """ + Y_50 + """; --y-100: """ + Y_100 + """; --y-200: """ + Y_200 + """;
      --y-300: """ + Y_300 + """; --y-400: """ + Y_400 + """; --y-500: """ + Y_500 + """; --y-700: """ + Y_700 + """;
      --ink: """ + INK + """; --ink-2: """ + INK_2 + """; --ink-3: """ + INK_3 + """;
      --paper: """ + PAPER + """; --line: """ + LINE + """; --line-strong: """ + LINE_STRONG + """;
      /* Motion tokens. Two curves and three durations cover every interaction
         on this dashboard; freestyling a fourth is how a UI starts to feel
         uncrafted. --dur-tick is "instant feedback" (a press), --dur-hover is
         a state transition, --dur-open is a panel/sheet appearing. */
      /* Type scale. The stylesheet had 34 distinct font sizes with 24 of them
         crammed between 9-14px and neighbouring steps differing by 1-3% —
         imperceptible, so nothing on the page announced itself as more
         important than anything else. Six steps at a ~1.25 ratio, each one
         obviously different from its neighbour. */
      --text-2xs: 0.68rem;   /* micro labels, chips */
      --text-xs:  0.76rem;   /* captions, secondary */
      --text-sm:  0.88rem;   /* body, table cells */
      --text-md:  1.00rem;   /* panel titles */
      --text-lg:  1.35rem;   /* section headings, stat values */
      --text-xl:  1.90rem;   /* KPI numbers */
      --text-2xl: 2.30rem;   /* page title */
      --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
      --ease-in-out: cubic-bezier(0.65, 0, 0.35, 1);
      --dur-tick: 90ms; --dur-hover: 170ms; --dur-open: 260ms;
      --focus: """ + ORANGE + """;
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      /* `clip`, NOT `hidden`. Both stop sideways scrolling, but `hidden` makes
         overflow-y compute to `auto`, which turns body into a scroll
         container — and then the sticky sidebar anchors to body (which scrolls
         away with the page) instead of the viewport, so it never sticks.
         `clip` contains the overflow without creating a scroll container, so
         sticky keeps working. */
      overflow-x: clip;
      width: 100%;
    }
    body {
      font-family: 'Inter', system-ui, sans-serif;
      background: var(--paper);
      color: var(--ink);
      background-image:
        radial-gradient(circle at 15% 0%, rgba(252, 211, 77, 0.20) 0%, transparent 40%),
        radial-gradient(circle at 90% 60%, rgba(251, 191, 36, 0.14) 0%, transparent 45%);
    }
    h1,h2,h3,h4,h5 { font-weight:800; letter-spacing:-0.02em; color:var(--ink); margin:0; }

    .app-shell {
      display:flex; min-height:100vh;
      width: 100%;
      max-width: 100vw;
      /* NO overflow here on purpose. `overflow-x: hidden` used to sit on this
         rule, and per spec that makes overflow-y compute to `auto` — turning
         .app-shell into a scroll container. position:sticky then resolves
         against .app-shell instead of the viewport, so the sidebar would
         scroll away exactly as before and the sticky would look broken for no
         visible reason. Horizontal overflow is still contained: .content has
         its own `overflow-x: hidden` + `min-width: 0`, which is what actually
         fixed the sideways-scrolling page. */
    }
    /* the nav sidebar must never be what widens the layout */
    .sidebar { flex-shrink: 0; }

    /* Sidebar */
    .sidebar {
  width: 260px; flex-shrink:0;
  background: var(--y-50);
  border-right: 2px solid var(--ink);
  padding: 70px 20px 24px 20px;   /* was: 24px 20px — extra top padding clears the floating button */
  display:flex; flex-direction:column; gap:14px;
  transition: width 0.2s ease, padding 0.2s ease, opacity 0.15s ease;

  /* Stick to the viewport instead of scrolling away with the page. On a long
     Summary page the nav used to disappear upward and leave a blank yellow
     column behind it.
       align-self:flex-start — REQUIRED. A flex child defaults to
         align-self:stretch, which makes the sidebar as tall as the whole
         scrolling page; sticky then has nothing to travel within and never
         engages. This one line is what makes position:sticky actually work.
       max-height/overflow-y — if the nav is ever taller than the viewport it
         scrolls on its own rather than being clipped.
       overflow-x stays hidden so the width collapse animation still clips. */
  position: sticky;
  top: 0;
  align-self: flex-start;
  /* height, NOT max-height. align-self:flex-start is required for sticky to
     engage, but it also stops the sidebar stretching to the container height —
     so with max-height the column was only as tall as its own content and the
     yellow panel + right border ended partway down the screen, leaving bare
     page below it. A fixed 100vh keeps it a full-height column at every scroll
     position (box-sizing is border-box globally, so padding is included). */
  height: 100vh;
  overflow-y: auto;
  overflow-x: hidden;

  /* Keep the overflow behaviour, hide the scrollbar chrome. On a short window
     the nav is taller than 100vh, so `overflow-y: auto` drew a second
     scrollbar down the middle of the layout next to the page's own. The nav
     still scrolls (wheel/trackpad/keyboard) — only the bar is hidden, which is
     the usual treatment for a short nav column. */
  scrollbar-width: none;        /* Firefox */
  -ms-overflow-style: none;     /* old Edge/IE */
}
.sidebar::-webkit-scrollbar { width: 0; height: 0; }   /* Chrome/Safari */
.sidebar.collapsed {
  width: 0;
  padding: 70px 0 24px 0;   /* keep top padding consistent on collapse */
  opacity: 0;
  pointer-events: none;
}
    .sidebar-logo { font-size:1.3rem; font-weight:800; display:flex; align-items:center; gap:10px; white-space:nowrap; }

    /* The logo already carries its own drop shadow, so it needs no border or
       box-shadow from us. flex-shrink:0 keeps it square while the sidebar
       animates its width on collapse — without it the mark squashes. */
    .brand-mark { width:30px; height:30px; flex-shrink:0; display:block; }
    .brand-mark-lg { width:34px; height:34px; }
    .page-title { display:flex; align-items:center; gap:12px;
                   font-size:var(--text-2xl); letter-spacing:-0.03em; }
    .sidebar-caption { font-size:0.78rem; color:var(--ink-3); line-height:1.5; font-family:'JetBrains Mono',monospace; }
    .sidebar-divider { border-top: 1.5px solid var(--line-strong); margin: 6px 0; }
    .nav-pill {
      background: var(--paper); border:2px solid var(--ink); border-radius:999px;
      padding:9px 16px; font-weight:600; font-size:0.85rem; cursor:pointer;
      text-align:left; transition: all 0.15s; white-space:nowrap;
    }
    .nav-pill:hover { background: var(--y-100); }
    .nav-pill.active { background: var(--ink); color: var(--y-300); }
    .toggle-row { display:flex; align-items:center; justify-content:space-between; font-size:0.85rem; font-weight:600; }
    .refresh-btn {
      background: var(--ink); color: var(--y-300); border:2px solid var(--ink);
      border-radius:999px; padding:8px 14px; font-weight:600; cursor:pointer; font-size:0.85rem;
      transition: all 0.15s; white-space:nowrap;
    }
    .refresh-btn:hover { background: var(--y-400); color: var(--ink); }
    .status-pill {
      border:1.5px solid var(--ink); border-radius:10px; padding:8px 10px;
      font-size:0.78rem; font-family:'JetBrains Mono',monospace; font-weight:600;
    }
    .status-ok { background: #eaf7ee; color:#1f7a3a; }
    .status-warn { background: var(--y-100); color: var(--y-700); }
    /* reserves space so the badge popping in after load doesn't push the
       rest of the sidebar down (a real, measurable CLS contributor) */
    #geo-status { min-height: 36px; }
    .source-cap { font-size:0.72rem; color:var(--ink-3); font-family:'JetBrains Mono',monospace; word-break:break-all; }

    /* Sidebar toggle (floating button, always visible) */
    .sidebar-toggle {
      position: fixed; top: 20px; left: 16px; z-index: 50;
      background: var(--ink); color: var(--y-300); border:2px solid var(--ink);
      border-radius:10px; width:38px; height:38px; cursor:pointer;
      font-size:1.1rem; display:flex; align-items:center; justify-content:center;
      transition: left 0.2s ease;
    }
    .sidebar-toggle:hover { background: var(--y-400); color: var(--ink); }

    /* Content */
    .content {
      flex:1; padding: 32px 36px 32px 70px; max-width: 1500px;
      min-width: 0;
      overflow-x: hidden;
      width: 100%;
    }

    /* Section header */
    .section-header {
      font-size:var(--text-lg); font-weight:800; letter-spacing:-0.01em;
      margin: 18px 0 12px; display:flex; align-items:center; gap:8px; color: var(--ink);
    }
    .section-header:before {
      content:""; width:8px; height:8px; background:var(--y-400);
      border:1.5px solid var(--ink); border-radius:3px; display:inline-block;
    }

    /* Metric cards */
    .metric-row { display:flex; gap:16px; flex-wrap:wrap; margin: 14px 0; }
    .metric-card {
      background: var(--paper); border:2px solid var(--ink); border-radius:14px;
      padding:14px 18px; box-shadow:4px 4px 0 var(--ink); flex:1; min-width:140px;
    }
    .metric-label {
      font-family:'JetBrains Mono',monospace; text-transform:uppercase; letter-spacing:0.08em;
      font-size:0.68rem; color:var(--ink-3); margin-bottom:6px;
    }
    .metric-value { font-weight:800; font-size:1.7rem; color:var(--ink); }
    .metric-sub { font-size:0.68rem; color:var(--ink-3); margin-top:4px;
      font-family:'JetBrains Mono',monospace; }
    /* Cost/energy cards — stand out in green so they read at a glance */
    .metric-card.cost-card {
      background:#0f8a4d; border-color:#0a5c34; box-shadow:4px 4px 0 #0a5c34;
    }
    .metric-card.cost-card .metric-label { color:#d6ffe6; }
    .metric-card.cost-card .metric-value { color:#ffffff; }
    .metric-card.cost-card .metric-sub { color:#bff0d1; font-size:0.65rem;
      font-family:'JetBrains Mono',monospace; margin-top:4px; }
    .threat-badge { border-radius:14px; padding:12px; text-align:center; border:2px solid var(--ink); flex:1; min-width:140px; }
    /* ── MITRE ATT&CK page ── */
    /* align-items:start on BOTH grids: otherwise the sidebar stretches to the
       card row's height and every card stretches to the tallest one, which is
       what produced the dead space under the trend charts (#3, #4). */
    /* min-width:0 on every grid child: a grid track's default min-width is
       "auto" (= its content), so a wide table or chart refuses to shrink and
       shoves the whole page sideways. This is what made the page drift
       horizontally instead of just scrolling down. */
    .mitre-grid { display:grid; grid-template-columns: 320px minmax(0, 1fr);
                  gap:16px; align-items:start; width:100%; }
    .mitre-grid > * { min-width:0; }
    .mitre-side { display:flex; flex-direction:column; min-width:0; }
    .tech-card { width:100%; margin-top:14px; }
    .tech-card .stage-body { padding:6px 10px 2px; }
    /* Sankey + playbooks sit side by side on desktop and stack under 1100px,
       matching how .mitre-grid already behaves. */
    .chain-grid { display:grid; grid-template-columns: 1.45fr 1fr;
                  gap:14px; margin-top:14px; align-items:start; }
    @media (max-width: 1100px) { .chain-grid { grid-template-columns: 1fr; } }
    /* -- Kill Chain Flow -------------------------------------------------
       A horizontal rail of tactic columns in MITRE order. Same sticker
       language as .stage-card (2px ink border, 14px radius, hard offset
       shadow) so it belongs to this page rather than looking imported.
       Severity is the only saturated colour used here; amber stays reserved
       for the page accent. Colours come from CSS vars, so the palette has a
       single source of truth. */
    .kc-rail { display:flex; align-items:stretch; gap:0;
               overflow-x:auto; padding:4px 2px 14px; scroll-snap-type:x proximity; }
    .kc-col { flex:0 0 208px; scroll-snap-align:start; background:#FFFFFF;
              border:2px solid var(--ink); border-radius:14px;
              box-shadow:3px 3px 0 var(--ink);
              display:flex; flex-direction:column; overflow:hidden; }
    .kc-head { padding:9px 11px 8px; background:var(--paper);
               border-bottom:3px solid var(--ink); }
    .kc-head-top { display:flex; align-items:center; justify-content:space-between; }
    .kc-ord { font-family:'JetBrains Mono',monospace; font-size:0.72rem;
              font-weight:700; color:var(--ink-3); letter-spacing:0.06em; }
    .kc-badge { font-family:'JetBrains Mono',monospace; font-size:0.68rem;
                font-weight:700; color:#fff; padding:2px 7px; border-radius:9px;
                border:1.5px solid var(--ink); font-variant-numeric:tabular-nums; }
    .kc-tactic { font-size:0.82rem; font-weight:700; color:var(--ink);
                 margin-top:5px; line-height:1.25; text-wrap:balance; }
    .kc-stack { display:flex; flex-direction:column; gap:7px; padding:9px; }
    .kc-card { text-align:left; width:100%; cursor:pointer; font:inherit;
               background:var(--paper); border:1.5px solid var(--line-strong);
               border-left:5px solid var(--ink); border-radius:9px; padding:8px 9px;
               transition:transform .12s ease, box-shadow .12s ease; }
    .kc-card:hover { transform:translate(-1px,-1px); box-shadow:2px 2px 0 var(--ink); }
    .kc-card:focus-visible { outline:2.5px solid var(--y-400); outline-offset:2px; }
    .kc-card-top { display:flex; align-items:center; justify-content:space-between; gap:6px; }
    .kc-tid { font-family:'JetBrains Mono',monospace; font-size:0.73rem;
              font-weight:700; color:var(--ink); }
    .kc-count { font-family:'JetBrains Mono',monospace; font-size:0.63rem;
                font-weight:700; color:#fff; padding:1px 6px; border-radius:8px;
                font-variant-numeric:tabular-nums; }
    .kc-tname { font-size:0.72rem; color:var(--ink-2); line-height:1.35; margin-top:3px; }
    .kc-card-foot { display:flex; justify-content:space-between; align-items:center;
                    margin-top:6px; }
    .kc-sev { font-family:'JetBrains Mono',monospace; font-size:0.6rem;
              font-weight:700; letter-spacing:0.07em; }
    .kc-sess { font-family:'JetBrains Mono',monospace; font-size:0.6rem; color:var(--ink-3); }
    .kc-chevron { flex:0 0 26px; display:flex; align-items:center;
                  justify-content:center; font-size:1.5rem; line-height:1;
                  color:var(--ink-3); user-select:none; }
    /* Drill-down side sheet. Off-canvas by default; .kc-open slides it in. */
    .kc-sheet { position:fixed; top:0; right:0; height:100vh; width:min(620px,94vw);
                background:#FFFFFF; border-left:3px solid var(--ink);
                box-shadow:-6px 0 0 rgba(38,35,31,0.10);
                transform:translateX(102%); transition:transform .22s ease;
                z-index:1200; overflow-y:auto; padding:18px 20px 28px; }
    .kc-sheet.kc-open { transform:translateX(0); }
    @media (prefers-reduced-motion: reduce) {
      .kc-sheet { transition:none; } .kc-card { transition:none; }
    }
    .kc-close { position:absolute; top:12px; right:14px; cursor:pointer;
                background:var(--paper); border:2px solid var(--ink);
                border-radius:9px; width:30px; height:30px; font-size:0.9rem;
                line-height:1; color:var(--ink); }
    .kc-close:hover { background:var(--y-200); }
    .kc-detail-head { padding-right:40px; }
    .kc-detail-id { font-family:'JetBrains Mono',monospace; font-size:1.15rem;
                    font-weight:700; color:var(--ink); }
    .kc-detail-sev { font-family:'JetBrains Mono',monospace; font-size:0.62rem;
                     font-weight:700; color:#fff; padding:2px 8px; border-radius:9px;
                     margin-left:9px; vertical-align:middle; border:1.5px solid var(--ink); }
    .kc-detail-name { font-size:0.95rem; color:var(--ink-2); margin-top:3px; }
    .kc-facts { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
                gap:8px; margin-top:14px; }
    .kc-fact { background:var(--paper); border:1.5px solid var(--line-strong);
               border-radius:9px; padding:7px 9px; }
    .kc-fact-l { font-family:'JetBrains Mono',monospace; font-size:0.58rem;
                 letter-spacing:0.08em; color:var(--ink-3); }
    .kc-fact-v { font-size:0.82rem; font-weight:600; color:var(--ink);
                 margin-top:2px; word-break:break-word; }
    .chain-pick { display:flex; align-items:center; gap:10px;
                  margin:2px 0 10px; flex-wrap:wrap; }
    .chain-pick .Select-control, .chain-pick .is-searchable {
                  border:2px solid var(--ink) !important; border-radius:10px !important; }
    .side-head { font-weight:700; font-size:0.86rem; margin-bottom:6px; display:flex;
                 align-items:center; gap:7px; }
    .side-head:before { content:""; width:7px; height:7px; background:var(--y-400);
                        border:1.5px solid var(--ink); border-radius:3px; }
    .stage-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                  gap:14px; align-items:start; min-width:0; }
    .stage-grid > * { min-width:0; }
    .stage-card { background:var(--paper); border:2px solid var(--ink); border-radius:14px;
                  box-shadow:4px 4px 0 var(--ink); overflow:hidden;
                  display:flex; flex-direction:column; height:fit-content; }
    .stage-head { color:#fff; font-weight:800; letter-spacing:0.06em; font-size:0.86rem;
                  padding:9px 13px; border-bottom:2px solid var(--ink); }
    .stage-body { padding:10px 12px 4px; }
    .stage-top { display:flex; gap:8px; align-items:center; }
    .stage-tactics { flex:0 0 42%; display:flex; flex-direction:column; gap:4px; }
    .stage-tactic { font-family:'JetBrains Mono',monospace; font-size:0.68rem; line-height:1.25;
                    background:var(--y-100); border:1.5px solid var(--line-strong);
                    border-radius:6px; padding:3px 6px; }
    .donut-key { display:flex; justify-content:center; gap:9px; margin-top:-6px; }
    .key-item { font-family:'JetBrains Mono',monospace; font-size:0.6rem; color:var(--ink-3);
                display:inline-flex; align-items:center; gap:3px; }
    .key-dot { width:7px; height:7px; border-radius:50%; display:inline-block;
               border:1px solid var(--ink); }
    .sev-row { display:flex; gap:7px; margin:8px 0 0; }
    .sev-badge { flex:1; text-align:center; background:var(--y-50);
                 border:1.5px solid var(--line-strong); border-radius:9px; padding:5px 3px; }
    .sev-dot { display:block; width:10px; height:10px; border-radius:50%;
               margin:0 auto 3px; border:1.5px solid var(--ink); }
    .sev-n { font-weight:800; font-size:1.05rem; color:var(--ink); }
    .sev-lbl { font-size:0.58rem; color:var(--ink-3); font-family:'JetBrains Mono',monospace;
               text-transform:uppercase; letter-spacing:0.03em; margin-top:1px; }
    @media (max-width: 1100px) { .mitre-grid { grid-template-columns: 1fr; } }

    .sensor-card {
      font-family:'Inter',sans-serif; text-align:left; cursor:pointer;
      transition: all 0.15s;
    }
    .sensor-card:hover { background: var(--y-100); }
    .sensor-card.active { background: var(--ink); }
    .sensor-card.active .metric-label,
    .sensor-card.active .metric-value,
    .sensor-card.active .metric-sub { color: var(--y-300); }

    /* Terminal feed */
    .terminal-feed {
      background: var(--ink); border-radius:16px; overflow:hidden;
      box-shadow: 0 1px 0 rgba(255,255,255,0.05) inset, 8px 8px 0 var(--y-400), 8px 8px 0 1px var(--ink);
      font-family:'JetBrains Mono',monospace; font-size:0.78rem; line-height:1.6; color:#E8DBC6;
      margin: 14px 0;
      min-width: 0;
      max-width: 100%;
    }
    .term-chrome { background:#2A2118; padding:10px 16px; display:flex; align-items:center; gap:8px; border-bottom:1px solid rgba(255,255,255,0.08); }
    .term-dot { width:11px; height:11px; border-radius:50%; }
    .dot-r { background:#FF5F56; } .dot-y { background:#FFBD2E; } .dot-g { background:#27C93F; }
    .term-chrome-title { color:rgba(255,255,255,0.45); font-size:0.7rem; margin-left:8px; }
    .term-header { color:var(--y-300); font-weight:700; padding:12px 16px 4px; font-size:0.82rem; }
    .term-body { padding:4px 16px 16px; max-height:280px; overflow-y:auto; overflow-x:hidden; min-width:0; }
    /* Big-screen wallboard (the Live page). Same markup as the Summary panel,
       just sized to fill a monitor: bigger type and a body that grows with the
       viewport instead of the fixed 280px the embedded panel uses. */
    .terminal-big { margin:0; font-size:1.02rem; line-height:1.75; }
    .terminal-big .term-body { max-height: calc(100vh - 190px); padding:8px 22px 22px; }
    .terminal-big .term-header { font-size:1.05rem; padding:14px 22px 6px; }
    .terminal-big .term-chrome-title { font-size:0.82rem; }
    @media (max-width: 900px) {
      .terminal-big { font-size:0.86rem; }
      .terminal-big .term-body { max-height: calc(100vh - 150px); }
    }
    .term-line {
      margin:2px 0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
      max-width: 100%;
    }
    .term-time { color:#6e7681; }
    .term-ip { color: var(--y-400); }
    .term-cmd { color:#E8DBC6; }
    .term-fi0 { color:#9aa3ad; } .term-fi1 { color:#6fb1ff; } .term-fi2 { color: var(--y-300); }
    .term-fi3 { color:#ff9f5a; } .term-fi4 { color:#ff6b6b; font-weight:700; }
    .term-agent-cowrie { color:#6fdb8f; } .term-agent-on_device { color: var(--y-300); } .term-agent-cloud { color:#ff6b6b; }
    .term-login { color:#6fdb8f; }
    .term-separator { color:#463826; }

    /* Stat box (auth breakdown) */
    .stat-box {
      background: var(--paper); border:2px solid var(--ink); border-radius:14px;
      padding:16px 18px; font-size:0.85rem; line-height:2.2; font-family:'JetBrains Mono',monospace;
      box-shadow:4px 4px 0 var(--ink);
    }
    .stat-box hr { border-color: var(--line-strong); margin: 8px 0; }

    /* Dangerous command card */
    .danger-card {
      background: var(--paper); border:1.5px solid var(--ink); border-radius:8px;
      padding:8px 12px; margin-bottom:6px; font-family:'JetBrains Mono',monospace;
      box-shadow:2px 2px 0 rgba(26,20,16,0.15);
    }

    .caption { color: var(--ink-3); font-family:'JetBrains Mono',monospace; font-size:0.78rem; }
    .empty-state {
      background: var(--y-100); border:1.5px solid var(--ink); border-radius:10px;
      padding: 12px 16px; font-size:0.9rem; color: var(--ink-2);
    }

    hr.divider { border:none; border-top:1.5px solid var(--line-strong); margin: 18px 0; }

    .grid-2 { display:grid; grid-template-columns: 3fr 2fr; gap: 24px; min-width:0; }
    .grid-4 { display:grid; grid-template-columns: repeat(4, 1fr); gap: 16px; min-width:0; }
    .grid-2 > div, .grid-4 > div { min-width: 0; overflow-x: auto; }
    @media (max-width: 1100px) {
      .grid-2 { grid-template-columns: 1fr; }
      .grid-4 { grid-template-columns: repeat(2, 1fr); }
    }

    /* Dash DataTable container border */
    .dash-table-container { border:2px solid var(--ink) !important; border-radius:12px !important; overflow:hidden !important; max-width:100% !important; }

    select.dd {
      border:2px solid var(--ink) !important; border-radius:10px !important;
      background: var(--paper) !important; font-family:'Inter',sans-serif !important;
    }
    /* ════════════════════════════════════════════════════════════════════
       SOC REDESIGN — appended so these rules win over the originals above.
       Layout/appearance only; no data, callback or id is affected.
       ════════════════════════════════════════════════════════════════════ */

    /* ── dark sidebar rail ────────────────────────────────────────────── */
    .sidebar {
    width: 232px;
    background: """ + SIDEBAR_BG + """;
    border-right: 1px solid """ + SIDEBAR_BG + """;
    padding: 22px 16px 18px 16px;
    overflow-x: hidden;          /* keep — needed for the collapse animation */
    transition: width 0.2s ease, padding 0.2s ease, opacity 0.15s ease;
    }
    .sidebar-logo { color: #fff; font-size: 1.18rem; }
    .sidebar-caption { color: """ + SIDEBAR_MUT + """; font-size: 0.72rem; line-height: 1.55;
                        font-family: 'Inter', sans-serif; }
    .sidebar-divider { border-top: 1px solid rgba(255,255,255,0.10); margin: 4px 0; }

    .nav-pill {
      background: transparent; color: """ + SIDEBAR_FG + """;
      border: none; border-radius: 8px;
      padding: 9px 12px; font-size: 0.87rem; font-weight: 600;
      text-align: left; width: 100%; cursor: pointer;
      display: flex; align-items: center; gap: 10px;
    }
    .nav-pill:hover { background: rgba(255,255,255,0.06); color: #fff; }
    /* active = warm dark-brown wash + gold text + gold edge, per spec */
    .nav-pill.active {
      background: rgba(245,178,27,0.13); color: """ + Y_400 + """;
      box-shadow: inset 2px 0 0 """ + Y_400 + """;
    }

    .sidebar .toggle-row { color: """ + SIDEBAR_MUT + """; font-size: 0.7rem;
                            letter-spacing: 0.08em; text-transform: uppercase; }
    .sidebar .source-cap { color: """ + SIDEBAR_MUT + """; font-size: 0.66rem; }
    .refresh-btn { background: rgba(255,255,255,0.07); color: """ + SIDEBAR_FG + """;
                    border: 1px solid rgba(255,255,255,0.12); border-radius: 8px;
                    padding: 8px 10px; font-size: 0.78rem; cursor: pointer; }
    .refresh-btn:hover { background: """ + Y_400 + """; color: """ + INK + """; }

    /* agent health box */
    .hp-status { border: 1px solid rgba(255,255,255,0.13); border-radius: 10px;
                  padding: 11px 12px; margin-top: 4px; }
    .hp-status-h { color: """ + Y_400 + """; font-size: 0.64rem; font-weight: 800;
                    letter-spacing: 0.1em; margin-bottom: 8px; }
    .hp-status-row { display:flex; align-items:center; justify-content:space-between;
                      font-size: 0.75rem; color: """ + SIDEBAR_FG + """; padding: 3px 0; }
    .hp-dot { width:7px; height:7px; border-radius:50%; display:inline-block; margin-right:7px; }
    .hp-tally { text-align:center; border:1px solid rgba(255,255,255,0.13);
                 border-radius:10px; padding:10px; margin-top:10px; }
    .hp-tally-n { font-size:1.5rem; font-weight:800; color:""" + SUCCESS + """; }
    .hp-tally-l { font-size:0.6rem; letter-spacing:0.1em; color:""" + SIDEBAR_MUT + """; }

    /* ── page chrome ──────────────────────────────────────────────────── */
    .content { padding: 20px 24px; max-width: none; }

    /* The toggle is position:fixed, so it floats over whatever is beneath it.
       It therefore has to move as the sidebar does, or it covers something:
         sidebar open      -> park it at the sidebar's right edge, clear of the
                              logo (the old 70px sidebar top-padding that used
                              to clear it is gone in this layout)
         sidebar collapsed -> back to the far left, and the content gains
                              matching left padding so it can't sit on top of
                              the page header.
       Both states use the transition already on .sidebar-toggle. */
    /* Horizontal filter chips (IOC categories, DB tables).
       These used .nav-pill, which this redesign turned into a full-width flex
       row for the vertical sidebar — so they stacked into a column. They need
       their own class: a filter row is horizontal, and reusing the nav's class
       means any future nav restyle silently breaks it again. */
    .chip-row { display:flex; flex-wrap:wrap; gap:8px; margin: 4px 0 14px; }
    .chip {
      background: """ + CARD + """; color: """ + INK_2 + """;
      border: 1.5px solid """ + LINE_STRONG + """; border-radius: 9px;
      padding: 8px 15px; font-size: 0.84rem; font-weight: 700;
      font-family: 'Inter', sans-serif; letter-spacing: 0.01em;
      cursor: pointer; white-space: nowrap; width: auto;
      display: inline-flex; align-items: center; gap: 7px; line-height: 1.1;
    }
    .chip:hover { background: """ + Y_100 + """; border-color: """ + INK + """; }
    .chip.active {
      background: """ + Y_400 + """; color: """ + INK + """;
      border-color: """ + INK + """;
    }
    .chip .chip-n { font-family:'JetBrains Mono',monospace; font-size:0.75rem;
                     font-weight:700; opacity:0.72; }

    /* Action buttons on light pages (Generate Intelligence, Export STIX).
       They previously borrowed .refresh-btn, which this redesign restyled for
       the DARK sidebar — a 7%-white fill with light-grey text, i.e. all but
       invisible on cream. Same class-sharing trap as .nav-pill.
       Light fill at rest so they read as pressable, stronger on hover. */
    .btn {
      border-radius: 9px; padding: 9px 16px; cursor: pointer;
      font-family: 'Inter', sans-serif; font-size: 0.84rem; font-weight: 700;
      display: inline-flex; align-items: center; gap: 8px; width: auto;
      border: 1.5px solid """ + INK + """; color: """ + INK + """;
      transition: background 0.15s ease, box-shadow 0.15s ease, transform 0.05s ease;
    }
    .btn:active { transform: translateY(1px); }

    /* primary — the main action on the page */
    .btn-primary { background: """ + Y_200 + """; }
    .btn-primary:hover { background: """ + Y_400 + """; box-shadow: 0 2px 0 """ + INK + """; }

    /* secondary — available, but visibly not the headline action */
    .btn-secondary { background: """ + CARD + """; border-color: """ + LINE_STRONG + """; }
    .btn-secondary:hover { background: """ + Y_100 + """; border-color: """ + INK + """;
                            box-shadow: 0 2px 0 """ + INK + """; }

    /* schema crib sheet under the SQL box */
    .sql-ref { background: """ + Y_50 + """; border: 1px solid """ + LINE + """;
                border-radius: 9px; padding: 11px 13px; margin: 4px 0 14px; }
    .sql-ref-row { display: grid; grid-template-columns: 92px 1fr; gap: 10px;
                    align-items: baseline; padding: 3px 0; }
    .sql-ref-tbl { font-family: 'JetBrains Mono', monospace; font-size: 0.74rem;
                    font-weight: 800; color: """ + INK + """; }
    .sql-ref-cols { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem;
                     color: """ + INK_3 + """; line-height: 1.6; word-break: break-word; }

    .sidebar-toggle { left: 186px; }
    .sidebar.collapsed ~ .sidebar-toggle { left: 16px; }
    .sidebar.collapsed ~ .content { padding-left: 66px; }
    /* Deliberately NOT re-declaring body's background here. The original rule
       sets `background: var(--paper)` and then a pair of radial-gradients; a
       later `background:` shorthand resets background-image, which silently
       removed the warm amber glow. --paper already carries the colour. */

    .hp-head { display:flex; align-items:center; justify-content:space-between;
                gap:16px; margin-bottom:14px; }
    .hp-range { display:flex; gap:4px; background:""" + CARD + """;
                 border:1px solid """ + LINE_STRONG + """; border-radius:9px; padding:3px; }
    .hp-range button { border:none; background:transparent; cursor:pointer;
                        font-family:'JetBrains Mono',monospace; font-size:0.72rem;
                        font-weight:700; color:""" + INK_3 + """; padding:5px 11px; border-radius:6px; }
    .hp-range button.active { background:""" + Y_400 + """; color:""" + INK + """; }

    /* ── panels ───────────────────────────────────────────────────────── */
    .pcard { background:""" + CARD + """; border:1px solid """ + LINE_STRONG + """;
              border-radius:12px; padding:14px 16px; min-width:0; }
    .pcard-h { display:flex; align-items:center; justify-content:space-between;
                gap:10px; margin-bottom:12px; }
    .pcard-t { font-size:var(--text-md); font-weight:800; letter-spacing:0.04em;
                text-transform:uppercase; color:""" + INK + """;
                display:flex; align-items:center; gap:7px; }
    .pcard-t:before { content:""; width:10px; height:10px; border-radius:3px;
                       background:""" + Y_400 + """; display:inline-block; }

    /* rows — explicit minmax(0,…) so wide children can never push the page
       sideways (a plain 1fr floors at min-content and overflows) */
    .hp-row { display:grid; gap:14px; margin-bottom:14px; }
    .hp-row-feed  { grid-template-columns: minmax(0,2.45fr) minmax(0,1fr); }
    .hp-row-kpi   { grid-template-columns: repeat(4, minmax(0,1fr)) minmax(0,1.35fr); }
    .hp-row-chart { grid-template-columns: minmax(0,1.55fr) minmax(0,1fr); }
    .hp-row-bot   { grid-template-columns: minmax(0,1.25fr) minmax(0,1.1fr) minmax(0,0.9fr); }
    /* Single full-width row. The minmax(0,1fr) is load-bearing: a bare
       display:grid leaves grid items at min-width:auto, which lets a Plotly
       graph size itself from its content and collapse/overflow instead of
       filling the row. */
    .hp-row-full  { grid-template-columns: minmax(0,1fr); }
    @media (max-width: 1400px) {
      .hp-row-kpi   { grid-template-columns: repeat(2, minmax(0,1fr)); }
      .hp-row-feed, .hp-row-chart, .hp-row-bot { grid-template-columns: minmax(0,1fr); }
    }

    /* ── KPI cards ────────────────────────────────────────────────────── */
    .kpi { background:""" + CARD + """; border:1px solid """ + LINE_STRONG + """;
            border-radius:12px; padding:13px 15px; min-width:0; }
    .kpi-top { display:flex; align-items:center; gap:9px; margin-bottom:9px; }
    .kpi-ico { width:26px; height:26px; border-radius:7px; display:flex;
                align-items:center; justify-content:center; font-size:0.82rem; flex-shrink:0; }
    .kpi-l { font-size:var(--text-2xs); font-weight:800; letter-spacing:0.06em;
              text-transform:uppercase; color:""" + INK_3 + """; line-height:1.3; }
    .kpi-v { font-size:var(--text-xl); font-weight:800; letter-spacing:-0.02em; color:""" + INK + """; }
    .kpi-s { font-size:var(--text-2xs); color:""" + INK_3 + """; margin-top:3px;
              font-family:'JetBrains Mono',monospace; }
    /* only the high-impact card carries the critical colour — everything else
       stays neutral so severity actually reads as severity */
    .kpi.kpi-crit { border-color: rgba(217,45,32,0.38); }
    .kpi.kpi-crit .kpi-v { color:""" + CRITICAL + """; }
    .kpi.kpi-crit .kpi-s { color:""" + CRITICAL + """; }

    .kpi-split { display:grid; grid-template-columns:1fr 1fr; gap:9px; }
    .kpi-mini { border:1px solid """ + LINE + """; border-radius:9px; padding:9px 10px; }
    .kpi-mini.save { background:rgba(21,148,71,0.07); border-color:rgba(21,148,71,0.3); }
    .kpi-mini.energy { background:rgba(245,178,27,0.10); border-color:rgba(245,178,27,0.38); }
    .kpi-mini-l { font-size:0.56rem; font-weight:800; letter-spacing:0.07em;
                   text-transform:uppercase; color:""" + INK_3 + """; line-height:1.35; }
    .kpi-mini-v { font-size:1.18rem; font-weight:800; margin-top:3px; }

    /* ── critical alert ───────────────────────────────────────────────── */
    .alert-card { background:#FDF3F2; border:1px solid rgba(217,45,32,0.42);
                   border-radius:12px; padding:14px 16px; min-width:0; }
    .alert-h { display:flex; align-items:center; gap:8px; color:""" + CRITICAL + """;
                font-weight:800; font-size:0.8rem; letter-spacing:0.06em;
                border-bottom:1px solid rgba(217,45,32,0.22); padding-bottom:9px; margin-bottom:11px; }
    .alert-sub { font-size:0.68rem; font-weight:800; letter-spacing:0.09em;
                  color:""" + INK_2 + """; margin-bottom:9px; }
    /* The open-alerts card sits beside the 560px map. Flex column with the
       list taking the slack, so the two columns end level instead of leaving
       a third of the row empty -- and the list scrolls rather than stretching
       the row when there are many alerts. */
    .alert-card { height:100%; display:flex; flex-direction:column; }
    .alert-list { flex:1; min-height:0; overflow-y:auto; margin:12px 0 8px;
                  display:flex; flex-direction:column; gap:2px; }
    .alert-card-quiet .caption { flex:1; }
    .alert-card .btn-cta { width:100%; margin-top:auto; }

    /* One open alert. A real <button> so it is keyboard-reachable, styled flat
       so eight of them read as a list rather than eight nested cards. */
    .alert-row { display:block; width:100%; text-align:left; cursor:pointer;
                 background:transparent; border:none; font-family:inherit;
                 color:inherit; padding:7px 8px; border-radius:5px;
                 border-left:2px solid transparent;
                 transition: background var(--dur-hover) var(--ease-out); }
    .alert-row:hover { background:rgba(217,45,32,0.06);
                       border-left-color:""" + CRITICAL + """; }
    .alert-row.acked { opacity:0.72; }
    .alert-row-top { display:flex; align-items:baseline; gap:6px; }
    .alert-row-t { font-size:0.76rem; font-weight:700; color:""" + INK + """;
                   overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
                   flex:1; }
    .alert-row-f { font-family:'JetBrains Mono',monospace; font-size:0.6rem;
                   color:""" + INK_3 + """; margin-top:3px; }

    .alert-grid { display:grid; grid-template-columns:1fr auto; gap:7px 12px; align-items:baseline; }
    .alert-k { font-size:0.66rem; color:""" + INK_3 + """; }
    .alert-v { font-size:1.02rem; font-weight:800; color:""" + INK + """;
                font-family:'JetBrains Mono',monospace; word-break:break-all; }
    .alert-badge { width:26px; height:26px; border-radius:50%; background:""" + CRITICAL + """;
                    color:#fff; font-weight:800; font-size:0.82rem;
                    display:flex; align-items:center; justify-content:center; }

    /* ── terminal ─────────────────────────────────────────────────────── */
    .terminal-feed { background:""" + TERMINAL_BG + """; border:1px solid """ + INK + """;
                      border-radius:12px; overflow:hidden; }
    .term-chrome { background:""" + TERMINAL_BG + """; border-bottom:1px solid rgba(255,255,255,0.09);
                    padding:11px 15px; }

    /* ── small tables inside panels ───────────────────────────────────── */
    .hp-tbl { width:100%; border-collapse:collapse; font-size:0.75rem; }
    .hp-tbl th { text-align:left; font-size:0.6rem; letter-spacing:0.07em;
                  text-transform:uppercase; color:""" + INK_3 + """; font-weight:800;
                  padding:0 8px 7px 0; border-bottom:1px solid """ + LINE + """; }
    .hp-tbl td { padding:7px 8px 7px 0; border-bottom:1px solid """ + LINE + """;
                  font-family:'JetBrains Mono',monospace; color:""" + INK_2 + """; }
    .hp-tbl tr:last-child td { border-bottom:none; }

    .hp-stat { border:1px solid """ + LINE + """; border-radius:9px; padding:9px 11px; }
    .hp-stat-l { font-size:var(--text-2xs); font-weight:800; letter-spacing:0.06em;
                  text-transform:uppercase; color:""" + INK_3 + """; }
    .hp-stat-v { font-size:var(--text-lg); font-weight:800; color:""" + INK + """; margin-top:2px; }

    /* horizontal bar rows (usernames / passwords) */
    .bar-row { display:grid; grid-template-columns:74px 1fr auto; gap:8px;
                align-items:center; font-size:0.72rem; padding:3px 0; }
    .bar-row .bl { font-family:'JetBrains Mono',monospace; color:""" + INK_2 + """;
                    overflow:hidden; text-overflow:ellipsis; }
    .bar-track { height:9px; background:""" + Y_100 + """; border-radius:3px; overflow:hidden; }
    .bar-fill { height:100%; background:""" + Y_400 + """; border-radius:3px; }
    .bar-row .bn { font-family:'JetBrains Mono',monospace; color:""" + INK_3 + """; font-size:0.68rem; }

    .hp-foot { border-top:1px solid """ + LINE + """; margin-top:4px; padding:13px 2px 4px;
                display:flex; justify-content:space-between; gap:12px;
                font-size:0.68rem; color:""" + INK_3 + """; font-family:'JetBrains Mono',monospace; }

    /* Investigate / drill-down CTAs. These were inheriting `.hp-range button`
       — transparent, no border, 0.72rem muted grey — which reads as a faint
       label rather than something you can click. A CTA needs a visible edge,
       full-contrast text, and a real hit target. Kept as its own class so the
       segmented controls (window presets, queue rank picker) keep their
       quieter treatment. */
    .btn-cta {
      display:inline-flex; align-items:center; gap:6px;
      background: var(--paper); color: var(--ink);
      border: 2px solid var(--ink); border-radius: 9px;
      font-family:'JetBrains Mono',monospace; font-size:0.78rem; font-weight:700;
      padding: 9px 14px; min-height: 38px; cursor: pointer;
      box-shadow: 2px 2px 0 var(--ink);
    }
    @media (hover: hover) {
      .btn-cta:hover {
        background: var(--y-400); color: var(--ink);
        transform: translateY(-1.5px);
        box-shadow: 3px 4px 0 var(--ink);
      }
    }
    .btn-cta:active { transform: translateY(1px); box-shadow: 1px 1px 0 var(--ink); }
    .btn-cta { transition: background var(--dur-hover) var(--ease-out),
                           transform var(--dur-tick) var(--ease-out),
                           box-shadow var(--dur-hover) var(--ease-out); }

    /* Attention Queue chips. A SOC analyst scans this column; grey running
       text forces them to READ it. Tactics are filled with their MITRE stage
       colour (the same mapping the MITRE page uses, so a tactic is the same
       colour everywhere in the app), techniques are outlined monospace so the
       two read as different kinds of thing at a glance. */
    .tac-chip {
      display:inline-block; padding:2px 8px; border-radius:999px;
      font-size:0.66rem; font-weight:800; letter-spacing:0.02em;
      color:#fff; white-space:nowrap;
    }
    .tac-arrow { color:var(--ink-3); margin:0 4px; font-size:0.7rem; }
    .tech-chip {
      display:inline-block; padding:1px 7px; margin:2px 4px 0 0;
      border:1px solid var(--ink); border-radius:6px;
      font-family:'JetBrains Mono',monospace; font-size:0.66rem; font-weight:700;
      color:var(--ink); background:var(--y-50); white-space:nowrap;
    }
    .q-num { font-weight:800; color:var(--ink); }

    /* ══ Investigation workspace ═════════════════════════════════════════
       An analyst console, not a dashboard. The rules this block follows:

       ONE SURFACE. The previous version nested panel > card > box; each
       border announced a new thing without a new thing behind it. Here the
       workspace is a single plane and hierarchy is carried by type weight,
       spacing, and hairline rules between sections. There is exactly one
       rounded container on the page (the workspace itself).

       SPACE BETWEEN SECTIONS, NOT INSIDE THEM. Generous gaps separate
       logical blocks; within a block, lines sit close enough to read as one
       thought.

       ACCENT IS A SIGNAL. Gold marks the selected row and the shared-
       behaviour node — the two things the eye must find. It is not used
       decoratively anywhere else. */

    /* Top bar ---------------------------------------------------------- */
    .iv-topbar { display:flex; align-items:flex-start; justify-content:space-between;
                 gap:20px; flex-wrap:wrap; margin-bottom:16px; }
    .iv-brand-1 { font-size:var(--text-lg); font-weight:800; color:var(--ink-3); }
    .iv-brand-sep { font-size:var(--text-lg); color:var(--ink-3); }
    .iv-brand-2 { font-size:var(--text-lg); font-weight:800; color:var(--ink); }
    .iv-sub { font-size:var(--text-xs); color:var(--ink-3); margin-top:3px; }

    /* Summary strip. Figures with what each is a share OF underneath, divided
       by hairlines rather than boxed into tiles — this is orientation, and it
       must not outweigh the queue. */
    .iv-kpis { display:grid; grid-template-columns:repeat(6, minmax(0,1fr));
               border:1px solid var(--line-strong); border-radius:10px;
               background:""" + CARD + """; margin-bottom:16px; overflow:hidden; }
    .iv-kpi { display:flex; align-items:flex-start; gap:11px; padding:14px 16px;
              border-right:1px solid var(--line); min-width:0; }
    .iv-kpi:last-child { border-right:none; }
    .iv-kpi-ico { width:30px; height:30px; border-radius:7px; flex:none;
                  display:flex; align-items:center; justify-content:center;
                  background:var(--y-100); color:var(--ink); font-size:0.88rem; }
    .iv-kpi-body { min-width:0; }
    .iv-kpi-v { font-size:1.35rem; font-weight:800; color:var(--ink);
                line-height:1.05; font-family:'JetBrains Mono',monospace; }
    .iv-kpi-l { font-size:0.6rem; letter-spacing:0.08em; font-weight:800;
                color:var(--ink-3); text-transform:uppercase; margin-top:3px; }
    .iv-kpi-s { font-size:0.62rem; color:var(--ink-3); margin-top:3px;
                line-height:1.35; }
    @media (max-width: 1250px) {
      .iv-kpis { grid-template-columns:repeat(3, minmax(0,1fr)); }
      .iv-kpi { border-bottom:1px solid var(--line); }
    }
    @media (max-width: 700px) { .iv-kpis { grid-template-columns:repeat(2, minmax(0,1fr)); } }

    /* Queue toolbar — filter by correlation type (the classifier this
       pipeline actually has) plus free text. */
    .iv-tools { padding:9px 12px; border-bottom:1px solid var(--line-strong); }
    .iv-pills { display:flex; flex-wrap:wrap; gap:5px; }
    .iv-pills button { border:1px solid var(--line-strong); background:transparent;
                       border-radius:999px; cursor:pointer; font-family:inherit;
                       font-size:0.62rem; font-weight:700; color:var(--ink-3);
                       padding:3px 10px;
                       transition: background var(--dur-hover) var(--ease-out),
                                   color var(--dur-hover) var(--ease-out); }
    .iv-pills button:hover { background:var(--y-50); color:var(--ink); }
    .iv-pills button.active { background:var(--ink); border-color:var(--ink);
                              color:var(--y-300); }
    /* dcc.Input renders a WRAPPER div carrying the className, with the real
       <input> inside it — so border, padding, placeholder and focus must be
       targeted at the child or they style a box around the field instead of
       the field. */
    .iv-search { width:100%; margin-top:8px; display:block; }
    .iv-search input {
      width:100%; padding:6px 10px; border:1px solid var(--line-strong);
      border-radius:6px; background:var(--paper); font-family:inherit;
      font-size:var(--text-2xs); color:var(--ink); }
    .iv-search input::placeholder { color:var(--ink-3); }
    .iv-search input:focus { outline:2px solid var(--focus); outline-offset:1px;
                             border-color:var(--y-500); }

    /* Tactic progression as interlocking chevrons: one directed path, rather
       than labels that happen to have arrows between them.

       The polygon is a breadcrumb arrow -- squared top/bottom edges, a point
       on the right, and a matching notch bitten out of the left so the next
       chevron nests into it. Both insets are NOTCH wide and the horizontal
       padding must exceed it, or the first and last characters render under
       the clip and the label reads as truncated. */
    .iv-chevs { display:flex; flex-wrap:wrap; align-items:center; }
    .iv-chev {
      color:#fff; font-size:0.66rem; font-weight:700; white-space:nowrap;
      padding:7px 18px 7px 26px; margin-left:-11px;
      clip-path: polygon(0 0, calc(100% - 11px) 0, 100% 50%,
                         calc(100% - 11px) 100%, 0 100%, 11px 50%);
    }
    /* No notch to nest into at the head of the chain. */
    .iv-chev.first {
      padding-left:15px; margin-left:0;
      clip-path: polygon(0 0, calc(100% - 11px) 0, 100% 50%,
                         calc(100% - 11px) 100%, 0 100%);
    }
    .iv-chev-more { background:var(--y-100) !important; color:var(--ink-2); }

    /* Workspace: rail + main. 28/72 — the investigation needs the room; the
       queue only needs to stay legible and reachable. */
    .iv-ws { display:grid; grid-template-columns: minmax(270px, 28%) minmax(0,1fr);
             gap:0; border:1px solid var(--line-strong); border-radius:10px;
             background:""" + CARD + """; overflow:hidden; }
    .iv-rail { border-right:1px solid var(--line-strong); min-width:0;
               display:flex; flex-direction:column; }
    .iv-rail-h { display:flex; align-items:center; justify-content:space-between;
                 padding:11px 14px; border-bottom:1px solid var(--line-strong);
                 font-size:0.64rem; letter-spacing:0.09em; font-weight:800;
                 color:var(--ink-2); text-transform:uppercase; }
    .iv-rail-n { font-family:'JetBrains Mono',monospace; color:var(--ink-3); }
    /* Rail and main scroll independently, so picking the 20th detection never
       scrolls the detection header off the screen. */
    .iv-rail-body { overflow-y:auto; max-height: calc(100vh - 235px); }
    .iv-main { min-width:0; padding:20px 24px 26px;
               overflow-y:auto; max-height: calc(100vh - 235px); }
    @media (max-width: 1150px) {
      .iv-ws { grid-template-columns: minmax(0,1fr); }
      .iv-rail { border-right:none; border-bottom:1px solid var(--line-strong); }
      .iv-rail-body, .iv-main { max-height:none; }
    }

    /* Queue rows ------------------------------------------------------- */
    .iv-queue { display:flex; flex-direction:column; }
    .iv-row { display:block; width:100%; text-align:left; cursor:pointer;
              background:transparent; border:none; color:inherit;
              font-family:inherit; padding:10px 13px 11px 12px;
              border-bottom:1px solid var(--line);
              border-left:3px solid transparent;
              transition: background var(--dur-hover) var(--ease-out),
                          border-left-color var(--dur-hover) var(--ease-out); }
    .iv-row:last-child { border-bottom:none; }
    .iv-row:hover { background:var(--y-50); }
    .iv-row.active { background:var(--y-50); border-left-color:var(--y-400); }
    .iv-row-top { display:flex; align-items:baseline; gap:7px; }
    .iv-row-n { font-family:'JetBrains Mono',monospace; font-size:0.6rem;
                color:var(--ink-3); font-weight:700; }
    .iv-row-title { font-size:var(--text-xs); font-weight:800; color:var(--ink);
                    line-height:1.35; flex:1; }
    .iv-row-facts { font-family:'JetBrains Mono',monospace; font-size:0.62rem;
                    color:var(--ink-2); margin-top:4px; }
    .iv-row-foot { display:flex; align-items:center; justify-content:space-between;
                   gap:8px; margin-top:6px; }
    .iv-row-seen { font-family:'JetBrains Mono',monospace; font-size:0.58rem;
                   color:var(--ink-3); }

    /* Severity, from threat_intel/severity.py. Five levels need five
       distinguishable weights, and colour alone is not enough — critical and
       high are both red-family, so critical is filled and high is outlined.
       Unrated is the absence of a level, not a sixth one, so it is drawn as a
       dashed outline that reads as "no answer" rather than "low". */
    .iv-sev { font-size:0.58rem; font-weight:800; letter-spacing:0.06em;
              padding:1px 5px; border-radius:3px; color:#fff; flex:none;
              border:1px solid transparent; white-space:nowrap; }
    .iv-sev-critical { background:""" + CRITICAL + """; }
    .iv-sev-high { background:transparent; color:""" + CRITICAL + """;
                   border-color:""" + CRITICAL + """; }
    .iv-sev-medium { background:""" + ORANGE + """; }
    .iv-sev-low { background:transparent; color:var(--ink-3);
                  border-color:var(--line-strong); }
    .iv-sev-info { background:var(--ink-3); }
    .iv-sev-unrated { background:transparent; color:var(--ink-3);
                      border-style:dashed; border-color:var(--line-strong); }

    /* Alert state. Present ONLY when a detection crossed the alerting bar, so
       the chip's existence is itself the signal. Distinct shape from severity
       (square, uppercase, outlined) because they answer different questions --
       "how bad" versus "has anyone dealt with it". */
    .iv-alert { font-size:0.54rem; font-weight:800; letter-spacing:0.07em;
                padding:1px 5px; border-radius:2px; flex:none; white-space:nowrap;
                border:1px solid currentColor; }
    .iv-alert-new { color:""" + CRITICAL + """; background:rgba(217,45,32,0.07); }
    .iv-alert-acknowledged { color:""" + Y_700 + """; background:rgba(245,178,27,0.14); }
    .iv-alert-closed { color:var(--ink-3); background:transparent; }

    /* Lifecycle actions. The primary one is filled and the rest stay quiet, so
       the expected next step is obvious without reading every label. */
    .iv-acts { display:flex; gap:6px; flex-wrap:wrap; }
    .iv-act { font-family:inherit; font-size:0.66rem; font-weight:700;
              padding:5px 12px; border-radius:6px; cursor:pointer;
              border:1px solid var(--line-strong); background:transparent;
              color:var(--ink-2);
              transition: background var(--dur-hover) var(--ease-out),
                          color var(--dur-hover) var(--ease-out); }
    .iv-act:hover { background:var(--y-50); color:var(--ink); }
    .iv-act.primary { background:var(--ink); border-color:var(--ink);
                      color:var(--y-300); }
    .iv-act.primary:hover { background:var(--ink-2); color:var(--y-300); }

    /* Severity filter pills carry a dot in their level's colour, so the row
       is scannable without reading every label. */
    .iv-pills button[class*="iv-pill-"]:before {
      content:""; display:inline-block; width:6px; height:6px; border-radius:50%;
      margin-right:5px; vertical-align:middle; background:var(--ink-3); }
    .iv-pills .iv-pill-critical:before { background:""" + CRITICAL + """; }
    .iv-pills .iv-pill-high:before { background:""" + CRITICAL + """; opacity:0.55; }
    .iv-pills .iv-pill-medium:before { background:""" + ORANGE + """; }

    /* The rules behind a rating — a severity with no visible basis is the
       opaque number this architecture refuses to produce. */
    .iv-sevrule { display:flex; align-items:flex-start; gap:9px; padding:7px 0;
                  border-bottom:1px solid var(--line); }
    .iv-sevrule:last-child { border-bottom:none; }
    .iv-sevrule-t { font-size:var(--text-xs); font-weight:700; color:var(--ink); }
    .iv-sevrule-d { font-size:0.66rem; color:var(--ink-3); line-height:1.45;
                    margin-top:2px; max-width:78ch; }

    /* Identifier, not prose. */
    .iv-type { font-family:'JetBrains Mono',monospace; font-size:0.58rem;
               font-weight:700; color:var(--ink-3); letter-spacing:0.02em; }

    .iv-tac { display:inline-block; padding:1px 7px; border-radius:3px;
              font-size:0.6rem; font-weight:700; color:#fff; white-space:nowrap; }
    .iv-arrow { color:var(--ink-3); margin:0 4px; font-size:0.6rem; }
    .iv-more-inline { font-family:'JetBrains Mono',monospace; font-size:0.58rem;
                      color:var(--ink-3); margin-left:5px; font-weight:700; }
    .iv-chain-sm { margin-top:6px; line-height:1.9; }
    .iv-chain-lg { margin-top:12px; line-height:2.1; }
    .iv-chain-lg .iv-tac { font-size:var(--text-2xs); padding:3px 10px; }
    .iv-chain-lg .iv-arrow { font-size:var(--text-xs); margin:0 6px; }

    /* Detection header — the largest thing on the page. */
    .iv-head { padding-bottom:16px; border-bottom:1px solid var(--line-strong); }
    .iv-head-top { display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }
    .iv-title { font-size:1.5rem; font-weight:800; color:var(--ink); margin:0;
                line-height:1.2; letter-spacing:-0.01em; }
    .iv-meta { display:flex; flex-wrap:wrap; gap:6px 30px; margin-top:13px; }
    .iv-k { font-size:0.58rem; letter-spacing:0.08em; font-weight:700;
            color:var(--ink-3); text-transform:uppercase; display:block; }
    .iv-v { font-size:var(--text-xs); font-weight:700; color:var(--ink);
            font-family:'JetBrains Mono',monospace; display:block; margin-top:2px; }
    .iv-v-mono { font-family:'JetBrains Mono',monospace; font-size:var(--text-2xs);
                 font-weight:700; color:var(--ink-2); }

    /* Blocks: spacing between sections does the separating, not borders. */
    .iv-block { margin-top:26px; }
    .iv-h { font-size:0.62rem; letter-spacing:0.11em; font-weight:800;
            color:var(--ink-3); text-transform:uppercase; margin-bottom:10px; }
    .iv-why { font-size:var(--text-sm); color:var(--ink); line-height:1.55;
              max-width:74ch; }
    .iv-why-meta { display:flex; align-items:center; gap:7px 16px;
                   flex-wrap:wrap; margin-top:11px; }
    .iv-rule-box { padding:10px 12px; background:var(--y-50);
                   border:1px solid var(--line); border-radius:6px; }
    .iv-quote { font-size:var(--text-xs); font-style:italic; color:var(--ink-2); }
    .iv-rule-text { font-size:var(--text-xs); color:var(--ink-2); line-height:1.5;
                    margin-top:7px; max-width:80ch; }
    .iv-muted { font-size:var(--text-xs); color:var(--ink-3); line-height:1.5; }
    .iv-empty { font-size:var(--text-xs); color:var(--ink-3); padding:28px 4px; }
    .iv-foot { font-size:0.66rem; color:var(--ink-3); padding:9px 2px 0; }

    /* Relationship graph — the one thing a paragraph cannot do. */
    .iv-graph { display:flex; align-items:center; gap:4px; flex-wrap:wrap;
                padding:16px 14px; border:1px solid var(--line);
                border-radius:8px; background:var(--y-50); }
    .iv-stage { display:flex; flex-direction:column; gap:6px; min-width:0;
                max-width:230px; }
    .iv-stage-cap { font-size:0.54rem; letter-spacing:0.1em; font-weight:800;
                    color:var(--ink-3); text-transform:uppercase; }
    .iv-stage-sub { font-size:0.6rem; color:var(--ink-3); font-style:italic;
                    line-height:1.4; }
    .iv-nodes-wrap { display:flex; align-items:stretch; }
    .iv-nodes { display:flex; flex-direction:column; gap:3px; }
    .iv-node { font-family:'JetBrains Mono',monospace; font-size:0.62rem;
               font-weight:700; color:var(--ink); background:""" + CARD + """;
               border:1px solid var(--line-strong); border-radius:3px;
               padding:3px 8px; white-space:nowrap; }
    .iv-node-more { background:transparent; border-style:dashed;
                    color:var(--ink-3); }
    /* The convergence: many sessions gathered into one shared fact. */
    .iv-brace { width:12px; margin:8px 0; border-right:1.5px solid var(--ink-3);
                border-top:1.5px solid var(--ink-3);
                border-bottom:1.5px solid var(--ink-3);
                border-radius:0 7px 7px 0; }
    .iv-flow-arrow { color:var(--ink-3); font-size:0.7rem; padding:0 3px;
                     align-self:center; margin-top:12px; }
    /* Gold: the shared behaviour is the reason the detection exists. */
    .iv-node-shared { font-family:'JetBrains Mono',monospace; font-size:0.62rem;
                      font-weight:800; color:var(--ink); background:var(--y-300);
                      border:1px solid var(--y-500); border-radius:3px;
                      padding:6px 10px; }
    .iv-node-rule { font-family:'JetBrains Mono',monospace; font-size:0.62rem;
                    font-weight:700; color:var(--ink-2); background:""" + CARD + """;
                    border:1px dashed var(--line-strong); border-radius:3px;
                    padding:6px 10px; }
    /* Ink: the terminus, where the chain resolves. */
    .iv-node-det { font-size:0.66rem; font-weight:800; color:var(--y-300);
                   background:var(--ink); border-radius:3px; padding:6px 10px;
                   line-height:1.35; }
    @media (max-width: 900px) {
      .iv-graph { flex-direction:column; align-items:flex-start; }
      .iv-flow-arrow { transform:rotate(90deg); margin:2px 0 2px 16px; }
      .iv-stage { max-width:100%; }
    }

    /* ATT&CK Activity: one COLUMN per stage, with what was actually done at
       that stage beneath it. Columns rather than a list because the tactics
       are a sequence -- reading left to right IS the attack progression, so
       the layout carries meaning the list version threw away. */
    .iv-att { display:flex; gap:6px; align-items:flex-start; overflow-x:auto;
              padding-bottom:4px; }
    .iv-att-col { flex:1 1 0; min-width:165px; }
    .iv-att-col .iv-chev { display:block; margin-left:0; padding-left:14px;
                           clip-path: polygon(0 0, calc(100% - 11px) 0, 100% 50%,
                                              calc(100% - 11px) 100%, 0 100%); }
    .iv-att-list { margin-top:6px; display:flex; flex-direction:column; gap:5px; }
    .iv-att-t { padding:7px 9px; border:1px solid var(--line); border-radius:5px;
                background:var(--y-50); }
    .iv-att-name { font-size:0.68rem; font-weight:600; color:var(--ink);
                   line-height:1.3; }
    .iv-att-id { font-family:'JetBrains Mono',monospace; font-size:0.58rem;
                 color:var(--ink-3); font-weight:700; margin-top:2px; }

    /* Techniques — name is the meaning, ID is the lookup key. */
    .iv-techs { display:flex; flex-direction:column; }
    .iv-tech { display:flex; align-items:baseline; justify-content:space-between;
               gap:14px; padding:6px 0; border-bottom:1px solid var(--line); }
    .iv-tech:last-child { border-bottom:none; }
    .iv-tech-name { font-size:var(--text-xs); color:var(--ink); font-weight:600; }
    .iv-tech-id { font-family:'JetBrains Mono',monospace; font-size:0.6rem;
                  color:var(--ink-3); font-weight:700; white-space:nowrap; }

    /* Evidence: four peers behind a segmented control, not a stack. */
    .iv-ev-head { display:flex; align-items:center; justify-content:space-between;
                  gap:16px; flex-wrap:wrap; margin-bottom:12px; }
    .iv-ev-head .iv-h { margin-bottom:0; }
    .iv-seg { display:inline-flex; border:1px solid var(--line-strong);
              border-radius:6px; overflow:hidden; }
    .iv-seg button { border:none; background:transparent; cursor:pointer;
                     font-family:inherit; font-size:0.66rem; font-weight:700;
                     color:var(--ink-3); padding:6px 13px;
                     border-right:1px solid var(--line);
                     transition: background var(--dur-hover) var(--ease-out),
                                 color var(--dur-hover) var(--ease-out); }
    .iv-seg button:last-child { border-right:none; }
    .iv-seg button:hover { background:var(--y-50); color:var(--ink); }
    .iv-seg button.active { background:var(--ink); color:var(--y-300); }
    /* Count beside each tab, so the analyst knows what is behind it before
       paying a click. */
    .iv-seg-n { font-family:'JetBrains Mono',monospace; font-size:0.58rem;
                font-weight:800; margin-left:6px; padding:1px 5px;
                border-radius:3px; background:var(--line); color:inherit; }
    .iv-seg button.active .iv-seg-n { background:rgba(255,255,255,0.16); }
    /* The evidence pane scrolls on its own, so the detection stays put. */
    .iv-ev-body { max-height:440px; overflow:auto; }

    .iv-tbl { width:100%; border-collapse:collapse; font-size:var(--text-2xs); }
    .iv-tbl th { text-align:left; font-size:0.56rem; letter-spacing:0.08em;
                 font-weight:800; color:var(--ink-3); text-transform:uppercase;
                 padding:0 10px 7px 0; border-bottom:1px solid var(--line-strong); }
    .iv-tbl td { padding:7px 10px 7px 0; border-bottom:1px solid var(--line);
                 vertical-align:top; }
    .iv-tbl tbody tr:hover { background:var(--y-50); }
    .iv-mono { font-family:'JetBrains Mono',monospace; color:var(--ink-3); }
    .iv-mono-b { font-family:'JetBrains Mono',monospace; color:var(--ink);
                 font-weight:800; }
    .iv-num { font-family:'JetBrains Mono',monospace; color:var(--ink-2);
              font-weight:700; }

    /* Command timeline — a transcript, so monospace and scrolling, not wrapped. */
    .iv-cmds { border:1px solid var(--line); border-radius:6px; overflow:hidden; }
    .iv-cmd { display:flex; align-items:baseline; gap:10px; padding:4px 9px;
              border-bottom:1px solid var(--line); background:""" + CARD + """; }
    .iv-cmd:nth-child(even) { background:var(--y-50); }
    .iv-cmd:last-child { border-bottom:none; }
    .iv-cmd-n { font-family:'JetBrains Mono',monospace; font-size:0.58rem;
                color:var(--ink-3); font-weight:700; min-width:20px; }
    .iv-cmd-ts { font-family:'JetBrains Mono',monospace; font-size:0.58rem;
                 color:var(--ink-3); white-space:nowrap; }
    .iv-cmd-t { font-family:'JetBrains Mono',monospace; font-size:0.64rem;
                color:var(--ink); flex:1; min-width:0; white-space:pre;
                overflow-x:auto; }
    .iv-cmd-tech { font-size:0.58rem; color:var(--ink-3); white-space:nowrap;
                   font-weight:600; }

    /* Raw evidence: present, reachable, visually quiet, never the default. */
    .iv-raw { margin-top:9px; padding:11px; background:var(--ink); color:#CFC7B8;
              border-radius:6px; font-family:'JetBrains Mono',monospace;
              font-size:0.6rem; line-height:1.55; overflow:auto; white-space:pre; }

    .iv-disc { margin-top:10px; }
    .iv-disc > summary { cursor:pointer; list-style:none; padding:5px 0;
                         font-size:var(--text-2xs); font-weight:700;
                         color:var(--ink-3); }
    .iv-disc > summary::-webkit-details-marker { display:none; }
    .iv-disc > summary:before { content:"▸"; display:inline-block;
                                margin-right:6px;
                                transition: transform var(--dur-tick) var(--ease-out); }
    .iv-disc[open] > summary:before { transform: rotate(90deg); }
    .iv-disc > summary:hover { color:var(--ink); }

    /* ══ Interaction layer ═══════════════════════════════════════════════
       Three animation primitives, deliberately no more: a hover lift on
       cards, a press tick on controls, and a row/pill highlight. Every
       hover has a :focus-visible equivalent so nothing is pointer-only,
       and the whole layer collapses under prefers-reduced-motion.        */

    /* Focus is keyboard-only and never removed without a replacement —
       `outline:none` with nothing in its place is the most common a11y bug. */
    .nav-pill:focus-visible, .hp-range button:focus-visible, .chip:focus-visible,
    .refresh-btn:focus-visible, .btn:focus-visible, button:focus-visible,
    a:focus-visible, [role="button"]:focus-visible, input:focus-visible,
    select:focus-visible, .Select-control:focus-within {
      outline: 2px solid var(--focus);
      outline-offset: 2px;
      border-radius: inherit;
    }

    /* Hover only where a pointer actually exists — on touch, :hover sticks
       after a tap and leaves controls looking permanently active. */
    @media (hover: hover) {
      /* Amber, not the pale cream this used to be: --y-100 on a white card is
         barely a tint, and these buttons carry muted grey text, so the hover
         state was effectively invisible. --y-300 with ink text reads clearly
         and still sits a step below .active's --y-400, so "hovered" and
         "selected" stay distinguishable. */
      .hp-range button:hover:not(.active),
      .chip:hover:not(.active) {
        background: var(--y-300);
        color: var(--ink);
        border-color: var(--ink);
      }
      .nav-pill:hover:not(.active) { background: rgba(255,255,255,0.07); }
      .refresh-btn:hover, .btn:hover { transform: translateY(-1.5px); }
      /* Cards lift a little and deepen their offset shadow — the same
         neo-brutalist shadow the terminal already uses, just responding. */
      .pcard:hover, .kpi:hover {
        transform: translateY(-2px);
        border-color: var(--line-strong);
        box-shadow: 0 2px 0 var(--line-strong);
      }
      .hp-tbl tbody tr:hover { background: var(--y-50); }
      .term-line:hover { background: rgba(255,255,255,0.04); }
    }

    /* Press tick: the control moves back down, fast. Instant feedback reads
       as "the click landed" in a way a colour change alone does not. */
    .hp-range button:active, .chip:active, .nav-pill:active,
    .refresh-btn:active, .btn:active { transform: translateY(1px); }
    .pcard:active, .kpi:active { transform: translateY(0); }

    .hp-range button, .chip, .nav-pill, .refresh-btn, .btn {
      transition: background var(--dur-hover) var(--ease-out),
                  border-color var(--dur-hover) var(--ease-out),
                  color var(--dur-hover) var(--ease-out),
                  transform var(--dur-tick) var(--ease-out);
    }
    .pcard, .kpi {
      transition: transform var(--dur-hover) var(--ease-out),
                  box-shadow var(--dur-hover) var(--ease-out),
                  border-color var(--dur-hover) var(--ease-out);
    }
    .hp-tbl tbody tr, .term-line {
      transition: background var(--dur-hover) var(--ease-out);
    }

    /* Disabled is a real state, not an afterthought. */
    button:disabled, .btn:disabled, .nav-pill:disabled {
      opacity: 0.5; cursor: not-allowed; transform: none;
    }

    /* Hit targets: a 4px-tall pill is a miss waiting to happen. */
    .hp-range button, .chip, .nav-pill, .refresh-btn, .btn { min-height: 32px; }

    /* Panels settle in once when a page renders. One orchestrated entrance,
       not a per-section stagger — twelve fade-ups is the slop tell. */
    @keyframes hp-settle { from { opacity: 0; transform: translateY(6px); }
                             to { opacity: 1; transform: translateY(0); } }
    /* fill-mode `backwards`, NOT `both`: `both` keeps the final keyframe's
       transform applied forever, and an animation's value beats a normal
       declaration in the cascade — so the settle silently cancelled the
       hover lift below. `backwards` covers the pre-start frame and then
       releases the element back to its own CSS. */
    .content .pcard, .content .kpi, .content .alert-card {
      animation: hp-settle var(--dur-open) var(--ease-out) backwards;
    }

    /* Reduced motion is a first-class state: spatial movement collapses to a
       plain opacity change, everything else simply stops moving. */
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
      .pcard:hover, .kpi:hover, .refresh-btn:hover, .btn:hover,
      .hp-range button:active, .chip:active, .nav-pill:active { transform: none; }
      .content .pcard, .content .kpi, .content .alert-card { animation: none; }
    }
  </style>
</head>
<body>
  {%app_entry%}
  <footer>{%config%}{%scripts%}{%renderer%}</footer>
</body>
</html>
"""

# ── DataTable style helper (ink-bordered, amber header) ────────────────────────

TABLE_STYLE = dict(
    style_table={"overflowX": "auto"},
    style_header={
        "backgroundColor": Y_200, "color": INK, "fontWeight": "700",
        "fontFamily": "Inter, sans-serif", "border": "none",
        "borderBottom": f"2px solid {INK}", "fontSize": "13px",
    },
    style_cell={
        "backgroundColor": PAPER, "color": INK_2, "fontFamily": "JetBrains Mono, monospace",
        "fontSize": "12.5px", "border": "none", "borderTop": f"1px solid {LINE}",
        "padding": "8px 12px",
    },
    style_data_conditional=[
        {"if": {"row_index": "odd"}, "backgroundColor": Y_50},
    ],
)


# ── Shared layout primitives ─────────────────────────────────────────────────
# Used by more than one page, so they live here rather than being private to
# whichever page happened to need them first (they started out in summary.py).
# `html` is imported locally to keep theme.py's top-level import list as it
# was -- this module is otherwise pure constants + plotly chrome.
from dash import html  # noqa: E402


def panel(title, body, right=None, cls=""):
    return html.Div(className=f"pcard {cls}", children=[
        html.Div(className="pcard-h", children=[
            html.Div(title, className="pcard-t"),
            right if right is not None else html.Span(),
        ]),
        body,
    ])


def kpi(label, value, sub=None, icon="", icon_bg=Y_200, critical=False):
    return html.Div(className="kpi" + (" kpi-crit" if critical else ""), children=[
        html.Div(className="kpi-top", children=[
            html.Div(icon, className="kpi-ico",
                     style={"background": icon_bg, "color": INK}),
            html.Div(label, className="kpi-l"),
        ]),
        html.Div(value, className="kpi-v"),
        html.Div(sub, className="kpi-s") if sub else html.Span(),
    ])


def bars(pairs, colour=Y_400, n=5):
    """Horizontal bar rows from (label, value) pairs, largest first.

    Takes plain pairs rather than a pandas Series so callers that already have
    a dict of counts (the aggregator returns dicts, not DataFrames) don't have
    to build a Series just to draw five bars.
    """
    # dict and pandas Series both expose .items(); anything else is assumed to
    # already be an iterable of (label, value) pairs.
    src = pairs.items() if hasattr(pairs, "items") else pairs
    items = sorted(src, key=lambda kv: -kv[1])[:n]
    if not items:
        return html.Div("No data.", className="caption")
    mx = int(items[0][1]) or 1
    return html.Div([
        html.Div(className="bar-row", children=[
            html.Div(str(k), className="bl", title=str(k)),
            html.Div(className="bar-track", children=html.Div(
                className="bar-fill",
                style={"width": f"{int(v)/mx*100:.0f}%", "background": colour})),
            html.Div(f"{int(v):,}", className="bn"),
        ]) for k, v in items
    ])
