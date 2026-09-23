"""
api/plot_rest.py — draw the REST API architecture.

NOTHING HERE IS TYPED TWICE. The endpoint list comes from the live routers,
the service function each route calls is read out of that route's own source
with inspect, and the assistant's tool surface is read from api.assistant.
Add an endpoint and re-run: the figure grows a line by itself.

    python api/plot_rest.py                  # -> rest_api.png
    python api/plot_rest.py --out fig4.png
"""
import argparse
import inspect
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

INK, GREY, PAPER = "#1c1c1c", "#8a8a8a", "#ffffff"
CLIENT = "#b7791f"      # outside the process
EDGE   = "#c53030"      # the one door in
ROUTE  = "#2b6cb0"      # HTTP shape only
SVC    = "#6b46c1"      # the application layer
LOGIC  = "#2f855a"      # the pipeline and the file


# ── measurement ─────────────────────────────────────────────────────────────

def _calls(fn) -> list:
    """Which api.services functions this route body actually calls."""
    try:
        src = inspect.getsource(fn)
    except (OSError, TypeError):
        return []
    names = set(re.findall(r"svc\.(\w+)", src))
    names |= {m for m in re.findall(r"_(\w+)\(", src) if m in ("ocsf",)}
    return sorted(names)


def _service_deps() -> list:
    """What the service layer actually imports -- read, not remembered.

    The first draft of this figure listed mitre_mapper here. No service file
    imports it: ATT&CK names come from SIEM/investigation.py and the tagging
    happens further in, inside SIEM/data.py and the aggregator.
    """
    import ast
    import pathlib
    deps = set()
    for f in sorted(pathlib.Path(os.path.join(
            os.path.dirname(__file__), "services")).glob("*.py")):
        for n in ast.walk(ast.parse(f.read_text())):
            if isinstance(n, ast.ImportFrom) and n.module:
                if n.module == "threat_intel":
                    deps.update(a.name for a in n.names)
                elif n.module.startswith("threat_intel."):
                    deps.add(n.module.split(".", 1)[1])
                elif n.module.startswith("SIEM"):
                    deps.add(n.module)
            elif isinstance(n, ast.Import):
                for a in n.names:
                    if a.name == "storage":
                        deps.add(a.name)
    return sorted(deps)


# What a service function ends up running. Read out of its source, one level
# deep, because that is where the call actually appears: `pipeline()` is
# SIEM/data.load_detections (correlation -> detection -> severity), `iocs()`
# is ioc_extractor.build_iocs, `overview()` is aggregator.aggregate_overview.
_ENGINES = (("normalize",       r"normalize\."),
            ("alert table",     r"query_alerts|get_alert\(|alert_counts\("),
            ("ioc_extractor",   r"build_iocs|\biocs\("),
            ("corr -> det -> sev", r"\bpipeline\("),
            ("aggregator",      r"load_overview|aggregate_session|\boverview\("),
            ("storage",         r"stats\(\)|read_health|disk_usage|time_bounds"))


_HELPERS = {"overview", "page", "pipeline", "iocs", "resolve_since",
            "detection_id", "correlation_id"}


def _engines(fn) -> list:
    try:
        src = inspect.getsource(fn)
    except (OSError, TypeError):
        return []
    return [name for name, rx in _ENGINES if re.search(rx, src)]


def measure() -> dict:
    from api import assistant, auth, services as svc
    from api.v1 import (alerts, correlations, detections, export, overview,
                        sessions, system, threats)

    routers = [("overview.py", overview), ("sessions.py", sessions),
               ("detections.py", detections), ("correlations.py", correlations),
               ("alerts.py", alerts), ("threats.py", threats),
               ("export.py", export), ("system.py", system)]

    files, used = [], {}
    for name, mod in routers:
        rows = []
        for r in mod.router.routes:
            called = _calls(r.endpoint)
            for c in called:
                target = getattr(svc, c, None)
                mod_name = getattr(target, "__module__", "")
                used.setdefault(mod_name.split(".")[-1], set()).add(c)
            rows.append((r.path.replace("/api/v1", "").replace(":path", "") or "/",
                         " + ".join(called) or "--"))
        files.append((name, rows))

    # the assistant reaches the SAME functions, without the HTTP hop
    tool_calls = sorted(set(re.findall(r"svc\.(\w+)",
                                       inspect.getsource(assistant._dispatch))))
    for c in tool_calls:
        mod_name = getattr(getattr(svc, c, None), "__module__", "")
        used.setdefault(mod_name.split(".")[-1], set()).add(c)

    # One level is not enough: investigate_ioc's own body only shows
    # pipeline(), because the indicator work happens inside the get_ioc() it
    # calls. Close over api.services until nothing new appears.
    own = {n: _engines(getattr(svc, n)) for n in svc.__all__}
    engines = {n: list(v) for n, v in own.items()}
    for n in svc.__all__:
        src = inspect.getsource(getattr(svc, n))
        for c in re.findall(r"\b(\w+)\(", src):
            # One hop, and never through the shared window/paging helpers:
            # every service function touches those, so hopping through them
            # would give all sixteen endpoints the same answer.
            if c in own and c != n and c not in _HELPERS:
                for e in own[c]:
                    if e not in engines[n]:
                        engines[n].append(e)

    return {
        "files": files,
        "engines": engines,
        "services": [(f"{k}.py", sorted(v)) for k, v in sorted(used.items())
                     if k and k != "__init__"],
        "tools": [t["function"]["name"] for t in assistant.TOOLS],
        "tool_calls": tool_calls,
        "endpoints": sum(len(rows) for _, rows in files),
        "deps": _service_deps(),
        "key_var": auth.ENV_VAR,
        "header": auth.HEADER,
        "formats": sorted(__import__("api.services.export", fromlist=["x"]).FORMATS),
        "classes": sorted(__import__("api.services.export", fromlist=["x"]).CLASSES),
    }


# ── drawing ─────────────────────────────────────────────────────────────────
#
# One box per endpoint, and inside it the engine that answers it. No services
# column and no import list: neither told you where a request GOES, which is
# the only thing this figure is for.

def _pill(ax, cx, cy, w, h, title, sub, edge=INK, face="#ffffff", tfs=9.4,
          sfs=7.6):
    from matplotlib.patches import FancyBboxPatch
    ax.add_patch(FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                                boxstyle="round,pad=0.003,rounding_size=0.012",
                                linewidth=1.7, edgecolor=edge, facecolor=face,
                                zorder=3))
    ax.text(cx, cy + (0.008 if sub else 0), title, ha="center", va="center",
            fontsize=tfs, fontweight="bold", color=edge, zorder=4)
    if sub:
        ax.text(cx, cy - 0.011, sub, ha="center", va="center", fontsize=sfs,
                color=GREY, zorder=4, family="DejaVu Sans Mono")


def _arrow(ax, p1, p2, color, lw=1.6, dashed=False, rad=0.0):
    from matplotlib.patches import FancyArrowPatch
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-|>", mutation_scale=15,
                                 connectionstyle=f"arc3,rad={rad}",
                                 linewidth=lw, color=color, zorder=2,
                                 linestyle="--" if dashed else "-",
                                 shrinkA=0, shrinkB=0))


ORDER = ("aggregator", "corr -> det -> sev", "ioc_extractor", "alert table",
         "normalize", "storage")


def draw(m, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    eng = m["engines"] if m else {}
    rows = [(p, fn) for _, rs in (m["files"] if m else []) for p, fn in rs]

    def engines_of(cell):
        out, seen = [], set()
        for fn in cell.split(" + "):
            for e in eng.get(fn, []):
                if e not in seen:
                    seen.add(e); out.append(e)
        return sorted(out, key=ORDER.index)   # pipeline order, not call order

    # Router order, which is domain order: overview, sessions, detections,
    # correlations, alerts, threats, export, system. Sorting by engine instead
    # scattered /overview away from /sessions for no reader's benefit.
    items = [(p, engines_of(fn)) for p, fn in rows]

    STEP, PH = 0.056, 0.044
    H = STEP * len(items)
    fig, ax = plt.subplots(figsize=(11.5, 1.6 + H * 13), dpi=190)
    ax.set_xlim(0, 1); ax.set_ylim(-0.10, H + 0.22); ax.axis("off")
    fig.patch.set_facecolor(PAPER)

    top = H + 0.06
    _pill(ax, 0.16, top, 0.26, 0.052, "client", "SIEM / script / browser",
          edge=CLIENT, face="#fffaf0", tfs=10)
    _pill(ax, 0.62, top, 0.36, 0.052, "api_server.py",
          "X-API-Key  .  GET only", edge=EDGE, face="#fff5f5", tfs=10)
    _arrow(ax, (0.29, top), (0.44, top), CLIENT)

    # one bus down from the door, one stub per endpoint
    bus_x = 0.115
    ys = [H - 0.03 - i * STEP for i in range(len(items))]
    ax.add_line(Line2D([0.62, 0.62], [top - 0.026, ys[0] + 0.035], color=EDGE,
                       linewidth=1.6, zorder=2))
    ax.add_line(Line2D([0.62, bus_x], [ys[0] + 0.035] * 2, color=EDGE,
                       linewidth=1.6, zorder=2))
    ax.add_line(Line2D([bus_x, bus_x], [ys[0] + 0.035, ys[-1]], color=EDGE,
                       linewidth=1.6, zorder=2))

    for (path, es), y in zip(items, ys):
        _arrow(ax, (bus_x, y), (0.18, y), EDGE, lw=1.3)
        _pill(ax, 0.59, y, 0.80, PH, path, "  +  ".join(es) or "--",
              edge=ROUTE, tfs=9.0, sfs=7.4)

    # the assistant: same answers, no server in the middle
    ai_y = ys[-1] - 0.085
    _pill(ax, 0.155, ai_y, 0.26, 0.052, "AI analyst",
          f"{len(m['tools'])} tools" if m else "-", edge=CLIENT,
          face="#fffaf0", tfs=10)
    ax.add_line(Line2D([0.155, 0.155], [ai_y + 0.026, ys[-1] - 0.030],
                       color=CLIENT, linewidth=1.5, linestyle="--", zorder=2))
    ax.add_line(Line2D([0.155, bus_x], [ys[-1] - 0.030] * 2,
                       color=CLIENT, linewidth=1.5, linestyle="--", zorder=2))
    _arrow(ax, (bus_x, ys[-1] - 0.030), (bus_x, ys[-1] - 0.004),
           CLIENT, dashed=True, lw=1.5)
    ax.text(0.30, ai_y, "same functions, no HTTP", ha="left", va="center",
            fontsize=8.0, color=CLIENT, style="italic")

    fig.savefig(out, bbox_inches="tight", facecolor=PAPER, pad_inches=0.22)
    print(f"[plot] wrote {out}")


def check(m) -> int:
    """Assert the figure describes THIS code and not an older shape of it.

    Three things can rot independently: an endpoint added to a router but not
    served, a service function renamed, and the assistant growing reach the
    REST surface does not have. Each is checked against a live source, never
    against a list kept here.
    """
    from api_server import api
    from api import services as svc

    drawn = {p for _, rows in m["files"] for p, _ in rows}
    live = {p.replace("/api/v1", "")
            for p in api.openapi()["paths"] if p.startswith("/api/v1")}
    route_calls = {fn for _, rows in m["files"] for _, cell in rows
                   for fn in cell.split(" + ")} - {"--"}
    extra = sorted(set(m["tool_calls"]) - route_calls)

    bad = 0
    for label, wrong in (("not in the figure", sorted(live - drawn)),
                         ("not served", sorted(drawn - live)),
                         ("missing from api.services",
                          sorted(f for f in route_calls | set(m["tool_calls"])
                                 if not hasattr(svc, f)))):
        if wrong:
            print(f"[check] {label}: {wrong}")
            bad = 1
    print(f"[check] {len(drawn)} endpoints, {len(m['tools'])} assistant tools, "
          f"{len(extra)} reachable by the assistant but not by any route"
          + (f": {extra}" if extra else ""))
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="rest_api.png")
    ap.add_argument("--no-measure", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="verify the figure against the live routers, no draw")
    a = ap.parse_args()
    m = None if a.no_measure else measure()
    if a.check:
        raise SystemExit(check(m))
    draw(m, a.out)


if __name__ == "__main__":
    main()
