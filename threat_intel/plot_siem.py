"""
threat_intel/plot_siem.py — draw HydraPoT's SIEM architecture.

NOTHING IS TYPED TWICE: the endpoint count comes from the live OpenAPI schema,
and measure() still reads the rule, table and page counts so any of them can be
put back on a chip without going hunting for the number.

    python threat_intel/plot_siem.py                # -> siem.png
    python threat_intel/plot_siem.py --out fig2.png --no-measure
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

INK, GREY, PAPER = "#1c1c1c", "#8a8a8a", "#ffffff"
CAPTURE = "#b7791f"     # the honeypot process
PIPE    = "#2b6cb0"     # the analysis pipeline
STORE   = "#6b46c1"     # the database
OUT     = "#2f855a"     # everything that leaves


def measure() -> dict:
    import yaml
    import storage
    _R = os.path.join(os.path.dirname(__file__), "rules")

    def n_yaml(fn, key):
        try:
            d = yaml.safe_load(open(os.path.join(_R, fn))) or {}
            return len(d.get(key) or d)
        except Exception:
            return 0

    try:
        with storage.connect() as c:
            tables = [r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        st = storage.stats()
    except Exception:
        tables, st = [], {"rows": 0, "sessions": 0}

    try:
        from api_server import api
        endpoints = len([p for p in api.openapi()["paths"]
                         if p.startswith("/api/v1")])
    except Exception:
        endpoints = 0

    g = lambda p: len(glob.glob(os.path.join(_R, p), recursive=True))
    return {
        "tables": tables, "rows": st["rows"], "sessions": st["sessions"],
        "strategies": n_yaml("correlation_strategies.yml", "strategies"),
        "detection": n_yaml("detection_rules.yml", "rules"),
        "severity": n_yaml("session_severity.yml", "rules"),
        "alert": n_yaml("alert_rules.yml", "rules"),
        "sinks": n_yaml("alert_sinks.yml", "sinks"),
        "local": g("local_custom/**/*.yml"), "upstream": g("upstream/**/*.yml"),
        "endpoints": endpoints,
        "pages": len(glob.glob(os.path.join(
            os.path.dirname(__file__), "..", "SIEM", "pages", "[!_]*.py"))),
    }


# ── drawing ─────────────────────────────────────────────────────────────────
#
# One serpentine workflow. Each chip carries the MODULE and, in brackets, the
# SIEM function it performs -- the wording is the one the modules' own
# docstrings use (aggregator.py "Collection -> Aggregator", correlation.py
# "Aggregation -> Correlation -> ... -> Detection", alert_records.py "the last
# layer ... ALERTING", normalize.py "ONE canonical security-event
# representation"). Note where normalisation sits: at the EXPORT boundary, not
# at ingest -- exporters translate FROM the canonical form.

CH = 0.105          # chip height


def _chip(ax, cx, cy, w, name, fn, num="", edge=INK, face="#ffffff"):
    from matplotlib.patches import FancyBboxPatch
    ax.add_patch(FancyBboxPatch((cx - w / 2, cy - CH / 2), w, CH,
                                boxstyle="round,pad=0.004,rounding_size=0.014",
                                linewidth=1.6, edgecolor=edge, facecolor=face,
                                zorder=3))
    ax.text(cx, cy + (0.022 if num else 0.014), name, ha="center", va="center",
            fontsize=8.4, fontweight="bold", color=edge, zorder=4)
    ax.text(cx, cy - (0.002 if num else 0.018), f"({fn})", ha="center",
            va="center", fontsize=7.4, color=GREY, style="italic", zorder=4)
    if num:
        ax.text(cx, cy - 0.030, num, ha="center", va="center", fontsize=7.0,
                color=INK, zorder=4, family="DejaVu Sans Mono")


def _flow(ax, x1, x2, y, color):
    """Straight arrow between two chips on the same row."""
    from matplotlib.patches import FancyArrowPatch
    ax.add_patch(FancyArrowPatch((x1, y), (x2, y), arrowstyle="-|>",
                                 mutation_scale=13, linewidth=1.5,
                                 color=color, zorder=2, shrinkA=0, shrinkB=0))


def _elbow(ax, pts, color, label="", lx=None, ly=None, lw=1.5):
    """Right-angle polyline; the last segment gets the arrowhead."""
    from matplotlib.lines import Line2D
    from matplotlib.patches import FancyArrowPatch
    for a, b in zip(pts, pts[1:-1]):
        ax.add_line(Line2D([a[0], b[0]], [a[1], b[1]], color=color,
                           linewidth=lw, zorder=2, solid_capstyle="round"))
    ax.add_patch(FancyArrowPatch(pts[-2], pts[-1], arrowstyle="-|>",
                                 mutation_scale=13, linewidth=lw, color=color,
                                 zorder=2, shrinkA=0, shrinkB=0))
    if label:
        ax.text(lx, ly, label, ha="center", va="bottom", fontsize=7.2,
                color=color, style="italic", zorder=5)


def _row(ax, chips, y, span, gap, edge, face="#ffffff", join=True):
    """Lay chips across `span`, join them, return their centres."""
    x0, x1 = span
    n = len(chips)
    w = (x1 - x0 - gap * (n - 1)) / n
    cs = [x0 + w / 2 + i * (w + gap) for i in range(n)]
    for cx, (name, fn, num) in zip(cs, chips):
        _chip(ax, cx, y, w, name, fn, num, edge=edge, face=face)
    if join:
        for a, b in zip(cs, cs[1:]):
            _flow(ax, a + w / 2, b - w / 2, y, edge)
    return cs, w


def draw(m, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    L = (lambda k: str(m.get(k, "-"))) if m else (lambda k: "-")
    fig, ax = plt.subplots(figsize=(15.0, 6.4), dpi=200)
    ax.set_xlim(0, 1); ax.set_ylim(-0.02, 0.97); ax.axis("off")
    fig.patch.set_facecolor(PAPER)

    Y1, Y2, Y3 = 0.855, 0.545, 0.175

    # ── row 1: collection ───────────────────────────────────────────────
    r1, w1 = _row(ax, [
        ("SSH front door", "collection", ""),
        ("router.py", "routing", ""),
        ("3 agents", "collection", ""),
        ("storage.py", "storage", ""),
    ], Y1, (0.03, 0.86), 0.030, CAPTURE)
    _chip(ax, r1[3], Y1, w1, "storage.py", "storage", "",
          edge=STORE, face="#faf5ff")        # recolour the sink of row 1

    # ── row 2: the analysis chain, right to left ────────────────────────
    r2, w2 = _row(ax, [
        ("mitre_mapper.py", "enrichment", ""),
        ("ioc_extractor.py", "enrichment", ""),
        ("aggregator.py", "aggregation", ""),
        ("correlation.py", "correlation", ""),
        ("detection.py", "detection", ""),
        ("severity.py", "severity", ""),
        ("alert_records.py", "alerting", ""),
    ], Y2, (0.03, 0.86), 0.022, PIPE)

    # ── row 3: what leaves ──────────────────────────────────────────────
    r3, w3 = _row(ax, [
        ("normalize.py", "normalization", ""),
        ("exporters.py", "forwarding", ""),
    ], Y3, (0.03, 0.40), 0.030, OUT, face="#f0fff4")
    r4, w4 = _row(ax, [
        ("SIEM/  Dash", "presentation", ""),
        ("api/v1  REST", "presentation", f"{L('endpoints')} endpoints"),
    ], Y3, (0.55, 0.89), 0.030, OUT, face="#f0fff4", join=False)

    # ── the wraps ───────────────────────────────────────────────────────
    mid12, mid23 = 0.700, 0.355
    _elbow(ax, [(r1[3], Y1 - CH / 2), (r1[3], mid12), (r2[0], mid12),
                (r2[0], Y2 + CH / 2)], STORE,
           "one window of rows", (r1[3] + r2[0]) / 2, mid12 + 0.014)

    # The chain is a LIBRARY both consumers import and run in-process
    # (SIEM/data.py:load_detections, api/services/*), so findings reach the UI
    # directly. Only alerts persist.
    # A COLLECTOR under the whole row, not one line off the last chip: every
    # stage is read by the UI, not just the alerting one. load_all() uses the
    # mapper, load_overview() the aggregator, load_detections() the IOC,
    # correlation, detection and severity layers.
    from matplotlib.lines import Line2D
    for cx in r2:
        ax.add_line(Line2D([cx] * 2, [Y2 - CH / 2, mid23], color=PIPE,
                           linewidth=1.1, zorder=2))
    ax.add_line(Line2D([r2[0], max(r2[-1], r4[-1])], [mid23] * 2, color=PIPE,
                       linewidth=1.6, zorder=2))
    for cx in r4:
        _elbow(ax, [(cx, mid23), (cx, Y3 + CH / 2)], PIPE, lw=1.2)
    ax.text(r2[0], mid23 - 0.016,
            "every stage is read by the UI",
            ha="left", va="top", fontsize=7.2, color=PIPE, style="italic")

    # alerts are the one analysis output that is written back
    _elbow(ax, [(r2[-1] + w2 / 2, Y2), (0.925, Y2), (0.925, Y1),
                (r1[3] + w1 / 2, Y1)], STORE, lw=1.2)
    ax.text(0.918, (Y1 + Y2) / 2, "alerts written back", fontsize=7.2,
            color=STORE, style="italic", rotation=90, ha="right", va="center")

    # One bus for everything that reads the file straight: /export normalises
    # STORED rows and alerts (api/services/export.py), the live feed is
    # storage.query_recent(), health reads stats and the heartbeat table.
    bus = 0.048
    ax.add_line(Line2D([r1[3] + w1 / 2, 0.975], [Y1 - 0.030] * 2, color=OUT,
                       linewidth=1.2, zorder=2))
    ax.add_line(Line2D([0.975] * 2, [Y1 - 0.030, bus], color=OUT,
                       linewidth=1.2, zorder=2))
    ax.add_line(Line2D([0.975, r3[0]], [bus] * 2, color=OUT, linewidth=1.2,
                       zorder=2))
    # Named per consumer: one shared caption read as though the whole
    # dashboard came straight off the table, which is what it does NOT do.
    for cx, what in ((r3[0], "session + auth rows,\nalert rows"),
                     (r4[0], "live feed, auth log,\nalert rows"),
                     (r4[1], "health + stats,\nalert rows")):
        _elbow(ax, [(cx, bus), (cx, Y3 - CH / 2)], OUT, lw=1.2)
        ax.text(cx + 0.010, (bus + Y3 - CH / 2) / 2, what, ha="left",
                va="center", fontsize=6.8, color=OUT, style="italic")
    ax.text(0.975, bus - 0.016, "read straight off the file -- no analysis",
            ha="right", va="top", fontsize=7.2, color=OUT, style="italic")

    fig.savefig(out, bbox_inches="tight", facecolor=PAPER, pad_inches=0.22)
    print(f"[plot] wrote {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="siem.png")
    ap.add_argument("--no-measure", action="store_true")
    a = ap.parse_args()
    draw(None if a.no_measure else measure(), a.out)


if __name__ == "__main__":
    main()
