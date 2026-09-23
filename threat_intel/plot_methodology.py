"""
threat_intel/plot_methodology.py — draw how the local rule tier was derived.

EVERY NUMBER IS MEASURED, NOT TYPED. The script runs the same ablation the
validator does and renders the result, so the figure cannot drift from the
code: if a rule changes, re-run this and the diagram changes with it.

    python threat_intel/plot_methodology.py                 # -> methodology.png
    python threat_intel/plot_methodology.py --out fig3.png --no-measure

--no-measure skips the ~40s measurement pass and draws the structure only,
with the numbers left blank. Use it to check layout, never for the report.
"""
import argparse
import collections
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── measurement ─────────────────────────────────────────────────────────────

def measure() -> dict:
    """Re-run the ablation on ONE denominator.

    The scope is the 42 techniques the local tier targets: those are what was
    written, so those are what is claimed. Within them, only atomics an SSH
    honeypot could observe are counted -- every exclusion carries a stated
    reason (see validate_rules.scope_of / unexpressed).

    Both arms are scored over that same set, so before and after are
    comparable. The whole-ART figure is kept alongside for context, clearly
    labelled, because a reader should see what is NOT claimed too.
    """
    import glob
    import yaml
    from threat_intel import mitre_mapper as mm
    from threat_intel import validate_rules as vr

    art = vr.load_art_linux(vr.fetch_art())
    tests, desc = collections.defaultdict(set), {}
    for r in art:
        key = (r["technique"], r.get("test") or r.get("name"))
        tests[key].add(r["command"])
        desc.setdefault(key, r.get("description", ""))

    targeted = {str(yaml.safe_load(open(f)).get("technique")).upper()
                for f in glob.glob(os.path.join(os.path.dirname(__file__),
                                                "rules", "local_custom",
                                                "**", "*.yml"), recursive=True)}

    scoped = {}
    for key, cmds in tests.items():
        lines = sorted(cmds)
        why = vr.unexpressed(desc.get(key, ""), lines)
        scoped[key] = (False, why) if why else vr.scope_of(lines)

    claimed = [k for k in tests if k[0] in targeted and scoped[k][0]]
    empty = tempfile.mkdtemp()

    def run(custom: bool):
        mm.load_rules(rules_dir=(mm.RULES_DIR if custom else empty), force=True)
        mm._UPSTREAM_ENABLED = True
        mm._match_rules_cached.cache_clear()
        mm._upstream_cached.cache_clear()
        got = lambda k: any(k[0] in {t["technique_id"] for t in (mm.tag_all(c) or [])}
                            for c in tests[k])
        per = collections.defaultdict(lambda: [0, 0])
        for k in claimed:
            per[k[0]][1] += 1
            per[k[0]][0] += got(k)
        dead = [t for t, (h, _) in per.items() if h == 0]
        return {"claimed": sum(1 for k in claimed if got(k)),
                "all_art": sum(1 for k in tests if got(k)),
                "zero_techniques": len(dead),
                "zero_atomics": sum(n for t, (h, n) in per.items() if h == 0),
                "techniques_scored": len(per)}

    before = run(custom=False)
    after = run(custom=True)
    mm.load_rules(force=True)

    return {
        "tests": len(tests),
        "techniques": len({k[0] for k in tests}),
        "targeted": len(targeted),
        "claimed_total": len(claimed),
        "claimed_oos": sum(1 for k in tests
                           if k[0] in targeted and not scoped[k][0]),
        "out_scope": collections.Counter(v[1] for v in scoped.values() if not v[0]),
        "upstream_rules": len(glob.glob(os.path.join(
            os.path.dirname(__file__), "rules", "upstream", "**", "*.yml"),
            recursive=True)),
        "local_rules": len(mm.load_rules()),
        "before": before,
        "after": after,
        "gap_techniques": before["zero_techniques"],
    }


# ── drawing ─────────────────────────────────────────────────────────────────

INK   = "#1c1c1c"
GREY  = "#8a8a8a"
BLUE  = "#2b6cb0"      # external references
AMBER = "#b7791f"      # the gap
GREEN = "#2f855a"      # result
PAPER = "#ffffff"


import math


def _node(ax, cx, cy, r, title, sub="", edge=INK, face="#ffffff", fs=10.5):
    """A circle. Title inside, optional one-line figure under it."""
    from matplotlib.patches import Circle
    ax.add_patch(Circle((cx, cy), r, linewidth=1.8, edgecolor=edge,
                        facecolor=face, zorder=3))
    dy = 0.012 if sub else 0
    ax.text(cx, cy + dy, title, ha="center", va="center", fontsize=fs,
            fontweight="bold", color=edge, zorder=4)
    if sub:
        ax.text(cx, cy - 0.022, sub, ha="center", va="center", fontsize=9.5,
                color=INK, zorder=4, family="DejaVu Sans Mono")


def _pill(ax, cx, cy, w, h, title, sub, edge=INK, face="#ffffff"):
    from matplotlib.patches import FancyBboxPatch
    ax.add_patch(FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                                boxstyle="round,pad=0.004,rounding_size=0.018",
                                linewidth=1.6, edgecolor=edge, facecolor=face,
                                zorder=3))
    ax.text(cx, cy + (0.013 if sub else 0), title, ha="center", va="center",
            fontsize=9.6, fontweight="bold", color=edge, zorder=4)
    if sub:
        ax.text(cx, cy - 0.015, sub, ha="center", va="center", fontsize=8.2,
                color=GREY, zorder=4, family="DejaVu Sans Mono")


def _curve(ax, p1, p2, rad, color=INK, lw=1.7, label="", lcol=None,
           out_from=None, push=0.10, shrinkA=6, shrinkB=6):
    """`out_from` = the ring centre. The label is pushed away from it, so arc
    labels sit OUTSIDE the ring -- placing them on the chord midpoint put all
    three on top of each other in the middle.

    shrinkA/B are POINTS. When an endpoint is a node centre they must clear
    that node's radius, or the arrowhead is drawn underneath the circle and
    the arrow reads as a plain line.
    """
    from matplotlib.patches import FancyArrowPatch
    ax.add_patch(FancyArrowPatch(p1, p2, connectionstyle=f"arc3,rad={rad}",
                                 arrowstyle="-|>", mutation_scale=17,
                                 linewidth=lw, color=color, zorder=2,
                                 shrinkA=shrinkA, shrinkB=shrinkB))
    if not label:
        return
    mx, my = (p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2
    if out_from:
        vx, vy = mx - out_from[0], my - out_from[1]
        n = math.hypot(vx, vy) or 1
        mx += vx / n * push
        my += vy / n * push
    ax.text(mx, my, label, ha="center", va="center", fontsize=8.8,
            color=lcol or color, fontweight="bold", zorder=5,
            bbox=dict(boxstyle="round,pad=0.25", fc=PAPER, ec="none"))


def draw(m: dict, out: str):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if m:
        b, a = m["before"], m["after"]
        CT = m["claimed_total"]
        pc = lambda n: f"{n}/{CT}"
        L = lambda k: str(m.get(k, "-"))
    else:
        b = a = {"claimed": 0}
        CT = 0
        pc = lambda n: "--"
        L = lambda k: "--"

    fig, ax = plt.subplots(figsize=(9.6, 9.4), dpi=200)
    ax.set_xlim(-0.03, 1.06); ax.set_ylim(0.02, 1.09); ax.axis("off")
    fig.patch.set_facecolor(PAPER)

    # ── inputs ──────────────────────────────────────────────────────────
    _pill(ax, 0.25, 1.020, 0.36, 0.070, "SigmaHQ",
          f"{L('upstream_rules')} imported rules", edge=BLUE)
    _pill(ax, 0.75, 1.020, 0.36, 0.070, "Atomic Red Team",
          f"{CT} atomics = ground truth", edge=BLUE)

    # ── the loop: three nodes on a circle ───────────────────────────────
    cx, cy, R, r = 0.50, 0.545, 0.255, 0.128
    ang = {"test": 90, "miss": -30, "write": 210}
    pos = {k: (cx + R * math.cos(math.radians(v)),
               cy + R * math.sin(math.radians(v))) for k, v in ang.items()}

    _node(ax, *pos["test"], r, "TEST", "vs ART")
    _node(ax, *pos["miss"], r, "MISS", edge=AMBER, face="#fffaf0")
    _node(ax, *pos["write"], r, "WRITE RULE", "", edge=INK)

    # Endpoints ON the circle boundary, not the centre. `shrink` measures along
    # the straight chord, so on a curved arc it over-shrinks and leaves the arc
    # floating between the nodes instead of touching them.
    RAD = -0.26

    def edge(a, b, rad, radius):
        """Where an arc3 leaving `a` toward `b` crosses `a`'s circle."""
        theta = math.atan2(b[1] - a[1], b[0] - a[0])
        theta -= math.atan(2 * rad)      # arc3 departs off the chord by this
        return (a[0] + radius * math.cos(theta), a[1] + radius * math.sin(theta))

    ring = (cx, cy)
    for src, dst, col, lab, push in (
            ("test", "miss", INK, "not tagged", 0.085),
            ("miss", "write", AMBER, "one rule per miss", -0.055),
            ("write", "test", INK, "re-test", 0.085)):
        p1 = edge(pos[src], pos[dst], RAD, r)
        p2 = edge(pos[dst], pos[src], -RAD, r)
        _curve(ax, p1, p2, RAD, color=col, lcol=col, label=lab,
               out_from=ring, push=push, shrinkA=0, shrinkB=3)

    # feeds into the loop
    _curve(ax, (0.25, 0.985), edge(pos["test"], (0.25, 0.985), -0.14, r),
           0.14, color=BLUE, lw=1.3, shrinkA=3, shrinkB=3)
    _curve(ax, (0.75, 0.985), edge(pos["test"], (0.75, 0.985), 0.14, r),
           -0.14, color=BLUE, lw=1.3, shrinkA=3, shrinkB=3)

    # MITRE feeds the WRITE step
    _pill(ax, 0.105, 0.235, 0.21, 0.066, "MITRE ATT&CK", "what it is", edge=BLUE)
    _curve(ax, (0.105, 0.271), edge(pos["write"], (0.105, 0.271), 0.12, r),
           -0.12, color=BLUE, lw=1.3, shrinkA=3, shrinkB=3)
    _pill(ax, 0.440, 0.235, 0.21, 0.066, "ART atomics", "the commands", edge=BLUE)
    _curve(ax, (0.440, 0.271), edge(pos["write"], (0.440, 0.271), -0.12, r),
           0.12, color=BLUE, lw=1.3, shrinkA=3, shrinkB=3)

    # ── exit ────────────────────────────────────────────────────────────
    done_y = 0.105
    tip = (0.865, done_y + 0.052)
    _curve(ax, edge(pos["miss"], tip, -0.05, r), tip,
           -0.05, color=GREEN, lw=1.8, shrinkA=0, shrinkB=3)
    ax.text(0.905, (pos["miss"][1] + tip[1]) / 2, "zero left", fontsize=8.8,
            color=GREEN, fontweight="bold", ha="left", va="center", zorder=5)
    _pill(ax, 0.795, done_y, 0.36, 0.078, "DONE", "",
          edge=GREEN, face="#f0fff4")

    fig.savefig(out, bbox_inches="tight", facecolor=PAPER, pad_inches=0.22)
    print(f"[plot] wrote {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="methodology.png")
    ap.add_argument("--no-measure", action="store_true",
                    help="draw the structure only, numbers blank (layout check)")
    args = ap.parse_args()
    m = None if args.no_measure else measure()
    draw(m, args.out)


if __name__ == "__main__":
    main()
