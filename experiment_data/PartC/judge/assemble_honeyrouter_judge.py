"""
experiment_data/PartC/assemble_honeyrouter_judge.py — build HoneyRouter's LLM-as-a-judge
scores WITHOUT re-calling the judge, by reusing the per-arm judge scores.

Why this works: the judge already scored every agent's response per command
(judge_scored_<arm>_<model>.jsonl). HoneyRouter just picks ONE agent per command
via the router. So HoneyRouter's judge score for a command = the judge score of
whichever agent the current routing (config.yaml) selects — a lookup, not a new
API call. Change the routing → re-run this → done. Zero judge calls, zero cost.

Routing source: router.classify() read from the LIVE config.yaml (so it reflects
your current fi_routing + which agents are enabled). Obfuscated commands follow
the same _is_cloud rule; if cloud is disabled they fall back to the strongest
enabled agent, exactly like production.

    python experiment_data/PartC/assemble_honeyrouter_judge.py
    python experiment_data/PartC/assemble_honeyrouter_judge.py --model z-ai_glm-5

Outputs -> results/fidelity_full109_final/:
    honeyrouter_judge_<model>.jsonl     per-command assembled judge scores
    judge_by_fi_<model>.png             judge score per FI band, 4 arms (house style)
    judge_scores_<model>.json           per-band + overall means
─────────────────────────────────────────────────────────────────────────────────
"""

import os
import sys
import json
import argparse
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# PartC/, not this sub-folder: every path below is relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

from core.router import classify   # noqa: E402  — reads live config.yaml routing

plt.rcParams.update({
    "font.family": "sans-serif", "font.size": 11,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y",
    "grid.color": "#E0E0E0", "grid.linewidth": 0.7,
    "savefig.dpi": 300, "figure.dpi": 150,
})

JUDGE_DIR = os.path.join(_HERE, "..", "results", "partC", "fidelity_full109_final")
ARM_ORDER = ["cowrie", "on_device", "cloud", "honeyrouter"]
ARM_COLOR = {"cowrie": "#AAAAAA", "on_device": "#7EB3C8",
             "cloud": "#5B7FA6", "honeyrouter": "#E07B39"}
ARM_LABEL = {"cowrie": "Pure Cowrie", "on_device": "Pure On-device LLM",
             "cloud": "Pure Cloud LLM", "honeyrouter": "HydraPoT"}
FI_BANDS = [0, 1, 2, 3, 4]


def load_judge(arm, model):
    """(str(session_id), position) -> record. Dedup keeping a SCORED record."""
    path = os.path.join(JUDGE_DIR, f"judge_scored_{arm}_{model}.jsonl")
    lut = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            k = (str(r["session_id"]), r["position_in_session"])
            # prefer a record that actually has a score over a null one
            if k not in lut or (lut[k].get("judge_score") is None and r.get("judge_score") is not None):
                lut[k] = r
    return lut


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="z-ai_glm-5",
                    help="judge model suffix in the filenames (default z-ai_glm-5)")
    args = ap.parse_args()

    luts = {a: load_judge(a, args.model) for a in ("cowrie", "on_device", "cloud")}
    print(f"[judge] loaded per-arm judge scores: " +
          ", ".join(f"{a}={len(l)}" for a, l in luts.items()))

    # master command list = cowrie file (clean 2179, has cmd + fi_score)
    master = list(luts["cowrie"].values())

    out_path = os.path.join(JUDGE_DIR, f"honeyrouter_judge_{args.model}.jsonl")
    fout = open(out_path, "w", encoding="utf-8")

    # per-arm + honeyrouter, grouped by FI  AND  grouped by session
    byfi = {a: defaultdict(list) for a in ARM_ORDER}
    bysession = {a: defaultdict(list) for a in ARM_ORDER}
    from collections import Counter
    routed_counter = Counter()
    miss = 0

    for rec in master:
        sid = str(rec["session_id"])
        k = (sid, rec["position_in_session"])
        fi = rec.get("fi_score")
        cmd = rec["cmd"]

        # pure-arm judge scores (for the comparison bars)
        for a in ("cowrie", "on_device", "cloud"):
            jr = luts[a].get(k)
            if jr and jr.get("judge_score") is not None:
                bysession[a][sid].append(jr["judge_score"])
                if fi is not None:
                    byfi[a][fi].append(jr["judge_score"])

        # HoneyRouter: route with current config, take that agent's judge score
        agent = classify(cmd, [])
        routed_counter[agent] += 1
        jr = luts.get(agent, {}).get(k)
        if jr is None or jr.get("judge_score") is None:
            miss += 1
            continue
        score = jr["judge_score"]
        if fi is not None:
            byfi["honeyrouter"][fi].append(score)
        bysession["honeyrouter"][sid].append(score)
        fout.write(json.dumps({
            "session_id": rec["session_id"], "position_in_session": rec["position_in_session"],
            "cmd": cmd, "fi_score": fi, "routed_to": agent,
            "judge_score": score, "judge_reason": jr.get("judge_reason"),
        }, ensure_ascii=False) + "\n")
    fout.close()

    # aggregate: per-FI mean, per-command overall, and per-SESSION average
    # (mean within each session, then averaged across sessions)
    summary, overall, session_avg = {}, {}, {}
    for a in ARM_ORDER:
        summary[a] = {}
        allv = []
        for fi in FI_BANDS:
            vals = byfi[a].get(fi, [])
            summary[a][fi] = (sum(vals) / len(vals)) if vals else None
            allv += vals
        overall[a] = (sum(allv) / len(allv)) if allv else None
        sess_means = [sum(v) / len(v) for v in bysession[a].values() if v]
        session_avg[a] = (sum(sess_means) / len(sess_means)) if sess_means else None

    json.dump({"per_band": summary, "overall_per_command": overall,
               "overall_per_session": session_avg,
               "n_sessions": {a: len(bysession[a]) for a in ARM_ORDER},
               "routing": dict(routed_counter), "misses": miss},
              open(os.path.join(JUDGE_DIR, f"judge_scores_{args.model}.json"), "w"), indent=2)

    # ── plot: 2 panels — (left) per FI band, (right) per-session average ───────
    fig, (axL, axR) = plt.subplots(
        1, 2, figsize=(13, 5.4), gridspec_kw={"width_ratios": [2.4, 1]})

    # left: grouped bars by FI band
    x = np.arange(len(FI_BANDS))
    w = 0.8 / len(ARM_ORDER)
    for i, a in enumerate(ARM_ORDER):
        vals = [summary[a].get(fi) or 0 for fi in FI_BANDS]
        off = (i - (len(ARM_ORDER) - 1) / 2) * w
        axL.bar(x + off, vals, w, label=ARM_LABEL[a], color=ARM_COLOR[a],
                edgecolor="white", linewidth=0.6)
    axL.set_xticks(x); axL.set_xticklabels([f"FI{fi}" for fi in FI_BANDS])
    axL.set_ylabel("LLM-as-a-judge score (1–5)")
    axL.set_ylim(0, 5.3)
    axL.set_title("By FI band", fontsize=12, fontweight="bold")
    axL.legend(fontsize=8.5, ncol=2, loc="lower center")

    # right: one bar per arm = average of per-session means
    xr = np.arange(len(ARM_ORDER))
    vals = [session_avg[a] or 0 for a in ARM_ORDER]
    bars = axR.bar(xr, vals, color=[ARM_COLOR[a] for a in ARM_ORDER],
                   edgecolor="white", linewidth=0.8)
    for b, v in zip(bars, vals):
        axR.text(b.get_x() + b.get_width() / 2, v + 0.05, f"{v:.2f}",
                 ha="center", va="bottom", fontsize=9, fontweight="bold")
    axR.set_xticks(xr)
    axR.set_xticklabels([ARM_LABEL[a].replace("Pure ", "").replace(" LLM", "")
                         for a in ARM_ORDER], fontsize=9, rotation=15)
    axR.set_ylim(0, 5.3)
    axR.set_title("Avg per session", fontsize=12, fontweight="bold")

    fig.tight_layout()
    out_png = os.path.join(JUDGE_DIR, f"judge_by_fi_{args.model}.png")
    fig.savefig(out_png, dpi=300, bbox_inches="tight"); plt.close(fig)

    # ── report ────────────────────────────────────────────────────────────────
    print(f"\n[judge] routing (current config): {dict(routed_counter)}")
    if miss:
        print(f"[judge] {miss} commands had no judge score for the routed arm (skipped)")
    print("\n  LLM-judge score (1-5):")
    print(f"    {'arm':<22}{'per-command':>13}{'per-session':>14}")
    for a in ARM_ORDER:
        v, s = overall[a], session_avg[a]
        print(f"    {ARM_LABEL[a]:<22}{(f'{v:.3f}' if v is not None else '-'):>13}"
              f"{(f'{s:.3f}' if s is not None else '-'):>14}")
    print(f"\n  saved -> {out_path}")
    print(f"  saved -> {out_png}")


if __name__ == "__main__":
    main()
