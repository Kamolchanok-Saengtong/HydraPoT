"""
experiment_data/PartC/cost_analysis.py — cost of each arm under the CURRENT routing.

Two real cost sources:
  • Cloud  = actual per-command $ billed (from the cloud arm, deepseek-v4-flash)
  • On-device = electricity: GPU_AVG_WATT x inference time -> kWh -> THB (MEA tariff)
  • Cowrie = ~free (a lightweight container)

For each arm (Pure Cowrie / Pure On-device / Pure Cloud / HydraPoT) it sums the
cost of the commands that arm actually handles under router.classify() (live
config.yaml). HydraPoT only pays cloud $ for the ~24% of commands routed to cloud.

    python experiment_data/PartC/cost_analysis.py

Outputs -> results/fidelity_full109_final/:
    cost_by_arm.png     total cost per arm (house style)
    cost_analysis.json  all the numbers
─────────────────────────────────────────────────────────────────────────────────
"""
import os, sys, json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# PartC/, not this sub-folder: every path below is relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, _ROOT); sys.path.insert(0, _ROOT)  # measure.py + power_cost.py live at the root
os.chdir(_ROOT)
from core.router import classify
from core.config_loader import load_config
from cost.power_cost import kwh_to_thb

plt.rcParams.update({"font.family": "sans-serif", "font.size": 11,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "axes.grid.axis": "y", "grid.color": "#E0E0E0", "grid.linewidth": 0.7,
    "savefig.dpi": 300, "figure.dpi": 150})

# ── constants (same as dashboard.py) ──────────────────────────────────────────
# Measured value comes from the root cost_model.py (config.yaml) so this
# analysis and the live dashboard can never disagree about the same GPU.
from cost.cost_model import gpu_avg_watt as _gpu_avg_watt
GPU_AVG_WATT = _gpu_avg_watt()
USD_PER_THB  = 1 / 35.0        # ~2026 fx; electricity(THB) -> USD for one combined bar

# The CURRENT run's arm files, not a dated snapshot of an old one: these paths
# were frozen at a 2026-07 results folder that the results/ reorg moved away, so
# the script had been unrunnable and its numbers could not be reproduced.
FIDELITY  = os.path.join(_HERE, "..", "results", "partC", "fidelity")
CLOUD     = os.path.join(FIDELITY, "cloud.jsonl")       # has $ cost/cmd
OND       = os.path.join(FIDELITY, "on_device.jsonl")   # has inference_ms/cmd
JUDGE_DIR = os.path.join(_HERE, "..", "results", "partC", "semantic_analysis")

ARM_ORDER = ["cowrie", "on_device", "cloud", "honeyrouter"]
ARM_COLOR = {"cowrie": "#AAAAAA", "on_device": "#7EB3C8", "cloud": "#5B7FA6", "honeyrouter": "#E07B39"}
ARM_LABEL = {"cowrie": "Pure Cowrie", "on_device": "Pure On-device LLM", "cloud": "Pure Cloud LLM", "honeyrouter": "HydraPoT"}


def main():
    tariff = load_config().power_tariff
    os.makedirs(JUDGE_DIR, exist_ok=True)
    cloud = [json.loads(l) for l in open(CLOUD) if l.strip()]
    ond   = [json.loads(l) for l in open(OND) if l.strip()]
    cost_lut = {(str(r["session_id"]), r["position_in_session"]): r.get("cost") for r in cloud}
    lat_lut  = {(str(r["session_id"]), r["position_in_session"]): r.get("inference_ms") for r in ond}

    # routing per command (current config)
    routed = {}
    for r in cloud:
        routed[(str(r["session_id"]), r["position_in_session"])] = classify(r["cmd"], [])

    def cloud_usd(keys):
        return sum(cost_lut.get(k) or 0 for k in keys)
    def elec(keys):  # kWh + THB for on-device compute over these keys
        ms = sum(lat_lut.get(k) or 0 for k in keys)
        kwh = GPU_AVG_WATT * (ms / 1000 / 3600) / 1000.0
        thb = kwh_to_thb(kwh, tariff)["total_thb"] if kwh > 0 else 0.0
        return kwh, thb

    allkeys = list(cost_lut.keys())
    cloud_keys = [k for k in allkeys if routed[k] == "cloud"]
    od_keys    = [k for k in allkeys if routed[k] == "on_device"]

    # cost per arm
    res = {}
    #   Pure Cowrie: no cloud, no GPU
    res["cowrie"] = {"cloud_usd": 0.0, "elec_kwh": 0.0, "elec_thb": 0.0}
    #   Pure On-device: ALL commands on GPU
    k, t = elec(allkeys); res["on_device"] = {"cloud_usd": 0.0, "elec_kwh": k, "elec_thb": t}
    #   Pure Cloud: ALL commands to cloud
    res["cloud"] = {"cloud_usd": cloud_usd(allkeys), "elec_kwh": 0.0, "elec_thb": 0.0}
    #   HydraPoT: cloud $ for cloud-routed + electricity for on-device-routed
    k, t = elec(od_keys)
    res["honeyrouter"] = {"cloud_usd": cloud_usd(cloud_keys), "elec_kwh": k, "elec_thb": t}

    for a in ARM_ORDER:
        res[a]["total_usd"] = res[a]["cloud_usd"] + res[a]["elec_thb"] * USD_PER_THB
    json.dump({"routing": {a: sum(1 for v in routed.values() if v == a) for a in ("cowrie","on_device","cloud")},
               "per_arm": res}, open(os.path.join(JUDGE_DIR, "cost_analysis.json"), "w"), indent=2)

    # ── report ────────────────────────────────────────────────────────────────
    pc = res["cloud"]["total_usd"]
    print("=" * 70)
    print("  COST ANALYSIS — current routing (2179 commands)")
    print("=" * 70)
    print(f"  {'arm':<20}{'cloud $':>10}{'elec kWh':>10}{'elec THB':>10}{'TOTAL $':>10}")
    for a in ARM_ORDER:
        r = res[a]
        print(f"  {ARM_LABEL[a]:<20}{r['cloud_usd']:>10.4f}{r['elec_kwh']:>10.4f}"
              f"{r['elec_thb']:>10.3f}{r['total_usd']:>10.4f}")
    hp = res["honeyrouter"]["total_usd"]
    print("-" * 70)
    print(f"  Pure Cloud total : ${pc:.4f}")
    print(f"  HydraPoT total   : ${hp:.4f}")
    print(f"  >>> HydraPoT saves {(1-hp/pc)*100:.1f}% vs pure cloud  (costs {hp/pc*100:.1f}%)")
    print("=" * 70)

    # ── plot: total cost per arm ($) ──────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5.2))
    vals = [res[a]["total_usd"] for a in ARM_ORDER]
    bars = ax.bar(range(len(ARM_ORDER)), vals,
                  color=[ARM_COLOR[a] for a in ARM_ORDER], edgecolor="white", linewidth=0.8)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width()/2, v + max(vals)*0.01, f"${v:.3f}",
                ha="center", va="bottom", fontsize=10, fontweight="bold")
    ax.set_xticks(range(len(ARM_ORDER)))
    ax.set_xticklabels([ARM_LABEL[a] for a in ARM_ORDER], fontsize=9)
    ax.set_ylabel("Total cost to process 2,179 commands (USD)")
    ax.set_title("Cost per arm — cloud $ + on-device electricity", fontsize=12, fontweight="bold")
    fig.tight_layout()
    out = os.path.join(JUDGE_DIR, "cost_by_arm.png")
    fig.savefig(out, dpi=300, bbox_inches="tight"); plt.close(fig)
    print(f"\n  saved -> {out}")


if __name__ == "__main__":
    main()
