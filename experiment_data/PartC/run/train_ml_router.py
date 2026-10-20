"""
experiment_data/PartC/run/train_ml_router.py — IRT + NN router vs the regex HoneyRouter.

Trains a routing policy from Part C's ALREADY-COLLECTED real responses -- no new
agent calls. cowrie.jsonl / on_device.jsonl / cloud.jsonl are the same 2179
commands, index-aligned (verified: same session_id/position/trial/cmd at every
row), each with that arm's REAL recorded answer against the SAME ground truth.

Pipeline:
  1. Score every arm's real response against ground truth (score_all_metrics.py's
     own _fast_metrics, so numbers line up with the rest of Part C) -> a
     2179 x 3 correctness matrix.
  2. Fit a Rasch (1PL) IRT model on that matrix: P(correct) = sigmoid(theta_arm -
     b_item). Only 3 respondents (the arms), so discrimination (2PL's `a`) is
     not identifiable -- Rasch is the honest fit here, not a simplification of
     convenience.
  3. Train a small NN (TF-IDF char n-grams -> MLP) to predict b_item from the
     command TEXT alone. This is what lets it route commands outside the 2179;
     b_item itself only exists for rows already scored.
  4. Router: for a command, predict b_hat, combine with each arm's theta and
     real per-arm cost (same formula as cost_analysis.py: cloud $/call for
     cloud, GPU_AVG_WATT x latency for on_device, 0 for cowrie) into a utility
     fidelity(arm) - lambda*cost(arm), argmax picks the arm.
  5. REPLAY: for every command, the response actually served is the stored real
     response from whichever arm was picked -- same mechanism replay_honeyrouter.py
     uses for the regex router, just a different routing function.
  6. Scored and costed by CALLING score_all_metrics.py's _fast_metrics and
     cost_analysis.py's own cost primitives (cost.cost_model.gpu_avg_watt,
     cost.power_cost.kwh_to_thb) -- nothing re-derived, one file.
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np
import torch

_HERE = os.path.dirname(os.path.abspath(__file__))                       # .../PartC/run
_PARTC = os.path.dirname(_HERE)                                          # .../PartC
_ROOT = os.path.abspath(os.path.join(_PARTC, "..", ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "evaluation"))
sys.path.insert(0, os.path.join(_PARTC, "score"))

FIDELITY = os.path.join(_ROOT, "experiment_data", "results", "partC", "fidelity")
OUT_DIR = os.path.join(_ROOT, "experiment_data", "results", "partC_ml_router")
ARMS = ("cowrie", "on_device", "cloud")


# ── 1. score every arm's real response against ground truth ────────────────

def load_matrix():
    from score_all_metrics import _fast_metrics  # noqa: E402

    rows = {a: [json.loads(l) for l in open(os.path.join(FIDELITY, f"{a}.jsonl"))]
            for a in ARMS}
    n = len(rows["cowrie"])
    for a in ARMS[1:]:
        assert len(rows[a]) == n

    cmds, scores, meta = [], np.zeros((n, 3)), []
    for i in range(n):
        base = rows["cowrie"][i]
        cmds.append(base["cmd"])
        meta.append({"session_id": base["session_id"],
                     "position_in_session": base["position_in_session"],
                     "trial": base["trial"], "cmd": base["cmd"],
                     "ground_truth": base["ground_truth"],
                     "fi_score": base["fi_score"]})
        for j, a in enumerate(ARMS):
            r = rows[a][i]
            fm = _fast_metrics(r.get("response"), r.get("ground_truth"))
            # one scalar "correctness" per (command, arm): mean of the
            # non-BERT metrics already used elsewhere in Part C -- avoids a
            # GPU dependency here, and avoids picking one metric over another.
            scores[i, j] = np.mean([fm["cosine_score"], fm["levenshtein_score"],
                                    fm["jaro_winkler_score"], fm["sequence_score"]])
    return cmds, scores, meta, rows


# ── 2. Rasch (1PL) fit by gradient descent ──────────────────────────────────

def fit_rasch(scores, epochs=2000, lr=0.1, l2=1e-3):
    """theta_arm (3,), b_item (n,) minimizing BCE between sigmoid(theta-b) and
    the continuous correctness score, treated as a soft target in [0,1] --
    with 3 respondents per item there is no discrete trial count to be exact
    about, so this is the honest reading of "probability of a correct answer".
    """
    n = scores.shape[0]
    y = torch.tensor(scores, dtype=torch.float32)
    theta = torch.zeros(3, requires_grad=True)
    b = torch.zeros(n, requires_grad=True)
    opt = torch.optim.Adam([theta, b], lr=lr)
    for _ in range(epochs):
        opt.zero_grad()
        p = torch.sigmoid(theta.unsqueeze(0) - b.unsqueeze(1))       # (n, 3)
        loss = torch.nn.functional.binary_cross_entropy(p, y) + l2 * (b ** 2).mean()
        loss.backward()
        opt.step()
    return theta.detach().numpy(), b.detach().numpy()


# ── 3. NN: command text -> predicted difficulty ─────────────────────────────

class DifficultyNet(torch.nn.Module):
    def __init__(self, in_dim, hidden=64):
        super().__init__()
        self.net = torch.nn.Sequential(
            torch.nn.Linear(in_dim, hidden), torch.nn.ReLU(),
            torch.nn.Linear(hidden, 1))

    def forward(self, x):
        return self.net(x).squeeze(-1)


def train_nn(cmds, b, epochs=300, lr=1e-3, seed=0):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split

    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), max_features=2000)
    X = vec.fit_transform(cmds).toarray().astype(np.float32)
    idx = np.arange(len(cmds))
    tr, te = train_test_split(idx, test_size=0.2, random_state=seed)

    net = DifficultyNet(X.shape[1])
    opt = torch.optim.Adam(net.parameters(), lr=lr)
    Xt, bt = torch.tensor(X[tr]), torch.tensor(b[tr], dtype=torch.float32)
    Xe, be = torch.tensor(X[te]), torch.tensor(b[te], dtype=torch.float32)
    for ep in range(epochs):
        opt.zero_grad()
        loss = torch.nn.functional.mse_loss(net(Xt), bt)
        loss.backward()
        opt.step()
    with torch.no_grad():
        pred_te = net(Xe).numpy()
    r = np.corrcoef(pred_te, b[te])[0, 1]
    print(f"[nn] held-out correlation(predicted difficulty, Rasch b) = {r:.3f}  "
          f"(n_test={len(te)})")

    with torch.no_grad():
        b_hat_all = net(torch.tensor(X)).numpy()      # used for routing below
    return net, vec, b_hat_all, r


# ── 4. per-arm real cost basis, same formula as cost_analysis.py ───────────

def per_arm_cost(rows):
    from cost.cost_model import gpu_avg_watt
    from cost.power_cost import kwh_to_thb
    from core.config_loader import load_config

    tariff = load_config().power_tariff
    gpu_w = gpu_avg_watt()
    n = len(rows["cowrie"])

    cloud_usd_per_call = np.array([r.get("cost") or 0.0 for r in rows["cloud"]])
    od_ms_per_call = np.array([r.get("inference_ms") or 0.0 for r in rows["on_device"]])
    od_kwh_per_call = gpu_w * (od_ms_per_call / 1000 / 3600) / 1000.0
    od_thb_per_call = np.array([kwh_to_thb(k, tariff)["total_thb"] if k > 0 else 0.0
                                for k in od_kwh_per_call])
    usd_per_thb = 1 / 35.0
    od_usd_per_call = od_thb_per_call * usd_per_thb

    # mean per-call cost, one scalar per arm -- the routing decision for a
    # command we have not yet run can only use the arm's AVERAGE cost, not
    # that command's own (unknown ahead of time) latency/token count.
    raw = {"cowrie": 0.0, "on_device": float(od_usd_per_call.mean()),
          "cloud": float(cloud_usd_per_call.mean())}
    # normalized to [0,1] by the most expensive arm, so lambda is comparable
    # to fidelity (also [0,1]) instead of needing a guessed huge multiplier
    # to register against a $1e-4 cost.
    scale = max(raw.values()) or 1.0
    norm = {a: v / scale for a, v in raw.items()}
    return norm, raw


# ── 5. route + replay with the REAL stored response ─────────────────────────

def route_and_replay(theta, b_hat_all, cost_mean, lam, rows, meta):
    theta_lut = dict(zip(ARMS, theta))
    picks, out = [], []
    for i, m in enumerate(meta):
        fidelity = {a: 1 / (1 + np.exp(-(theta_lut[a] - b_hat_all[i]))) for a in ARMS}
        utility = {a: fidelity[a] - lam * cost_mean[a] for a in ARMS}
        chosen = max(utility, key=utility.get)
        picks.append(chosen)
        real = rows[chosen][i]
        row = dict(real)
        row["arm"] = "ml_router"
        row["routed_to"] = chosen
        row["ml_utility"] = {a: round(float(v), 4) for a, v in utility.items()}
        out.append(row)
    return picks, out


# ── 6. score against Part C, calling score_all_metrics.py / cost_analysis.py ──

def score_vs_partc(ml_rows):
    """Fidelity + cost for ml_router, next to cowrie/on_device/cloud/honeyrouter --
    calls the SAME functions those arms were scored with, not a re-derivation.
    """
    from collections import defaultdict
    from score_all_metrics import _fast_metrics, _load_valid, METRICS  # noqa: E402

    fast_metrics = [m for m in METRICS if m[0] != "bert_f1"]   # CPU-only here
    arm_files = {a: os.path.join(FIDELITY, f"{a}.jsonl")
                for a in ("cowrie", "on_device", "cloud", "honeyrouter")}
    overall = {}
    for arm, path in arm_files.items():
        vals = defaultdict(list)
        for _fi, resp, gt in _load_valid(path):
            fm = _fast_metrics(resp, gt)
            for k, _ in fast_metrics:
                vals[k].append(fm[k])
        overall[arm] = {k: round(sum(v) / len(v), 4) for k, v in vals.items()}

    vals = defaultdict(list)
    for r in ml_rows:
        fm = _fast_metrics(r.get("response"), r.get("ground_truth"))
        for k, _ in fast_metrics:
            vals[k].append(fm[k])
    overall["ml_router"] = {k: round(sum(v) / len(v), 4) for k, v in vals.items()}

    print("\n" + "=" * 70)
    print("  FIDELITY — honeyrouter (regex) vs ml_router (IRT+NN)")
    print("=" * 70)
    print("  " + f"{'arm':<12}" + "".join(f"{lbl.split(' (')[0]:>13}" for _, lbl in fast_metrics))
    for arm in ("cowrie", "on_device", "cloud", "honeyrouter", "ml_router"):
        row = "  " + f"{arm:<12}"
        for k, _ in fast_metrics:
            row += f"{overall[arm][k]:>13.3f}"
        print(row)

    # cost: same primitives cost_analysis.py uses, called directly
    from cost.cost_model import gpu_avg_watt
    from cost.power_cost import kwh_to_thb
    from core.config_loader import load_config

    tariff = load_config().power_tariff
    gpu_w = gpu_avg_watt()
    usd_per_thb = 1 / 35.0

    cloud_rows = [json.loads(l) for l in open(arm_files["cloud"])]
    ond_rows = [json.loads(l) for l in open(arm_files["on_device"])]
    hr_rows = [json.loads(l) for l in open(arm_files["honeyrouter"])]
    key = lambda r: (str(r["session_id"]), r["position_in_session"])
    cost_lut = {key(r): r.get("cost") for r in cloud_rows}
    lat_lut = {key(r): r.get("inference_ms") for r in ond_rows}

    def cost_of(routed_lut):
        cloud_keys = [k for k, v in routed_lut.items() if v == "cloud"]
        od_keys = [k for k, v in routed_lut.items() if v == "on_device"]
        cloud_usd = sum(cost_lut.get(k) or 0 for k in cloud_keys)
        ms = sum(lat_lut.get(k) or 0 for k in od_keys)
        kwh = gpu_w * (ms / 1000 / 3600) / 1000.0
        thb = kwh_to_thb(kwh, tariff)["total_thb"] if kwh > 0 else 0.0
        return {"cloud_usd": round(cloud_usd, 6), "elec_kwh": round(kwh, 6),
                "elec_thb": round(thb, 4),
                "total_usd": round(cloud_usd + thb * usd_per_thb, 6)}

    hr_routed = {key(r): r["routed_to"] for r in hr_rows}
    ml_routed = {key(r): r["routed_to"] for r in ml_rows}
    cost = {"honeyrouter": cost_of(hr_routed), "ml_router": cost_of(ml_routed)}

    print("\n" + "=" * 70)
    print("  COST — honeyrouter (regex) vs ml_router (IRT+NN)")
    print("=" * 70)
    for a in ("honeyrouter", "ml_router"):
        c = cost[a]
        print(f"  {a:<12} cloud $ {c['cloud_usd']:.4f}  elec kWh {c['elec_kwh']:.4f}  "
              f"total $ {c['total_usd']:.4f}")

    return {"fidelity": overall, "cost": cost}


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--lambda-sweep", dest="lams", default="0,0.25,0.5,0.75,1,1.25,1.5,1.75,2",
                    help="lambda values to try, comma-separated. Cost is "
                         "normalized to [0,1] (divided by the most expensive "
                         "arm's mean $/call), so lambda is now on the SAME "
                         "scale as fidelity -- 0 ignores cost entirely, 1 "
                         "weighs a maximally-expensive call as costing a full "
                         "point of fidelity, 2 weighs it double.")
    ap.add_argument("--epochs-irt", type=int, default=2000)
    ap.add_argument("--epochs-nn", type=int, default=300)
    args = ap.parse_args()
    lams = [float(x) for x in args.lams.split(",")]

    print("[1/5] scoring every arm's real response against ground truth ...")
    cmds, scores, meta, rows = load_matrix()
    print(f"      {scores.shape[0]} commands x {scores.shape[1]} arms  "
          f"mean correctness: " + "  ".join(
              f"{a}={scores[:, j].mean():.3f}" for j, a in enumerate(ARMS)))

    print("[2/5] fitting Rasch IRT ...")
    theta, b = fit_rasch(scores, epochs=args.epochs_irt)
    print(f"      theta (ability): " + "  ".join(
        f"{a}={t:.3f}" for a, t in zip(ARMS, theta)))
    print(f"      b (difficulty): mean={b.mean():.3f} std={b.std():.3f} "
          f"min={b.min():.3f} max={b.max():.3f}")

    print("[3/5] training NN: command text -> difficulty ...")
    net, vec, b_hat_all, corr = train_nn(cmds, b, epochs=args.epochs_nn)

    print("[4/5] computing real per-arm cost basis (normalized to [0,1]) ...")
    cost_norm, cost_raw = per_arm_cost(rows)
    print(f"      raw $/call:  " + "  ".join(f"{a}={c:.6f}" for a, c in cost_raw.items()))
    print(f"      normalized:  " + "  ".join(f"{a}={c:.4f}" for a, c in cost_norm.items()))

    import collections
    sweep = []
    for lam in lams:
        print(f"\n[5/6] lambda={lam} -- routing + replay ...")
        picks, out = route_and_replay(theta, b_hat_all, cost_norm, lam, rows, meta)
        dist = collections.Counter(picks)
        print(f"      routing distribution: {dict(dist)}")

        out_dir = OUT_DIR if lam == lams[0] else os.path.join(OUT_DIR, f"lambda_{lam}")
        os.makedirs(os.path.join(out_dir, "fidelity"), exist_ok=True)
        path = os.path.join(out_dir, "fidelity", "ml_router.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for row in out:
                fh.write(json.dumps(row) + "\n")

        print("[6/6] scoring against Part C (honeyrouter + pure arms) ...")
        comparison = score_vs_partc(out)
        sweep.append({"lambda": lam, "routing_distribution": dict(dist), **comparison})

    print("\n" + "=" * 70)
    print("  LAMBDA SWEEP -- fidelity (cosine) vs cost, ml_router only")
    print("=" * 70)
    print(f"  {'lambda':>8}{'cowrie':>9}{'on_device':>11}{'cloud':>8}"
          f"{'cosine':>9}{'total_usd':>11}")
    for s in sweep:
        d, f, c = s["routing_distribution"], s["fidelity"]["ml_router"], s["cost"]["ml_router"]
        print(f"  {s['lambda']:>8.2f}{d.get('cowrie', 0):>9}{d.get('on_device', 0):>11}"
              f"{d.get('cloud', 0):>8}{f['cosine_score']:>9.3f}{c['total_usd']:>11.4f}")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "irt_model.json"), "w") as fh:
        json.dump({"theta": dict(zip(ARMS, theta.tolist())),
                   "nn_held_out_correlation": float(corr),
                   "mean_cost_usd_raw": cost_raw, "mean_cost_normalized": cost_norm,
                   "lambda_sweep": sweep}, fh, indent=2)
    print(f"\nwrote {os.path.join(OUT_DIR, 'irt_model.json')}")
    print(f"ml_router.jsonl for lambda={lams[0]} at {OUT_DIR}/fidelity/; "
          f"other lambdas under {OUT_DIR}/lambda_<value>/fidelity/")


if __name__ == "__main__":
    main()
