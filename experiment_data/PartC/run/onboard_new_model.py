"""
experiment_data/PartC/run/onboard_new_model.py -- add ONE new model by fitting only its vector.

The router network is trained once. A new model takes over one slot; its true
labels come from running it on every command and judging with the same judge
(the answer key). Only the prompts in selected_prompts.json are shown to the fit,
the network and the other vectors stay frozen, and the result is graded on
held-out sessions against the new model's own true labels.

    exp A  benchmark_score/   start from [benchmark score, 2 small random numbers]
    exp B  no_benchmark/      start from the mean of the existing identities + noise

    python experiment_data/PartC/run/onboard_new_model.py \
        --true-dir experiment_data/results/partC_onboarding/glm-5.3_true_run --bench-score 0.917
"""
import argparse
import glob
import json
import os
import shutil
import sys

import numpy as np
import torch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from honeyrouter import onboarding as OB                     # noqa: E402
from honeyrouter import predictor as P                       # noqa: E402
from honeyrouter.action import AGENTS                        # noqa: E402
from honeyrouter.sessions import load_sessions               # noqa: E402
import eval_onboarding as EO                                 # noqa: E402

BASE = os.path.join(ROOT, "experiment_data", "results", "partC_onboarding")
BUDGETS = (10, 20, 30)          # 50 is the saved set itself


def load_true_scores(true_dir):
    """(session_id, position) -> the new model's real 1-5 judge score. Unscored rows are absent."""
    files = glob.glob(os.path.join(true_dir, "judge", "*", "judge_scored_*.jsonl"))
    if len(files) != 1:
        sys.exit(f"expected one judge file under {true_dir}/judge, found {files}")
    out = {}
    with open(files[0], encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            if isinstance(r.get("judge_score"), (int, float)):
                out[(str(r["session_id"]), int(r["position_in_session"]))] = float(r["judge_score"])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--true-dir", required=True)
    ap.add_argument("--bench-score", type=float, required=True)
    ap.add_argument("--slot", default="cloud", choices=list(AGENTS))
    ap.add_argument("--seeds", type=int, default=5)
    args = ap.parse_args()
    k = list(AGENTS).index(args.slot)

    E, Y_old, raw_old, sids, eta = P.build_dataset()
    sess = load_sessions()
    keys = [(str(sid), int(c["position"])) for sid, cmds in sess.items() for c in cmds]
    texts = np.array([c["cmd"] for cmds in sess.values() for c in cmds])
    row = {key: i for i, key in enumerate(keys)}

    true = load_true_scores(args.true_dir)
    valid = np.array([key in true for key in keys])
    raw = raw_old.copy()
    raw[:, k] = [true.get(key, np.nan) for key in keys]
    # same scaling and same eta as the existing arms: the label rule is not ours to change
    norm = np.clip((raw[:, k] - 1.0) / 4.0, 0.0, 1.0)
    Y = Y_old.copy()
    Y[:, k] = (norm > eta).astype(np.float32)
    print(f"true labels: {int(valid.sum())}/{len(valid)} commands scored, eta={eta:.3f}, "
          f"success rate {Y[valid, k].mean():.3f}")

    sel = json.load(open(os.path.join(BASE, "selected_prompts.json"), encoding="utf-8"))
    at = lambda recs: np.array([row[(str(r["session_id"]), int(r["position_in_session"]))] for r in recs])
    fit_idx, chk_idx = at(sel["fit_prompts"]), at(sel["check_prompts"])
    held = np.isin(sids, [str(s) for s in sel["heldout_session_ids"]])
    fit_ok, chk_ok, held_ok = fit_idx[valid[fit_idx]], chk_idx[valid[chk_idx]], np.flatnonzero(held & valid)
    print(f"fit prompts {len(fit_ok)}/{len(fit_idx)} scored | check {len(chk_ok)}/{len(chk_idx)} | "
          f"held-out rows {len(held_ok)} ({len(sel['heldout_session_ids'])} sessions)")

    model, _ = P.load()
    for p in model.parameters():
        p.requires_grad_(False)
    Et, Yt = torch.tensor(E), torch.tensor(Y)
    yk = Yt[:, k]
    ev, yv = Et[held_ok], yk[held_ok]

    tr, _va = P.split_by_session(sids, seed=0)
    pool = np.flatnonzero(tr & valid)
    psi = OB.discrimination(model, Et[pool], torch.tensor(Y_old)[pool])

    bench = P.benchmark_identity()[0].clone()
    bench[k, 0] = args.bench_score
    mean_existing = model.mu.detach().mean(0)

    def start(tag, seed):
        g = torch.Generator().manual_seed(1000 + seed)
        if tag == "A":
            return torch.cat([bench[k], 0.5 * torch.randn(EO.EXTRA, generator=g)])
        return mean_existing + 0.1 * torch.randn(mean_existing.shape[0], generator=g)

    def grade(I):
        return OB.evaluate_identity(model, I, ev, yv)

    r_ = min(max(float(yk[fit_ok].mean()), 1e-4), 1 - 1e-4)
    base = {
        "constant guess": {"bce": float(-(yv * np.log(r_) + (1 - yv) * np.log(1 - r_)).mean()),
                           "acc": float(((yv > 0.5) == (r_ > 0.5)).float().mean()), "auc": 0.5},
        "keep old vector (no onboarding)": grade(model.mu[k].detach()),
    }

    trn = np.flatnonzero(tr & valid)
    Rt = torch.tensor(np.nan_to_num(raw, nan=3.0))
    full = []
    for seed in range(args.seeds):
        torch.manual_seed(100 + seed)
        net = EO.train_stage1(Et[trn], Yt[trn], Rt[trn], bench, list(range(len(AGENTS))), seed)
        full.append(OB.evaluate_identity(net, net.mu[k], ev, yv))
    base["full retrain with true labels (ruler)"] = EO.summarise(full)

    for tag, folder in (("A", "benchmark_score"), ("B", "no_benchmark")):
        out = os.path.join(BASE, folder)
        os.makedirs(out, exist_ok=True)
        shutil.copy(os.path.join(BASE, "selected_prompts.json"), os.path.join(out, "selected_prompts.json"))
        with open(os.path.join(out, "fit_labels.json"), "w", encoding="utf-8") as fh:
            json.dump([{"session_id": keys[i][0], "position_in_session": keys[i][1], "cmd": str(texts[i]),
                        "judge_score": float(raw[i, k]), "label": int(Y[i, k])} for i in fit_ok], fh, indent=1)
        rows, vectors = {}, {}
        for seed in range(args.seeds):
            s0 = start(tag, seed)
            sets = {f"{n:>2} prompts": OB.stratified_select(psi, n, seed=seed, groups=texts[pool])
                    for n in BUDGETS}
            for name, idx in {**{n: pool[v] for n, v in sets.items()}, "50 prompts": fit_ok}.items():
                I = OB.fit_identity(model, Et[idx], yk[idx], s0)
                rows.setdefault(name, []).append(grade(I))
                vectors.setdefault(name, []).append([round(float(x), 5) for x in I])
                if name == "50 prompts":
                    ok = OB.worth_trusting(OB.evaluate_identity(model, I, Et[chk_ok], yk[chk_ok]),
                                           yk[chk_ok], float(yk[idx].mean()))
                    rows.setdefault("check passed (50 prompts)", []).append(
                        {"bce": float(ok), "acc": float(ok), "auc": float(ok)})
            rows.setdefault("all train prompts (upper bound for a frozen net)", []).append(
                grade(OB.fit_identity(model, Et[trn], yk[trn], s0)))
        table = {**{k_: v for k_, v in base.items()}, **{n: EO.summarise(v) for n, v in rows.items()}}
        table = {n: (v if "bce" in v and isinstance(v["bce"], tuple) else {c: (v[c], 0.0) for c in ("bce", "acc", "auc")})
                 for n, v in table.items()}
        with open(os.path.join(out, "results.json"), "w", encoding="utf-8") as fh:
            json.dump({"table": table, "vectors": vectors, "bench_score": args.bench_score if tag == "A" else None,
                       "seeds": args.seeds, "eta": float(eta), "n_heldout_rows": int(len(held_ok))}, fh, indent=1)
        start_txt = (f"[{args.bench_score}, 2 small random numbers]" if tag == "A"
                     else "mean of the existing identities + noise")
        lines = [f"New model onboarding, exp {tag} ({folder}); start = {start_txt}",
                 f"slot={args.slot}, true labels from {os.path.basename(args.true_dir)}, "
                 f"{len(fit_ok)} fit prompts, {len(chk_ok)} check prompts, "
                 f"{len(held_ok)} held-out rows, {args.seeds} seeds (mean +- sd). Lower BCE, higher acc/AUC is better.\n",
                 f"  {'method':<52} {'BCE':>13} {'acc':>13} {'AUC':>13}"]
        for name, m in table.items():
            if name.startswith("check"):
                lines.append(f"  {name:<52} passed in {100 * m['bce'][0]:.0f}% of seeds")
            else:
                lines.append(f"  {name:<52} " + " ".join(f"{m[c][0]:6.3f}+-{m[c][1]:5.3f}" for c in ("bce", "acc", "auc")))
        text = "\n".join(lines) + "\n"
        with open(os.path.join(out, "summary.txt"), "w", encoding="utf-8") as fh:
            fh.write(text)
        print("\n" + text)


if __name__ == "__main__":
    main()
