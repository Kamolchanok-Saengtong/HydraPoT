"""
experiment_data/PartC/run/eval_onboarding.py -- is "frozen network + fit only the new vector" enough?

Each arm is treated as the NEW model in turn. The network is trained on the other
two arms only, so the new arm is unseen. Then its 3-number identity is fitted on a
few prompts chosen by honeyrouter/onboarding.py and compared, on sessions held
out from everything, with fully retraining the network on all three arms.

    exp A  start from the benchmark score:  I0 = [GPQA score, 2 small random numbers]
    exp B  no benchmark score:              I0 = mean of the existing identities + noise

    python experiment_data/PartC/run/eval_onboarding.py --seeds 5
"""
import argparse
import json
import os
import sys

import numpy as np
import torch
import torch.nn as nn

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, ROOT)

from honeyrouter import onboarding as OB                     # noqa: E402
from honeyrouter import predictor as P                       # noqa: E402
from honeyrouter.action import AGENTS                        # noqa: E402
from honeyrouter.sessions import load_sessions               # noqa: E402

OUT = os.path.join(ROOT, "experiment_data", "results", "partC_onboarding")
BUDGETS = (10, 20, 30, 50)
EXTRA = 2


def train_stage1(E, Y, raw, bench, arms, seed, epochs=10, batch=256, lr=1e-3):
    """The current recipe (bench+2learn+net) on a subset of arms. Writes nothing."""
    torch.manual_seed(seed)
    init = torch.cat([bench[arms], 0.5 * torch.randn(len(arms), EXTRA)], dim=1)
    model = P.Predictor(E.shape[1], len(arms), dim=init.shape[1],
                        identity="vector_learn", init_mu=init)
    Y, raw = Y[:, arms], raw[:, arms]
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    sched = torch.optim.lr_scheduler.ExponentialLR(opt, gamma=0.95)
    rng = np.random.default_rng(seed)
    for _ in range(epochs):
        model.train()
        order = rng.permutation(len(E))
        for s in range(0, len(E), batch):
            idx = torch.as_tensor(order[s:s + batch])
            I = model.sample_identity(train=True)
            loss = (nn.functional.binary_cross_entropy_with_logits(model.logits(E[idx], I), Y[idx])
                    + P.pairwise_loss(model.pair_logits(E[idx], I), raw[idx]))
            opt.zero_grad()
            loss.backward()
            opt.step()
        sched.step()
    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)
    return model


def random_select(n, seed, groups):
    rng = np.random.default_rng(seed)
    seen, out = set(), []
    for i in rng.permutation(len(groups)):
        if groups[i] not in seen:
            seen.add(groups[i])
            out.append(int(i))
        if len(out) == n:
            break
    return np.array(sorted(out))


def summarise(rows):
    out = {}
    for key in ("bce", "acc", "auc"):
        v = np.array([r[key] for r in rows], dtype=float)
        out[key] = (float(np.nanmean(v)), float(np.nanstd(v)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--arms", nargs="+", default=list(AGENTS), choices=list(AGENTS))
    args = ap.parse_args()

    E, Y, raw, sids, eta = P.build_dataset()
    texts = np.array([c["cmd"] for cmds in load_sessions().values() for c in cmds])
    tr, va = P.split_by_session(sids, seed=0)
    bench = P.benchmark_identity()[0]
    Et, Yt, Rt = (torch.tensor(x[tr]) for x in (E, Y, raw))
    Ev, Yv = torch.tensor(E[va]), torch.tensor(Y[va])
    tt = texts[tr]
    print(f"train rows {int(tr.sum())}, held-out rows {int(va.sum())}, eta*={eta:.2f}")

    results = {}
    for k_name in args.arms:
        k = list(AGENTS).index(k_name)
        ex = [j for j in range(len(AGENTS)) if j != k]
        acc = {}

        def add(name, row):
            acc.setdefault(name, []).append(row)

        for seed in range(args.seeds):
            torch.manual_seed(100 + seed)
            frozen = train_stage1(Et, Yt, Rt, bench, ex, seed)
            psi = OB.discrimination(frozen, Et, Yt[:, ex])
            yk, yv = Yt[:, k], Yv[:, k]
            rate = float(yk.mean())

            r = min(max(rate, 1e-4), 1 - 1e-4)
            add("constant guess", {"bce": float(-(yv * np.log(r) + (1 - yv) * np.log(1 - r)).mean()),
                                   "acc": float(((yv > 0.5) == (r > 0.5)).float().mean()),
                                   "auc": 0.5})

            full = train_stage1(Et, Yt, Rt, bench, list(range(len(AGENTS))), seed)
            add("full retrain (all 3 arms)", OB.evaluate_identity(full, full.mu[k], Ev, yv))

            start_a = torch.cat([bench[k], 0.5 * torch.randn(EXTRA)])
            start_b = frozen.mu.mean(0) + 0.1 * torch.randn(frozen.mu.shape[1])
            for tag, start in (("A bench", start_a), ("B no-bench", start_b)):
                add(f"frozen net + all train prompts [{tag}]",
                    OB.evaluate_identity(frozen, OB.fit_identity(frozen, Et, yk, start), Ev, yv))
                for n in BUDGETS:
                    for how, sel in (("stratified", OB.stratified_select(psi, n, seed=seed, groups=tt)),
                                     ("random", random_select(n, seed, tt))):
                        I = OB.fit_identity(frozen, Et[sel], yk[sel], start)
                        add(f"{n:>2} prompts {how:<10} [{tag}]", OB.evaluate_identity(frozen, I, Ev, yv))
                        if how == "stratified" and n == 50:
                            chk = OB.stratified_select(psi, 10, seed=seed + 1, groups=tt, exclude=sel)
                            ok = OB.worth_trusting(OB.evaluate_identity(frozen, I, Et[chk], yk[chk]),
                                                   yk[chk], float(yk[sel].mean()))
                            add(f"check passed (50, stratified) [{tag}]",
                                {"bce": float(ok), "acc": float(ok), "auc": float(ok)})
            print(f"  {k_name}: seed {seed} done", flush=True)
        results[k_name] = {name: summarise(rows) for name, rows in acc.items()}

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)
    lines = [f"Adding a new arm: frozen network + fitted vector vs full retrain "
             f"({args.seeds} seeds, held-out sessions, mean +- sd)\n"]
    for k_name, table in results.items():
        lines.append(f"NEW ARM = {k_name}   (lower BCE is better; higher acc/AUC is better)")
        lines.append(f"  {'method':<52} {'BCE':>13} {'acc':>13} {'AUC':>13}")
        for name, m in table.items():
            if name.startswith("check"):
                lines.append(f"  {name:<52} passed in {100 * m['bce'][0]:.0f}% of seeds")
                continue
            lines.append(f"  {name:<52} " + " ".join(f"{m[c][0]:6.3f}+-{m[c][1]:5.3f}" for c in ("bce", "acc", "auc")))
        lines.append("")
    text = "\n".join(lines)
    with open(os.path.join(OUT, "summary.txt"), "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)


if __name__ == "__main__":
    main()
