"""
experiment_data/PartC/run/onboarding.py -- add a new arm without retraining (LLM Bandit Sec 2.6).

When a model joins, the network f and the other arms' identities stay frozen and
only the new arm's identity vector is fitted, on a few prompts that tell models
apart best:

    1. psi_n   how badly the EXISTING arms are predicted on prompt n      Eq (7)
    2. pick    stratified over psi, so easy and hard prompts both appear  App B.3.4
    3. run     the new model on those prompts, judge them, binarise       (caller)
    4. fit     I~ = argmin BCE(y, sigmoid(f(e, I))) + KL-style prior      Eq (8)
    5. check   a few prompts the fit never saw                            (not in the paper)

psi depends only on the existing arms and the prompts, so steps 1-2 run ONCE after
Stage 1 and the same set serves every later model.

    Yang Li, "LLM Bandit: Cost-Efficient LLM Generation via
    Preference-Conditioned Dynamic Routing", arXiv:2502.02743
"""
import json
import os

import numpy as np
import torch
import torch.nn.functional as F

_HERE = os.path.dirname(os.path.abspath(__file__))
_OUT_DIR = os.environ.get("HONEYROUTER_OUT") or os.path.join(_HERE, "out")
PROMPTS_FILE = os.path.join(_OUT_DIR, "onboarding_prompts.json")


def discrimination(model, E: torch.Tensor, Y: torch.Tensor) -> np.ndarray:
    """psi_n, Eq (7): mean over existing arms of BCE(p_kn, y_kn). E (N,d), Y (N,K)."""
    model.eval()
    with torch.no_grad():
        logits = model.logits(E, model.sample_identity(train=False))
        bce = F.binary_cross_entropy_with_logits(logits, Y, reduction="none")
    return bce.mean(dim=1).numpy()


def stratified_select(psi, n, n_strata=5, seed=0, groups=None, exclude=()):
    """n row indices spread evenly over equal-count strata of psi.

    groups: one label per row (the command text); a label is used at most once, since
    a repeated command teaches the new vector nothing and spends budget.
    """
    rng = np.random.default_rng(seed)
    psi = np.asarray(psi)
    taken, used = [], set()
    blocked = set(int(i) for i in exclude)
    order = [int(i) for i in np.argsort(psi, kind="stable") if int(i) not in blocked]
    strata = [list(s) for s in np.array_split(np.array(order), n_strata)]
    quota = [n // n_strata] * n_strata
    for s in rng.permutation(n_strata)[: n % n_strata]:
        quota[s] += 1

    def pick(pool, want):
        pool = list(rng.permutation(pool))
        got = []
        for i in pool:
            key = groups[i] if groups is not None else i
            if key in used or i in taken:
                continue
            used.add(key)
            got.append(int(i))
            if len(got) == want:
                break
        return got

    for pool, want in zip(strata, quota):
        taken += pick(pool, want)
    # a stratum with too few distinct prompts leaves a gap: fill it from the rest
    if len(taken) < n:
        rest = [i for s in strata for i in s]
        taken += pick(rest, n - len(taken))
    return np.array(sorted(taken))


def fit_identity(model, E: torch.Tensor, y: torch.Tensor, init: torch.Tensor,
                 prior: torch.Tensor = None, beta: float = None,
                 steps: int = 300, lr: float = 0.05) -> torch.Tensor:
    """Eq (8) for a point identity: only I moves, f and every other arm stay frozen.

    The KL term of a point identity is its pull toward the prior mean (here the
    starting vector); beta = 1/n amortises it over the prompts, as Stage 1 does.
    """
    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)
    prior = init.clone() if prior is None else prior
    beta = 1.0 / len(y) if beta is None else beta
    I = torch.nn.Parameter(init.clone().reshape(1, -1))
    opt = torch.optim.Adam([I], lr=lr)
    for _ in range(steps):
        loss = (F.binary_cross_entropy_with_logits(model.logits(E, I)[:, 0], y)
                + beta * 0.5 * ((I - prior.reshape(1, -1)) ** 2).sum())
        opt.zero_grad()
        loss.backward()
        opt.step()
    return I.detach().reshape(-1)


BETAS = (0.02, 0.1, 0.3, 1.0, 3.0, 10.0)


def fit_identity_cv(model, E, y, init, betas=BETAS, folds=5, seed=0):
    """fit_identity with the pull toward `init` chosen by cross-validation on the
    fit prompts themselves (never on held-out data). With ~50 prompts the default
    beta=1/n lets the vector drift far enough to memorise them; the fold that
    predicts its own held-out prompts best picks how hard to hold it back.
    Returns (vector, chosen beta)."""
    n = len(y)
    order = np.random.default_rng(seed).permutation(n)
    parts = np.array_split(order, min(folds, n))
    best, best_beta = None, betas[0]
    for b in betas:
        loss = 0.0
        for f in parts:
            tr = np.setdiff1d(order, f)
            I = fit_identity(model, E[tr], y[tr], init, beta=b, steps=100)
            lg = model.logits(E[f], I.reshape(1, -1))[:, 0]
            loss += float(F.binary_cross_entropy_with_logits(lg, y[f], reduction="sum"))
        if best is None or loss < best:
            best, best_beta = loss, b
    return fit_identity(model, E, y, init, beta=best_beta), best_beta


def _auc(score: np.ndarray, y: np.ndarray) -> float:
    pos, neg = score[y == 1], score[y == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    ranks = np.argsort(np.argsort(np.concatenate([pos, neg]))) + 1.0
    return float((ranks[: len(pos)].sum() - len(pos) * (len(pos) + 1) / 2)
                 / (len(pos) * len(neg)))


def evaluate_identity(model, I: torch.Tensor, E: torch.Tensor, y: torch.Tensor) -> dict:
    """How well the fitted identity predicts prompts the fit never saw."""
    model.eval()
    with torch.no_grad():
        logits = model.logits(E, I.reshape(1, -1))[:, 0]
        bce = F.binary_cross_entropy_with_logits(logits, y).item()
    yn, p = y.numpy(), torch.sigmoid(logits).numpy()
    return {"bce": bce, "acc": float(((p > 0.5) == (yn > 0.5)).mean()),
            "auc": _auc(p, yn), "n": int(len(yn))}


def worth_trusting(check: dict, y_check: torch.Tensor, train_rate: float) -> bool:
    """Step 5: on the unseen check prompts the fit must beat guessing the fitted success rate."""
    r = min(max(train_rate, 1e-4), 1 - 1e-4)
    y = y_check.numpy()
    constant = float(-(y * np.log(r) + (1 - y) * np.log(1 - r)).mean())
    return bool(check["bce"] < constant)


def select_onboarding_set(model, E, Y, texts, n=50, n_check=10, seed=0, path=PROMPTS_FILE):
    """Steps 1-2 once, plus a few extra prompts for step 5. Saved for reuse."""
    psi = discrimination(model, torch.as_tensor(E), torch.as_tensor(Y))
    fit_idx = stratified_select(psi, n, seed=seed, groups=texts)
    check_idx = stratified_select(psi, n_check, seed=seed + 1, groups=texts, exclude=fit_idx)
    out = {"fit": [texts[i] for i in fit_idx], "check": [texts[i] for i in check_idx],
           "psi_fit": [float(psi[i]) for i in fit_idx], "n": n, "n_check": n_check}
    out["fit_idx"], out["check_idx"] = [int(i) for i in fit_idx], [int(i) for i in check_idx]
    if path:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1, ensure_ascii=False)
    return out
