"""
honeyrouter/predictor.py — Stage 1 of the LLM Bandit.

The network, the per-arm identity vectors, and the IRT objective that fits
them. Everything that turns "a command" into "how well would arm k do on it"
lives here; Stage 3's policy consumes what this file produces and trains
nothing of its own about ability.

    p_kn = sigmoid( f(e_n, I_k) )

    e_n   frozen prompt embedding of command n        (embeddings.py)
    I_k   identity of arm k, a LATENT VARIABLE         (learned here)
    f     small network                                (learned here)

Not classical IRT: there are no per-item difficulty or discrimination
parameters. Difficulty is implicit in e_n, which is what lets the fitted model
say something about a command it has never seen -- nothing is keyed to an
item id.

I_k IS A DISTRIBUTION, NOT A POINT. The paper treats identities variationally
with Gaussian prior p(I_k) and posterior q(I_k), so each arm learns a mean and
a variance. Training samples I_k ~ q; inference uses the mean. The KL term is
what stops three arms with 128 free dimensions from simply memorising 2,179
observations.

THREE LOSSES, all from the paper:

    L_irt   BCE on whether arm k handled command n            (per observation)
    L_pair  BCE on "arm a beat arm b on command n"            (per comparison)
    L_KL    KL( q(I_k) || p(I_k) )                            (regulariser)

THE TARGET IS BINARISED BY THE PAPER'S OWN RULE, not by a threshold anyone
here picked. Judge scores are 1-5; normalised to [0,1] they average 0.641, and
the paper says to "find an optimal threshold eta* so that the average
performance across instances are close to the original scores", giving
Y = 1(y > eta*). On this data eta* = 0.25, i.e. success = judge >= 3.

    Yang Li, "LLM Bandit: Cost-Efficient LLM Generation via
    Preference-Conditioned Dynamic Routing", arXiv:2502.02743

    python honeyrouter/predictor.py --dim 128 --epochs 300
"""
import argparse
import os
import sys

import numpy as np
import torch
import torch.nn as nn

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

from honeyrouter.action import AGENTS                    # noqa: E402
from honeyrouter.embeddings import embed                 # noqa: E402
from honeyrouter.sessions import load_sessions           # noqa: E402

OUT = os.path.join(_HERE, "out", "predictor.npz")


# ── data ────────────────────────────────────────────────────────────────────

def optimal_threshold(scores: np.ndarray) -> float:
    """The paper's eta*: the cut whose success RATE matches the mean score.

    Judge scores are ordinal, so a threshold chosen for interpretability ("4
    and 5 are good") would be ours. This one is chosen by the rule the paper
    states, which makes it a property of the data instead.
    """
    grid = np.linspace(0.0, 1.0, 1001)
    target = scores.mean()
    rates = np.array([(scores > t).mean() for t in grid])
    return float(grid[int(np.argmin(np.abs(rates - target)))])


def build_dataset():
    """(E, Y, raw, sessions) aligned row-for-row with the replay."""
    sess = load_sessions()
    rows = [(sid, c) for sid, cmds in sess.items() for c in cmds]
    table = embed([c["cmd"] for _, c in rows])

    E = np.stack([table[c["cmd"]] for _, c in rows]).astype(np.float32)
    raw = np.array([[c["agents"][a]["judge_score"] for a in AGENTS]
                    for _, c in rows], dtype=np.float32)
    norm = np.clip((raw - 1.0) / 4.0, 0.0, 1.0)
    eta = optimal_threshold(norm.reshape(-1))
    Y = (norm > eta).astype(np.float32)
    sids = np.array([sid for sid, _ in rows])
    return E, Y, raw, sids, eta


def split_by_session(sids: np.ndarray, frac: float = 0.2, seed: int = 0):
    """Hold out whole SESSIONS, never single commands.

    Commands repeat inside a session (1,146 distinct texts across 2,179 rows),
    so a random row split would put the same command in train and test and
    report a score that memorisation alone could reach.
    """
    uniq = np.unique(sids)
    rng = np.random.default_rng(seed)
    rng.shuffle(uniq)
    n_val = max(1, int(len(uniq) * frac))
    val_ids = set(uniq[:n_val].tolist())
    mask = np.array([s in val_ids for s in sids])
    return ~mask, mask


# ── model ───────────────────────────────────────────────────────────────────

class Predictor(nn.Module):
    """f(e, I) with a variational identity per arm."""

    def __init__(self, emb_dim: int, n_arms: int, dim: int = 128,
                 hidden: int = 128):
        super().__init__()
        # q(I_k) = N(mu_k, softplus(rho_k)^2); prior p(I_k) = N(0, I)
        self.mu = nn.Parameter(torch.randn(n_arms, dim) * 0.1)
        self.rho = nn.Parameter(torch.full((n_arms, dim), -3.0))
        self.f = nn.Sequential(
            nn.Linear(emb_dim + dim, hidden), nn.ReLU(),
            nn.Linear(hidden, hidden), nn.ReLU(),
            nn.Linear(hidden, 1),
        )

    def sigma(self):
        return torch.nn.functional.softplus(self.rho)

    def sample_identity(self, train: bool = True):
        if not train:
            return self.mu
        return self.mu + self.sigma() * torch.randn_like(self.mu)

    def logits(self, E: torch.Tensor, I: torch.Tensor) -> torch.Tensor:
        """(N, n_arms) logits: every command against every arm."""
        n, k = E.shape[0], I.shape[0]
        e = E.unsqueeze(1).expand(n, k, E.shape[1])
        i = I.unsqueeze(0).expand(n, k, I.shape[1])
        return self.f(torch.cat([e, i], dim=-1)).squeeze(-1)

    def kl(self) -> torch.Tensor:
        """KL( N(mu, sigma) || N(0, 1) ), summed over dims, mean over arms."""
        s = self.sigma()
        return (0.5 * (s ** 2 + self.mu ** 2 - 1.0 - 2.0 * torch.log(s))
                ).sum(dim=1).mean()


def pairwise_loss(logits: torch.Tensor, raw: torch.Tensor) -> torch.Tensor:
    """BCE on 'arm a scored higher than arm b on this command'.

    Ties carry no preference and are dropped rather than being taught as 0.5 --
    1,403 of 2,179 commands have at least two arms level, so labelling those
    either way would drown the real comparisons.
    """
    n_arms = logits.shape[1]
    terms = []
    for a in range(n_arms):
        for b in range(a + 1, n_arms):
            keep = raw[:, a] != raw[:, b]
            if keep.sum() == 0:
                continue
            z = (raw[keep, a] > raw[keep, b]).float()
            d = logits[keep, a] - logits[keep, b]
            terms.append(nn.functional.binary_cross_entropy_with_logits(d, z))
    return torch.stack(terms).mean() if terms else logits.sum() * 0.0


# ── training ────────────────────────────────────────────────────────────────

def train(dim=128, epochs=300, lr=1e-3, w_pair=1.0, w_kl=1e-3, seed=0,
          verbose=True):
    torch.manual_seed(seed)
    E, Y, raw, sids, eta = build_dataset()
    tr, va = split_by_session(sids, seed=seed)

    Et, Yt, Rt = (torch.tensor(x[tr]) for x in (E, Y, raw))
    Ev, Yv, Rv = (torch.tensor(x[va]) for x in (E, Y, raw))

    model = Predictor(E.shape[1], len(AGENTS), dim=dim)
    opt = torch.optim.Adam(model.parameters(), lr=lr)

    if verbose:
        # strict >, so the lowest PASSING judge score is the next one up
        print(f"[irt] eta*={eta:.3f} (success = judge >= {eta * 4 + 2:.0f})  "
              f"train={tr.sum()} val={va.sum()} rows, dim={dim}")

    for ep in range(1, epochs + 1):
        model.train()
        I = model.sample_identity(train=True)
        logits = model.logits(Et, I)
        l_irt = nn.functional.binary_cross_entropy_with_logits(logits, Yt)
        l_pair = pairwise_loss(logits, Rt)
        l_kl = model.kl()
        loss = l_irt + w_pair * l_pair + w_kl * l_kl

        opt.zero_grad(); loss.backward(); opt.step()

        if verbose and (ep % 50 == 0 or ep == 1):
            model.eval()
            with torch.no_grad():
                lv = model.logits(Ev, model.sample_identity(train=False))
                acc = ((lv > 0).float() == Yv).float().mean().item()
                pair_acc = _pair_accuracy(lv, Rv)
            print(f"  ep{ep:>4}  irt={l_irt:.4f} pair={l_pair:.4f} "
                  f"kl={l_kl:.1f} | val acc={acc:.3f} pairwise={pair_acc:.3f}")
    # Majority-class and coin-flip baselines, or 0.83 means nothing: an arm
    # that succeeds 79% of the time is 79% accurate by answering "yes" always.
    maj = max(Yv.mean().item(), 1 - Yv.mean().item())
    if verbose:
        print(f"  baseline: always-majority acc={maj:.3f}, "
              f"pairwise coin-flip=0.500")

    model.eval()
    with torch.no_grad():
        mu = model.mu.detach().numpy()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    np.savez(OUT, identity=mu, sigma=model.sigma().detach().numpy(),
             agents=np.array(AGENTS), eta=eta, dim=dim)
    if verbose:
        print(f"[stage1] saved identity vectors -> {OUT}")
    return model, (E, Y, raw, sids, eta), (tr, va)


def _pair_accuracy(logits: torch.Tensor, raw: torch.Tensor) -> float:
    """How often the model orders two arms the way the judge did."""
    ok = tot = 0
    for a in range(logits.shape[1]):
        for b in range(a + 1, logits.shape[1]):
            keep = raw[:, a] != raw[:, b]
            if keep.sum() == 0:
                continue
            z = (raw[keep, a] > raw[keep, b])
            pred = (logits[keep, a] > logits[keep, b])
            ok += (pred == z).sum().item()
            tot += int(keep.sum())
    return ok / tot if tot else float("nan")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dim", type=int, default=128)
    ap.add_argument("--epochs", type=int, default=300)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--w-pair", type=float, default=1.0)
    ap.add_argument("--w-kl", type=float, default=1e-3)
    a = ap.parse_args()
    model, data, _ = train(dim=a.dim, epochs=a.epochs, lr=a.lr,
                           w_pair=a.w_pair, w_kl=a.w_kl)
    E, Y, raw, sids, eta = data
    with torch.no_grad():
        I = model.mu
        print("\n=== learned identities ===")
        for k, name in enumerate(AGENTS):
            print(f"  {name:10} |mu|={I[k].norm():.3f}  "
                  f"mean sigma={model.sigma()[k].mean():.4f}")
        logits = model.logits(torch.tensor(E), I)
        p = torch.sigmoid(logits).numpy()
        print("\n=== predicted vs observed success rate (all rows) ===")
        for k, name in enumerate(AGENTS):
            print(f"  {name:10} predicted {p[:, k].mean():.1%}   "
                  f"observed {Y[:, k].mean():.1%}")


if __name__ == "__main__":
    main()
