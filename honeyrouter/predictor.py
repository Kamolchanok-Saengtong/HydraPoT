"""
honeyrouter/predictor.py — Stage 1 of the LLM Bandit ("the IRT model").

Learns a per-arm identity vector and a network so that, for any command,
    p_kn = sigmoid( f(e_n, I_k) )
predicts whether arm k would handle command n well. Stage 3's policy consumes
what this file produces and trains nothing of its own about ability.

    e_n   frozen prompt embedding of command n        (embeddings.py)
    I_k   identity of arm k, a LATENT VARIABLE         (learned here)
    f     success head    on concat[e_n, I_k]          (learned here)
    g     pairwise head   on concat[e_n, I_k]          (learned here)

This follows the FULL method the paper describes in Sec 2.3, using every
objective it states:

    L_irt   BCE, does arm k handle command n            Eq (2)   via f
    L_pair  BCE, does arm a beat arm b on command n     Eq (3)   via g
    L_KL    KL( q(I_k) || p(I_k) ), variational reg.    Eq (4)

f and g SHARE A COMMON BACKBONE and differ only in their final linear layer
(App E.3), so the identity vector is pushed to capture both "how good" and
"who wins". Identity is variational (App B.1): q(I_k)=N(mu_k, diag Sigma_k),
prior p(I_k)=N(0,I); training samples I_k = mu_k + sigma_k*eps, inference uses
mu_k. L_irt + L_KL together are the negative ELBO of Eq (B.1).

PAIRWISE DATA. The paper's g is trained on external human-preference sets; ours
comes from the replay itself -- every command really was run through all three
arms and judge-scored, so each command yields real (arm_a vs arm_b) labels
z = 1[score_a > score_b]. Ties (equal judge scores) carry no preference and are
dropped.

KL WEIGHTING. The ELBO pays the KL ONCE PER ARM but averages L_irt over every
row, so on this small data (3 arms x ~1,780 rows) an unscaled KL (~300) would
crush the BCE (~0.5). The faithful per-observation ELBO amortises the per-arm
KL over the N training rows it regularises, i.e. beta = 1/N. That is the
default; --w-kl overrides it.

THE TARGET IS BINARISED BY THE PAPER'S OWN RULE (Eq B.2): judge scores 1-5,
normalised to [0,1] and thresholded at eta* so the success rate matches the
mean score. On this data eta* = 0.25 (judge >= 3).

OPTIMISER (App E.3): Adam, lr 0.001, lr x0.95 after each epoch, batch 256,
10 epochs. AFTER TRAINING (Sec 2.6) f, g and every I_k are frozen -- load()
returns a frozen model.

    Yang Li, "LLM Bandit: Cost-Efficient LLM Generation via
    Preference-Conditioned Dynamic Routing", arXiv:2502.02743

    python honeyrouter/predictor.py --dim 128 --epochs 10 --batch 256
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

OUT = os.path.join(_HERE, "out", "predictor.npz")   # mu + sigma, for inspection
CKPT = os.path.join(_HERE, "out", "predictor.pt")   # full model, for inference


# ── data ────────────────────────────────────────────────────────────────────

def optimal_threshold(scores: np.ndarray) -> float:
    """The paper's eta* (Eq B.2): the cut whose success RATE matches the mean.

    Judge scores are ordinal, so a threshold chosen for interpretability ("4
    and 5 are good") would be ours. This one is chosen by the rule the paper
    states, which makes it a property of the data instead.
    """
    grid = np.linspace(0.0, 1.0, 1001)
    target = scores.mean()
    rates = np.array([(scores > t).mean() for t in grid])
    return float(grid[int(np.argmin(np.abs(rates - target)))])


def build_dataset():
    """(E, Y, raw, sids, eta) aligned row-for-row with the replay.

    raw keeps the real 1-5 judge score per arm -- L_pair reads it to decide
    which arm won each command; Y is the binarised target for L_irt.
    """
    sess = load_sessions()
    rows = [(sid, c) for sid, cmds in sess.items() for c in cmds]
    table = embed([c["cmd"] for _, c in rows])

    E = np.stack([table[c["cmd"]] for _, c in rows]).astype(np.float32)
    raw = np.array([[c["agents"][a]["judge_score"] for a in AGENTS]
                    for _, c in rows], dtype=np.float32)
    norm = np.clip((raw - 1.0) / 4.0, 0.0, 1.0)      # judge 1-5 -> [0,1]
    eta = optimal_threshold(norm.reshape(-1))
    Y = (norm > eta).astype(np.float32)              # y_bar_kn, Eq B.2
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
    """Variational identity per arm + two heads over a shared backbone.

    q(I_k) = N(mu_k, diag sigma_k^2),  prior p(I_k) = N(0, I),  dim d.
    f  Eq (2) success head:  p_kn = sigmoid(f(e, I_k))
    g  Eq (3) pairwise head: p_n  = sigmoid(g(e, I_a) - g(e, I_b))

    f and g share the backbone and differ only in their final linear layer
    (App E.3), so one identity vector serves both objectives.
    """

    def __init__(self, emb_dim: int, n_arms: int, dim: int = 128,
                 hidden: int = 128):
        super().__init__()
        # Posterior q(I_k) = N(mu_k, softplus(rho_k)^2); prior p(I_k) = N(0, I).
        # rho init -3 => sigma ~ 0.049, a tight start the KL pulls toward 1.
        self.mu = nn.Parameter(torch.randn(n_arms, dim) * 0.1)
        self.rho = nn.Parameter(torch.full((n_arms, dim), -3.0))

        self.backbone = nn.Sequential(
            nn.Linear(emb_dim + dim, hidden), nn.ReLU(),
            nn.Linear(hidden, hidden), nn.ReLU(),
        )
        self.f_head = nn.Linear(hidden, 1)   # Eq (2): does arm k handle cmd n?
        self.g_head = nn.Linear(hidden, 1)   # Eq (3): does arm a beat arm b?

    def sigma(self) -> torch.Tensor:
        return torch.nn.functional.softplus(self.rho)

    def sample_identity(self, train: bool = True) -> torch.Tensor:
        """I_k = mu_k + sigma_k * eps while training; mu_k at inference."""
        if not train:
            return self.mu
        return self.mu + self.sigma() * torch.randn_like(self.mu)

    def _score(self, head: nn.Module, E: torch.Tensor,
               I: torch.Tensor) -> torch.Tensor:
        """(N, n_arms): shared backbone then `head`, every command x every arm."""
        n, k = E.shape[0], I.shape[0]
        e = E.unsqueeze(1).expand(n, k, E.shape[1])
        i = I.unsqueeze(0).expand(n, k, I.shape[1])
        h = self.backbone(torch.cat([e, i], dim=-1))
        return head(h).squeeze(-1)

    def logits(self, E: torch.Tensor, I: torch.Tensor) -> torch.Tensor:
        """(N, n_arms) success logits from f -- Eq (2)."""
        return self._score(self.f_head, E, I)

    def pair_logits(self, E: torch.Tensor, I: torch.Tensor) -> torch.Tensor:
        """(N, n_arms) ranking logits from g; differenced pairwise -- Eq (3)."""
        return self._score(self.g_head, E, I)

    def kl(self) -> torch.Tensor:
        """L_KL = mean_k KL( N(mu_k, sigma_k) || N(0, 1) )  -- Eq (4).

        KL summed over the d dims of an arm, then averaged over arms.
        """
        s = self.sigma()
        return (0.5 * (s ** 2 + self.mu ** 2 - 1.0 - 2.0 * torch.log(s))
                ).sum(dim=1).mean()


def pairwise_loss(g_logits: torch.Tensor, raw: torch.Tensor) -> torch.Tensor:
    """Eq (3): BCE on 'arm a scored higher than arm b on this command'.

    `g_logits` are the pairwise head's outputs (model.pair_logits). The winner
    probability is sigmoid(g(e,I_a) - g(e,I_b)), which is exactly this
    differenced BCE. Ties (equal judge scores) are dropped, not taught as 0.5.
    """
    n_arms = g_logits.shape[1]
    terms = []
    for a in range(n_arms):
        for b in range(a + 1, n_arms):
            keep = raw[:, a] != raw[:, b]
            if keep.sum() == 0:
                continue
            z = (raw[keep, a] > raw[keep, b]).float()
            d = g_logits[keep, a] - g_logits[keep, b]
            terms.append(nn.functional.binary_cross_entropy_with_logits(d, z))
    return torch.stack(terms).mean() if terms else g_logits.sum() * 0.0


# ── training ──────────────────────────────────────────────────────────────────

def train(dim=128, epochs=10, lr=1e-3, batch=256, lr_decay=0.95,
          w_pair=1.0, w_kl=None, seed=0, verbose=True):
    """Fit the variational IRT model: minimise L_irt + w_pair*L_pair + beta*L_KL.

    w_kl None -> beta = 1/N (faithful ELBO amortisation, see module docstring).
    Optimiser is App E.3: Adam 1e-3, lr x0.95/epoch, batch 256, 10 epochs.
    """
    torch.manual_seed(seed)
    E, Y, raw, sids, eta = build_dataset()
    tr, va = split_by_session(sids, seed=seed)

    Et, Yt, Rt = (torch.tensor(x[tr]) for x in (E, Y, raw))
    Ev, Yv, Rv = (torch.tensor(x[va]) for x in (E, Y, raw))

    model = Predictor(E.shape[1], len(AGENTS), dim=dim)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    sched = torch.optim.lr_scheduler.ExponentialLR(opt, gamma=lr_decay)

    n_tr = Et.shape[0]
    beta = (1.0 / n_tr) if w_kl is None else w_kl     # ELBO KL amortisation
    rng = np.random.default_rng(seed)

    if verbose:
        print(f"[irt] eta*={eta:.3f} (success = judge >= {eta * 4 + 2:.0f})  "
              f"train={n_tr} val={int(va.sum())} rows, dim={dim}, "
              f"batch={batch}, epochs={epochs}, beta(KL)={beta:.2e}")

    for ep in range(1, epochs + 1):
        model.train()
        order = rng.permutation(n_tr)
        last = {"irt": 0.0, "pair": 0.0, "kl": 0.0}
        for s in range(0, n_tr, batch):
            idx = torch.as_tensor(order[s:s + batch])
            I = model.sample_identity(train=True)              # reparam sample
            l_irt = nn.functional.binary_cross_entropy_with_logits(
                model.logits(Et[idx], I), Yt[idx])
            l_pair = pairwise_loss(model.pair_logits(Et[idx], I), Rt[idx])
            l_kl = model.kl()
            loss = l_irt + w_pair * l_pair + beta * l_kl       # Sec 2.3, all 3
            opt.zero_grad(); loss.backward(); opt.step()
            last = {"irt": l_irt.item(), "pair": l_pair.item(), "kl": l_kl.item()}
        sched.step()

        if verbose:
            model.eval()
            with torch.no_grad():
                Iv = model.sample_identity(train=False)
                lv = model.logits(Ev, Iv)                       # f: success
                gv = model.pair_logits(Ev, Iv)                  # g: pairwise
                acc = ((lv > 0).float() == Yv).float().mean().item()
                pair_acc = _pair_accuracy(gv, Rv)
            print(f"  ep{ep:>3}  irt={last['irt']:.4f} pair={last['pair']:.4f} "
                  f"kl={last['kl']:.1f} lr={sched.get_last_lr()[0]:.2e} | "
                  f"val acc={acc:.3f} pairwise={pair_acc:.3f}")

    # Baselines, or 0.72 means nothing: an arm that succeeds 66% of the time is
    # 66% accurate by answering "yes" always; pairwise coin-flip is 0.5.
    maj = max(Yv.mean().item(), 1 - Yv.mean().item())
    if verbose:
        print(f"  baseline: always-majority acc={maj:.3f}, "
              f"pairwise coin-flip=0.500")

    # Sec 2.6: after training, freeze f, g and every I_k.
    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)

    with torch.no_grad():
        mu = model.mu.detach().numpy()
        sig = model.sigma().detach().numpy()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    np.savez(OUT, identity=mu, sigma=sig, agents=np.array(AGENTS),
             eta=eta, dim=dim)
    torch.save({"state_dict": model.state_dict(),
                "emb_dim": int(E.shape[1]), "dim": int(dim),
                "agents": list(AGENTS), "eta": float(eta),
                "beta": float(beta)}, CKPT)
    if verbose:
        print(f"[stage1] saved mu + sigma  -> {OUT}")
        print(f"[stage1] saved full model  -> {CKPT}  (frozen)")
    return model, (E, Y, raw, sids, eta), (tr, va)


def _pair_accuracy(g_logits: torch.Tensor, raw: torch.Tensor) -> float:
    """How often the g head orders two arms the way the judge did."""
    ok = tot = 0
    for a in range(g_logits.shape[1]):
        for b in range(a + 1, g_logits.shape[1]):
            keep = raw[:, a] != raw[:, b]
            if keep.sum() == 0:
                continue
            z = (raw[keep, a] > raw[keep, b])
            pred = (g_logits[keep, a] > g_logits[keep, b])
            ok += (pred == z).sum().item()
            tot += int(keep.sum())
    return ok / tot if tot else float("nan")


# ── inference (what Stage 3 consumes) ─────────────────────────────────────────

def load(path: str = CKPT):
    """Rebuild the trained predictor, FROZEN (Sec 2.6). Returns (model, meta)."""
    ckpt = torch.load(path, map_location="cpu", weights_only=False)
    model = Predictor(ckpt["emb_dim"], len(ckpt["agents"]), dim=ckpt["dim"])
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)
    return model, ckpt


def predict(model: "Predictor", commands) -> np.ndarray:
    """(N, n_arms) success probability p_kn = sigmoid(f(e_n, I_k)) -- Eq (2).

    Inference uses the posterior MEAN mu_k (not a sample). Commands are raw
    strings, embedded with the same frozen encoder used in training, so this
    works on commands never seen at fit time.
    """
    table = embed(list(commands))
    E = np.stack([table[c] for c in commands]).astype(np.float32)
    with torch.no_grad():
        logits = model.logits(torch.tensor(E), model.sample_identity(train=False))
        return torch.sigmoid(logits).numpy()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dim", type=int, default=128)
    ap.add_argument("--epochs", type=int, default=10)      # E.3
    ap.add_argument("--lr", type=float, default=1e-3)      # E.3
    ap.add_argument("--batch", type=int, default=256)      # E.3
    ap.add_argument("--lr-decay", type=float, default=0.95)  # E.3
    ap.add_argument("--w-pair", type=float, default=1.0)
    ap.add_argument("--w-kl", type=float, default=None,
                    help="KL weight beta; default 1/N (ELBO amortisation)")
    a = ap.parse_args()
    model, data, _ = train(dim=a.dim, epochs=a.epochs, lr=a.lr, batch=a.batch,
                           lr_decay=a.lr_decay, w_pair=a.w_pair, w_kl=a.w_kl)
    E, Y, raw, sids, eta = data
    with torch.no_grad():
        mu = model.mu
        print("\n=== learned identities ===")
        for k, name in enumerate(AGENTS):
            print(f"  {name:10} |mu|={mu[k].norm():.3f}  "
                  f"mean sigma={model.sigma()[k].mean():.4f}")
        logits = model.logits(torch.tensor(E), mu)
        p = torch.sigmoid(logits).numpy()
        print("\n=== predicted vs observed success rate (all rows) ===")
        for k, name in enumerate(AGENTS):
            print(f"  {name:10} predicted {p[:, k].mean():.1%}   "
                  f"observed {Y[:, k].mean():.1%}")


if __name__ == "__main__":
    main()
