"""
honeyrouter/routing_policy.py — Stage 2 of the LLM Bandit: SUPERVISED
PRETRAINING of the preference-conditioned routing policy (Algorithm 1, lines
1-10; App B.3.1; App E.4).

This is ONLY the supervised pretraining stage. The RL stage (Algorithm 1 lines
11-21: on-manifold mixup, the value network, multi-objective PPO) is Stage 3
and lives elsewhere -- nothing here trains with reward or a replay buffer.

WHAT PRETRAINING DOES. It teaches the policy to imitate the scalarised-optimal
choice. For a prompt and a preference omega, the "right" arm is the one that
maximises omega^T [score, -cost]; the policy is trained by cross-entropy to put
its mass on that arm. Doing this over many sampled preferences is what makes a
single network able to route differently as the user dials cost-vs-fidelity.

    k in {cowrie, on_device, cloud}

PIPELINE (Algorithm 1, lines 3-9), per your Phase-2 spec:

    1. Data      one command per row, ALL THREE arms scored      Alg1 L3*
    2. Pref      omega = [1, w], w ~ U(0, 2)                      Alg1 L4, B.3.3
    3. Score     p_hat_k = sigmoid(f(x, I_k))                     Alg1 L5
    4. Calibrate p_bar_k = sigmoid(a*f(x,I_k) + b)                Alg1 L6, B.3.1 (Platt)
    5. Normalise p_bar/=max p_bar,  c_bar=c/max c                 Alg1 L7, Eq B.7
    6. Target    a_hat = argmax_k omega^T[p_bar_k,-c_bar_k]  (over 3)  Alg1 L8
    7. Context   C = {(I_k, c_bar_k, p_hat_k)}, k in ALL 3 arms   Alg1 L9*
    8. Policy    pi(k'|x,C,omega) = softmax_k' I_k'^T h  (over 3) Eq 5, B.3
    9. Net h     SetTransformer(C) ++ prompt-emb ++ proj(omega) -> R^d   B.2
   10. Loss      L_pretrain = -log pi(a_hat | x, C, omega)        Eq B.4
   11. Settings  500 steps, batch 1024, Adam lr 1e-3             E.4

* ADAPTATION: the paper pretrains PAIRWISE (context/action over {k1,k2}) only
  because its human-preference data provides 2-model comparisons. We ran every
  command through all three arms and judge-scored each, so we build the context
  and the target action over ALL THREE arms -- matching the 3-arm set the policy
  faces at inference. Calibration a,b is still FIT on the pairwise winner labels
  (that is what Platt scaling needs, B.3.1); only the policy's context/action is
  3-way.

TWO THINGS THAT ARE EASY TO GET WRONG (both from the paper):

  * The TARGET action is computed with the CALIBRATED, normalised scores, but
    the policy's INPUT context carries the ORIGINAL p_hat_k, not p_bar_k. B.3.1:
    "the policy utilizes the original predicted scores p_hat as input ... to
    maintain consistency with the subsequent RL training stage."

  * I_k are FROZEN (Stage 1 output, Sec 2.6). The policy trains h only; the
    identity vectors appear in the context and in the final dot-product but
    receive no gradient.

OUR PAIRWISE DATA. The paper draws V from human-preference datasets; ours is
the replay -- every command ran through all three arms and was judge-scored, so
each command yields real (arm_a vs arm_b) winner labels. Cost is the measured
$/command per arm (cloud is billed; cowrie/on_device are ~0), matching
reward.py's cost term.

    Yang Li, "LLM Bandit: Cost-Efficient LLM Generation via
    Preference-Conditioned Dynamic Routing", arXiv:2502.02743

    python honeyrouter/routing_policy.py --steps 500 --batch 1024
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
from honeyrouter import predictor as P                   # noqa: E402

OUT = os.path.join(_HERE, "out", "routing_policy.pt")


# ── data: the pairwise comparison set V ───────────────────────────────────────

def build_pairwise_dataset(seed: int = 0):
    """Build V from the replay.

    Returns per-COMMAND arrays (aligned with the Stage-1 predictor's rows) plus
    a flat list of PAIRS. A pair is (row, k1, k2, z) with z=1 iff arm k1 scored
    strictly higher than arm k2 (ties dropped -- they carry no preference).

        E     (N, emb)   frozen prompt embedding per command
        score (N, K)     judge score 1-5 per arm (0 if the judge failed)
        cost  (N, K)     $/command per arm
        sids  (N,)       session id per command (for the held-out split)
        pairs (M, 4)     [row, k1, k2, z]
    """
    sess = load_sessions()
    rows = [(sid, c) for sid, cmds in sess.items() for c in cmds]
    table = embed([c["cmd"] for _, c in rows])

    E = np.stack([table[c["cmd"]] for _, c in rows]).astype(np.float32)
    score = np.array([[c["agents"][a]["judge_score"] for a in AGENTS]
                      for _, c in rows], dtype=np.float32)
    cost = np.array([[c["agents"][a]["cost_usd"] for a in AGENTS]
                     for _, c in rows], dtype=np.float32)
    sids = np.array([sid for sid, _ in rows])

    K = len(AGENTS)
    pairs = []
    for n in range(len(rows)):
        for a in range(K):
            for b in range(a + 1, K):
                if score[n, a] == score[n, b]:
                    continue                      # tie -> no winner label
                z = 1 if score[n, a] > score[n, b] else 0
                pairs.append((n, a, b, z))
    pairs = np.array(pairs, dtype=np.int64)
    return E, score, cost, sids, pairs


# ── calibration: Platt scaling of the Stage-1 scores (B.3.1) ──────────────────

def fit_calibration(f_logits: np.ndarray, pairs: np.ndarray,
                    iters: int = 500, lr: float = 0.05):
    """Fit a, b so that p(k1 beats k2) = sigmoid(a*(f_k1 - f_k2) + b).

    This is Platt scaling (B.3.1): a 1-feature logistic regression of the winner
    label z on the score-predictor's logit difference. `f_logits` is (N, K), the
    predictor's f(x, I_k) BEFORE the sigmoid. Returns (a, b) as python floats.
    """
    row, k1, k2, z = (torch.as_tensor(pairs[:, i]) for i in range(4))
    fl = torch.as_tensor(f_logits)
    d = fl[row, k1] - fl[row, k2]                  # logit difference
    zt = z.float()

    a = torch.zeros(1, requires_grad=True)
    b = torch.zeros(1, requires_grad=True)
    opt = torch.optim.Adam([a, b], lr=lr)
    for _ in range(iters):
        p = a * d + b
        loss = nn.functional.binary_cross_entropy_with_logits(p, zt)
        opt.zero_grad(); loss.backward(); opt.step()
    return float(a.detach()), float(b.detach())


# ── policy network h (B.2): a SetTransformer over the context ─────────────────

class SAB(nn.Module):
    """Set Attention Block (Lee et al. 2019): self-attention over set elements,
    the permutation-equivariant core of a SetTransformer."""

    def __init__(self, dim: int, heads: int = 4):
        super().__init__()
        self.mha = nn.MultiheadAttention(dim, heads, batch_first=True)
        self.ln1 = nn.LayerNorm(dim)
        self.ff = nn.Sequential(nn.Linear(dim, dim), nn.ReLU(),
                                nn.Linear(dim, dim))
        self.ln2 = nn.LayerNorm(dim)

    def forward(self, x):                          # x: (B, S, dim)
        a, _ = self.mha(x, x, x)
        x = self.ln1(x + a)
        return self.ln2(x + self.ff(x))


class PMA(nn.Module):
    """Pooling by Multihead Attention (Lee et al. 2019): one learnable seed
    attends over the set, giving a permutation-INVARIANT set vector."""

    def __init__(self, dim: int, heads: int = 4):
        super().__init__()
        self.seed = nn.Parameter(torch.randn(1, 1, dim))
        self.mha = nn.MultiheadAttention(dim, heads, batch_first=True)
        self.ln = nn.LayerNorm(dim)

    def forward(self, x):                           # (B, S, dim) -> (B, dim)
        q = self.seed.expand(x.shape[0], 1, x.shape[-1])
        a, _ = self.mha(q, x, x)
        return self.ln(q + a).squeeze(1)


class RoutingPolicy(nn.Module):
    """pi(k'|x, C, omega) = softmax_k' ( I_k'^T h(x, C, omega) )  -- Eq (5)/(B.3).

    h reads the context set C = {(I_k, c_bar_k, p_hat_k)} with a SetTransformer
    (SAB + PMA), concatenates the pooled set vector with the prompt embedding and
    a linear projection of omega, and maps to R^d (B.2). Identities I_k are
    frozen inputs; only h is trained.
    """

    def __init__(self, emb_dim: int, id_dim: int, hidden: int = 128):
        super().__init__()
        self.id_dim = id_dim
        # each context element is [I_k (id_dim), c_bar_k (1), p_hat_k (1)]
        self.elem = nn.Linear(id_dim + 2, hidden)
        self.sab = SAB(hidden)
        self.pma = PMA(hidden)
        self.prompt = nn.Linear(emb_dim, hidden)
        self.pref = nn.Linear(2, hidden)           # omega = [1, w] is 2-dim
        self.head = nn.Sequential(
            nn.Linear(hidden * 3, hidden), nn.ReLU(),
            nn.Linear(hidden, id_dim),             # h in R^d
        )

    def h(self, e, I_ctx, c_ctx, p_ctx, omega):
        """e:(B,emb)  I_ctx:(B,S,id)  c_ctx,p_ctx:(B,S,1)  omega:(B,2) -> (B,id)."""
        x = self.elem(torch.cat([I_ctx, c_ctx, p_ctx], dim=-1))   # (B,S,hidden)
        x = self.sab(x)
        s = self.pma(x)                                           # (B,hidden)
        z = torch.cat([s, self.prompt(e), self.pref(omega)], dim=-1)
        return self.head(z)                                       # (B,id)

    def logits(self, e, I_ctx, c_ctx, p_ctx, omega):
        """(B, S) routing logits: I_k'^T h for each candidate in the set."""
        h = self.h(e, I_ctx, c_ctx, p_ctx, omega)                # (B,id)
        return (I_ctx * h.unsqueeze(1)).sum(dim=-1)              # (B,S)


# ── pretraining (Algorithm 1, lines 2-10) ─────────────────────────────────────

def pretrain(steps=500, batch=1024, lr=1e-3, w_min=0.0, w_max=2.0,
             seed=0, verbose=True):
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)

    # Frozen Stage-1 predictor: identities I_k = mu, and f(x, I_k).
    model, meta = P.load()
    E, score, cost, sids, pairs = build_pairwise_dataset(seed=seed)
    I = model.mu.detach()                                        # (K, id) frozen
    with torch.no_grad():
        f_logits = model.logits(torch.tensor(E), I).numpy()      # (N, K)

    # Platt calibration on the winner labels (B.3.1). Calibration is fit on the
    # PAIRWISE winner labels -- that is what Platt scaling needs -- even though
    # the policy below trains over the full 3-model context.
    a_cal, b_cal = fit_calibration(f_logits, pairs)

    # Hold out whole sessions, same rule as Stage 1, to report generalisation.
    # Split is over COMMANDS (rows) now, since the policy is trained per command.
    tr_mask, va_mask = P.split_by_session(sids, seed=seed)
    tr_rows = np.where(tr_mask)[0]
    va_rows = np.where(va_mask)[0]

    K = len(AGENTS)
    Et = torch.tensor(E)
    fl = torch.tensor(f_logits)
    p_hat = torch.sigmoid(fl)                                    # (N,K) original
    p_bar_all = torch.sigmoid(a_cal * fl + b_cal)               # (N,K) calibrated
    cost_t = torch.tensor(cost)

    policy = RoutingPolicy(emb_dim=E.shape[1], id_dim=I.shape[1])
    opt = torch.optim.Adam(policy.parameters(), lr=lr)

    if verbose:
        print(f"[pretrain] rows train={len(tr_rows)} val={len(va_rows)}  "
              f"K={K} arms  calib a={a_cal:.3f} b={b_cal:.3f}  "
              f"steps={steps} batch={batch} omega~U[{w_min},{w_max}]")

    def normed(x):                                              # Eq (B.7): x/max_k x
        return x / x.max(dim=1, keepdim=True).values.clamp_min(1e-8)

    def make_batch(pool):
        row = torch.as_tensor(pool[rng.integers(0, len(pool), size=batch)])
        w = torch.tensor(rng.uniform(w_min, w_max, size=batch),
                         dtype=torch.float32)
        omega = torch.stack([torch.ones_like(w), w], dim=1)      # [1, w]

        # Context over ALL THREE arms: C_K = {(I_k, c_bar_k, p_hat_k)}.
        I_ctx = I.unsqueeze(0).expand(batch, K, I.shape[1])      # (B,K,id)
        c_bar = normed(cost_t[row])                             # (B,K)
        c_ctx = c_bar.unsqueeze(-1)                             # (B,K,1)
        p_ctx = p_hat[row].unsqueeze(-1)                        # (B,K,1) ORIGINAL

        # target action over K arms: argmax omega^T[p_bar, -c_bar], calibrated.
        pb = normed(p_bar_all[row])                            # (B,K) calibrated
        scalar = pb - w.unsqueeze(1) * c_bar                   # omega^T[p,-c]
        a_hat = scalar.argmax(dim=1)                           # (B,) in {0..K-1}
        return Et[row], I_ctx, c_ctx, p_ctx, omega, a_hat

    def evaluate(pool):
        policy.eval()
        with torch.no_grad():
            e, I_ctx, c_ctx, p_ctx, omega, a_hat = make_batch(pool)
            lg = policy.logits(e, I_ctx, c_ctx, p_ctx, omega)
            loss = nn.functional.cross_entropy(lg, a_hat)
            acc = (lg.argmax(1) == a_hat).float().mean().item()
        policy.train()
        return loss.item(), acc

    for step in range(1, steps + 1):
        policy.train()
        e, I_ctx, c_ctx, p_ctx, omega, a_hat = make_batch(tr_rows)
        lg = policy.logits(e, I_ctx, c_ctx, p_ctx, omega)
        loss = nn.functional.cross_entropy(lg, a_hat)           # -log pi(a_hat)
        opt.zero_grad(); loss.backward(); opt.step()

        if verbose and (step % 100 == 0 or step == 1):
            vl, va_acc = evaluate(va_rows)
            print(f"  step{step:>4}  train -logpi={loss.item():.4f}  "
                  f"| val -logpi={vl:.4f} action-match={va_acc:.3f}")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    torch.save({"state_dict": policy.state_dict(),
                "emb_dim": int(E.shape[1]), "id_dim": int(I.shape[1]),
                "agents": list(AGENTS), "alpha": a_cal, "beta": b_cal,
                "w_range": [w_min, w_max]}, OUT)
    if verbose:
        print(f"[stage2] saved pretrained policy -> {OUT}")
    return policy, {"alpha": a_cal, "beta": b_cal}


# ── inference helper (used by Stage 3 / evaluation) ───────────────────────────

def load_policy(path: str = OUT):
    """Rebuild the pretrained policy. Returns (policy, meta)."""
    ckpt = torch.load(path, map_location="cpu", weights_only=False)
    policy = RoutingPolicy(ckpt["emb_dim"], ckpt["id_dim"])
    policy.load_state_dict(ckpt["state_dict"])
    policy.eval()
    return policy, ckpt


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--steps", type=int, default=500)     # E.4
    ap.add_argument("--batch", type=int, default=1024)    # E.4
    ap.add_argument("--lr", type=float, default=1e-3)     # E.4
    ap.add_argument("--w-min", type=float, default=0.0)   # B.3.3
    ap.add_argument("--w-max", type=float, default=2.0)   # B.3.3
    a = ap.parse_args()
    pretrain(steps=a.steps, batch=a.batch, lr=a.lr,
             w_min=a.w_min, w_max=a.w_max)


if __name__ == "__main__":
    main()
