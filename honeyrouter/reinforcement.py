"""
honeyrouter/reinforcement.py — Stage 3 of the LLM Bandit: RL TRAINING of the
routing policy with multi-objective PPO (Algorithm 1, lines 11-21; Sec 2.4;
App B.2, B.3.2, E.5).

It CONTINUES the Phase-2 policy (routing_policy.load_policy) -- same network,
now trained against real reward instead of imitating a target action.

WHAT ONE STEP DOES (Algorithm 1, lines 14-20):

    1. sample a batch of prompts, each with its K candidate arms          L14
    2. sample a preference omega = [1, w], w ~ U(0, 2)                    L15
    3. normalise scores/costs within the set: s_bar, c_bar   Eq (6)      L16
    4. p_hat_k = sigmoid(f(x, I_k))   (frozen Stage-1 predictor)         L17
    5. act a ~ pi(x, {(I_k, c_bar_k, p_hat_k)}, omega); reward [s_bar_a, -c_bar_a]  L18
    6. store the transition in the replay buffer                         L19
    7. PPO update on replayed data, with on-manifold mixup               L20

MULTI-OBJECTIVE PPO (Sec 2.4, B.2). The reward is a VECTOR r = [score, -cost].
The value network V(x, C) is also VECTOR-valued and is NOT conditioned on omega
(so value estimation is shared across preferences); it is fit by ||V - V_targ||^2.
The policy gradient scalarises the VECTOR advantage with omega:

    grad_theta [ omega^T J ] = E[ omega^T A(x,k') * grad_theta log pi(k'|x,C,omega) ]

and we optimise it with PPO's clipped surrogate, GAE for the advantage.

SINGLE-STEP EPISODES. Routing is a contextual bandit: one prompt -> one arm ->
one immediate reward, no next state. GAE(gamma, lambda) over a length-1 episode
therefore collapses to

    A = r - V(s),     V_targ = r

which is what we compute. There is no bootstrapping and gamma/lambda do not
appear -- stated plainly rather than hidden behind a general GAE loop that only
ever runs one step.

ON-MANIFOLD MIXUP (B.3.2, Eq B.5/B.6). Each sampled prompt is blended with its
nearest neighbour in embedding space, e_hat = lambda*e + (1-lambda)*e_n,
lambda ~ Beta(0.2, 0.2); the old policy prob, advantage and value target are
interpolated the same way, and the discrete choices (action, omega) are taken
from whichever transition dominates (lambda > 0.5). Toggle with --no-mixup.

REPLAY, NOT LIVE. "Run the selected model" is a lookup: every command in Part C
was really executed on all three arms and judge-scored, so the chosen arm's true
score and cost are known. Cost is $/command (reward.py's cost term); cloud is
billed, cowrie/on_device ~0.

OUTPUT. Writes the RL-trained policy to out/routing_policy_rl.pt (Phase 2's file
is left intact so the two stages can be compared).

    Yang Li, "LLM Bandit: Cost-Efficient LLM Generation via
    Preference-Conditioned Dynamic Routing", arXiv:2502.02743

    python honeyrouter/reinforcement.py --steps 500 --batch 256
"""
import argparse
import os
import sys

import numpy as np
import torch
import torch.nn as nn

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

from honeyrouter.action import AGENTS                       # noqa: E402
from honeyrouter import predictor as P                      # noqa: E402
from honeyrouter import routing_policy as RP                # noqa: E402

OUT = os.path.join(_HERE, "out", "routing_policy_rl.pt")
N_OBJ = 2                                                    # [score, -cost]


# ── vector value network V(x, C) -> R^2, NOT conditioned on omega (Sec 2.4) ────

class ValueNet(nn.Module):
    """Reads the same context set as the policy and outputs a vector of expected
    returns, one per objective. No omega input -- values are shared across
    preferences (Sec 2.4)."""

    def __init__(self, emb_dim: int, id_dim: int, hidden: int = 128,
                 n_obj: int = N_OBJ):
        super().__init__()
        self.elem = nn.Linear(id_dim + 2, hidden)
        self.sab = RP.SAB(hidden)
        self.pma = RP.PMA(hidden)
        self.prompt = nn.Linear(emb_dim, hidden)
        self.head = nn.Sequential(
            nn.Linear(hidden * 2, hidden), nn.ReLU(),
            nn.Linear(hidden, n_obj),
        )

    def forward(self, e, I_ctx, c_ctx, p_ctx):
        x = self.elem(torch.cat([I_ctx, c_ctx, p_ctx], dim=-1))
        x = self.sab(x)
        s = self.pma(x)
        return self.head(torch.cat([s, self.prompt(e)], dim=-1))    # (B, n_obj)


# ── nearest neighbours for mixup (B.5) ────────────────────────────────────────

def nearest_neighbours(E: np.ndarray, rows: np.ndarray) -> dict:
    """Map each row to its most similar OTHER row (cosine; E is L2-normalised).

    Restricted to `rows` (the training rows) so mixup never blends in a held-out
    prompt.
    """
    sub = E[rows]                                  # (R, d), already normalised
    sim = sub @ sub.T
    np.fill_diagonal(sim, -np.inf)
    nn_local = sim.argmax(axis=1)
    return {int(rows[i]): int(rows[j]) for i, j in enumerate(nn_local)}


# ── RL training (Algorithm 1, lines 11-21) ────────────────────────────────────

def train(steps=500, batch=256, lr=1e-3, w_min=0.0, w_max=2.0,
          ppo_epochs=4, clip=0.2, c_value=0.5, c_entropy=0.01,
          mixup=True, seed=0, verbose=True):
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)

    # Frozen Stage-1 predictor and the Stage-2 policy we keep training.
    model, _ = P.load()
    policy, meta = RP.load_policy()
    I = model.mu.detach()                                   # (K, id) frozen
    E, score, cost, sids, _ = RP.build_pairwise_dataset(seed=seed)

    with torch.no_grad():
        p_hat = torch.sigmoid(model.logits(torch.tensor(E), I))   # (N, K)
    Et = torch.tensor(E)
    score_t = torch.tensor(score)
    cost_t = torch.tensor(cost)
    K = len(AGENTS)

    tr_mask, va_mask = P.split_by_session(sids, seed=seed)
    tr_rows = np.where(tr_mask)[0]
    va_rows = np.where(va_mask)[0]
    nn_map = nearest_neighbours(E, tr_rows) if mixup else {}

    value = ValueNet(E.shape[1], I.shape[1])
    opt = torch.optim.Adam(list(policy.parameters()) + list(value.parameters()),
                           lr=lr)

    def normed(x):                                          # Eq (6): x / max_k x
        return x / x.max(dim=1, keepdim=True).values.clamp_min(1e-8)

    def collect(rows, w):
        """One transition per row under preference w. Returns tensors + the full
        old action distribution (needed for mixup blending)."""
        rows = torch.as_tensor(rows)
        n = rows.shape[0]
        omega = torch.stack([torch.ones(n), w], dim=1)              # [1, w]
        I_ctx = I.unsqueeze(0).expand(n, K, I.shape[1])
        s_bar = normed(score_t[rows])                              # (n,K)
        c_bar = normed(cost_t[rows])                               # (n,K)
        c_ctx = c_bar.unsqueeze(-1)
        p_ctx = p_hat[rows].unsqueeze(-1)                          # ORIGINAL p_hat
        e = Et[rows]
        with torch.no_grad():
            logits = policy.logits(e, I_ctx, c_ctx, p_ctx, omega)  # (n,K)
            probs = torch.softmax(logits, dim=1)
            a = torch.distributions.Categorical(probs=probs).sample()
            V = value(e, I_ctx, c_ctx, p_ctx)                     # (n,2)
        idx = torch.arange(n)
        r = torch.stack([s_bar[idx, a], -c_bar[idx, a]], dim=1)   # (n,2) reward
        return {"e": e, "I_ctx": I_ctx, "c_ctx": c_ctx, "p_ctx": p_ctx,
                "omega": omega, "a": a, "probs": probs, "V": V, "r": r,
                "s_bar": s_bar, "c_bar": c_bar}

    def blend(prim, nb, lam):
        """On-manifold mixup (B.5/B.6). lam:(n,1). Returns the batch to update on."""
        dom = (lam.squeeze(1) > 0.5)                              # (n,) which dominates

        def pick(p, q):                                           # broadcast dom
            d = dom.view((-1,) + (1,) * (p.dim() - 1))
            return torch.where(d, p, q)
        e = lam * prim["e"] + (1 - lam) * nb["e"]                 # Eq (B.5)
        probs_old = lam * prim["probs"] + (1 - lam) * nb["probs"]  # blended pi_old
        r_blend = lam * prim["r"] + (1 - lam) * nb["r"]           # V_targ = r
        A = (lam * (prim["r"] - prim["V"]) +
             (1 - lam) * (nb["r"] - nb["V"]))                     # blended adv
        a = torch.where(dom, prim["a"], nb["a"])                  # discrete by lam
        omega = pick(prim["omega"], nb["omega"])
        I_ctx = pick(prim["I_ctx"], nb["I_ctx"])
        c_ctx = pick(prim["c_ctx"], nb["c_ctx"])
        p_ctx = pick(prim["p_ctx"], nb["p_ctx"])
        return e, I_ctx, c_ctx, p_ctx, omega, a, probs_old, A, r_blend

    if verbose:
        print(f"[rl] train rows={len(tr_rows)} val={len(va_rows)}  "
              f"steps={steps} batch={batch} ppo_epochs={ppo_epochs} "
              f"mixup={mixup} omega~U[{w_min},{w_max}]")

    for step in range(1, steps + 1):
        rows = rng.choice(tr_rows, size=batch, replace=True)
        w = torch.tensor(rng.uniform(w_min, w_max, size=batch), dtype=torch.float32)
        prim = collect(rows, w)

        if mixup:
            nb_rows = np.array([nn_map[int(r)] for r in rows])
            w_n = torch.tensor(rng.uniform(w_min, w_max, size=batch),
                               dtype=torch.float32)
            nb = collect(nb_rows, w_n)
            lam = torch.tensor(rng.beta(0.2, 0.2, size=batch),
                               dtype=torch.float32).unsqueeze(1)   # Beta(0.2,0.2)
            e, I_ctx, c_ctx, p_ctx, omega, a, probs_old, A, V_targ = blend(
                prim, nb, lam)
        else:
            e, I_ctx, c_ctx, p_ctx = (prim[k] for k in
                                      ("e", "I_ctx", "c_ctx", "p_ctx"))
            omega, a, probs_old = prim["omega"], prim["a"], prim["probs"]
            A = prim["r"] - prim["V"]
            V_targ = prim["r"]

        idx = torch.arange(batch)
        logp_old = torch.log(probs_old[idx, a].clamp_min(1e-8))
        adv = (omega * A).sum(dim=1).detach()                     # omega^T A
        adv = (adv - adv.mean()) / (adv.std() + 1e-8)             # PPO norm
        V_targ = V_targ.detach()

        last = {}
        for _ in range(ppo_epochs):
            logits = policy.logits(e, I_ctx, c_ctx, p_ctx, omega)
            dist = torch.distributions.Categorical(logits=logits)
            logp = dist.log_prob(a)
            ratio = torch.exp(logp - logp_old)                   # pi_new / pi_old
            surr1 = ratio * adv
            surr2 = torch.clamp(ratio, 1 - clip, 1 + clip) * adv
            pol_loss = -torch.min(surr1, surr2).mean()           # clipped PPO
            V_new = value(e, I_ctx, c_ctx, p_ctx)
            val_loss = ((V_new - V_targ) ** 2).mean()            # ||V - V_targ||^2
            ent = dist.entropy().mean()
            loss = pol_loss + c_value * val_loss - c_entropy * ent
            opt.zero_grad(); loss.backward(); opt.step()
            last = {"pol": pol_loss.item(), "val": val_loss.item(),
                    "ent": ent.item()}

        if verbose and (step % 100 == 0 or step == 1):
            sr = _mean_scalarised_reward(policy, model, Et, score_t, cost_t,
                                         p_hat, I, va_rows, rng)
            print(f"  step{step:>4}  pol={last['pol']:+.4f} val={last['val']:.4f} "
                  f"ent={last['ent']:.3f} | val mean r_omega={sr:.4f}")

    torch.save({"state_dict": policy.state_dict(),
                "value_state_dict": value.state_dict(),
                "emb_dim": int(E.shape[1]), "id_dim": int(I.shape[1]),
                "agents": list(AGENTS), "alpha": meta.get("alpha"),
                "beta": meta.get("beta"), "w_range": [w_min, w_max]}, OUT)
    if verbose:
        print(f"[stage3] saved RL-trained policy -> {OUT}")
    return policy, value


# ── evaluation helpers ────────────────────────────────────────────────────────

def _mean_scalarised_reward(policy, model, Et, score_t, cost_t, p_hat, I,
                            rows, rng, n_omega=5):
    """Greedy routing on held-out rows, averaged over a sweep of omega.

    Reports the realised r_omega = omega^T[s_bar, -c_bar] of the arm the policy
    picks -- the quantity RL is supposed to raise.
    """
    K = len(AGENTS)
    rows_t = torch.as_tensor(rows)
    n = rows_t.shape[0]
    s_bar = score_t[rows_t] / score_t[rows_t].max(1, keepdim=True).values.clamp_min(1e-8)
    c_bar = cost_t[rows_t] / cost_t[rows_t].max(1, keepdim=True).values.clamp_min(1e-8)
    I_ctx = I.unsqueeze(0).expand(n, K, I.shape[1])
    c_ctx = c_bar.unsqueeze(-1)
    p_ctx = p_hat[rows_t].unsqueeze(-1)
    e = Et[rows_t]
    total = 0.0
    for w in np.linspace(0.0, 2.0, n_omega):
        omega = torch.tensor([[1.0, float(w)]]).expand(n, 2)
        with torch.no_grad():
            a = policy.logits(e, I_ctx, c_ctx, p_ctx, omega).argmax(1)
        idx = torch.arange(n)
        r = s_bar[idx, a] - float(w) * c_bar[idx, a]           # omega^T[s,-c]
        total += r.mean().item()
    return total / n_omega


def load_rl_policy(path: str = OUT):
    """Rebuild the RL-trained policy (and value net). Returns (policy, value, meta)."""
    ckpt = torch.load(path, map_location="cpu", weights_only=False)
    policy = RP.RoutingPolicy(ckpt["emb_dim"], ckpt["id_dim"])
    policy.load_state_dict(ckpt["state_dict"])
    policy.eval()
    value = ValueNet(ckpt["emb_dim"], ckpt["id_dim"])
    value.load_state_dict(ckpt["value_state_dict"])
    value.eval()
    return policy, value, ckpt


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--steps", type=int, default=500)      # E.5
    ap.add_argument("--batch", type=int, default=256)      # E.5
    ap.add_argument("--lr", type=float, default=1e-3)      # E.5
    ap.add_argument("--w-min", type=float, default=0.0)    # B.3.3
    ap.add_argument("--w-max", type=float, default=2.0)    # B.3.3
    ap.add_argument("--ppo-epochs", type=int, default=4)
    ap.add_argument("--clip", type=float, default=0.2)
    ap.add_argument("--no-mixup", action="store_true", help="disable B.3.2 mixup")
    a = ap.parse_args()
    train(steps=a.steps, batch=a.batch, lr=a.lr, w_min=a.w_min, w_max=a.w_max,
          ppo_epochs=a.ppo_epochs, clip=a.clip, mixup=not a.no_mixup)


if __name__ == "__main__":
    main()
