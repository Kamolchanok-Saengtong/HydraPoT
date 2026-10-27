"""
experiment_data/PartC/run/irt_router_live.py — route with the TRAINED neural
policy, per command, for a live run.

This is HoneyRouter v2: the agent is chosen by the Stage-1 IRT predictor plus
the Stage-2/3 routing policy, not by core/router.py's regex and FI table.
run_partC.py's `honeyrouter` arm leaves force_agent=None and lets
core.router.classify() decide, which is the regex path; the `irt_router` arm
asks this module instead and forces the agent it names, so the command really
runs on Cowrie / the on-device model / the cloud model and its cost, latency
and response are measured for real.

Nothing here is replayed. The caller executes whatever agent pick() returns.

WHY THE COST VECTOR IS FIXED. Training fed the policy each command's recorded
cost. A live router cannot: the cost is not known until the command has run,
which is the thing being decided. So the context carries the per-arm MEAN
normalised cost measured over the reference run (per_arm_cost), which is what
a deployment would know in advance -- a price list, not a measurement of the
future.
"""
from __future__ import annotations

import os

from honeyrouter.action import AGENTS


class IrtRouter:
    """Per-command agent choice from the trained policy.

    config_dir: a results/partC_ml_router/config_<hash>/ folder holding
                predictor.pt + routing_policy{,_rl}.pt
    which:      "rl" = Stage 3 (PPO), "policy" = Stage 2 (supervised)
    omega:      preference weight on -cost; the policy is conditioned on
                [1, omega], so this is the knob the paper exposes at
                inference time.
    """

    def __init__(self, config_dir: str, which: str = "rl", omega: float = 0.5,
                 cost_norm: dict | None = None):
        config_dir = os.path.abspath(config_dir)
        # Set before importing any honeyrouter stage: predictor.py,
        # routing_policy.py and reinforcement.py each resolve their own
        # OUT_DIR at import, so the env var has to be in place first.
        os.environ["HONEYROUTER_OUT"] = config_dir
        from honeyrouter import cli as HR
        from honeyrouter import predictor as P
        HR.OUT_DIR = config_dir
        HR.STATE_PATH = os.path.join(config_dir, "router_state.json")

        import torch
        self._torch = torch
        self.model, _ = P.load()                 # frozen Stage-1 IRT
        self.I = self.model.mu.detach()          # (K, id) arm identities
        self.pol = HR._policy(which)
        if self.pol is None:
                raise SystemExit(
                    f"no '{which}' policy in {config_dir} -- train it first:\n"
                    f"  python experiment_data/PartC/run/train_ml_router.py")
        self.which, self.omega = which, float(omega)

        if cost_norm is None:
            cost_norm = _reference_cost_norm()
        self.c_vec = torch.tensor(
            [[float(cost_norm.get(a, 0.0)) for a in AGENTS]],
            dtype=torch.float32)

        from honeyrouter.embeddings import embed
        self._embed = embed
        self._cache: dict[str, str] = {}

    def pick(self, cmd: str) -> str:
        """Agent name for this command. Cached: the same command text always
        routes the same way, and embedding is the slow part."""
        if cmd in self._cache:
            return self._cache[cmd]
        torch = self._torch
        vec = self._embed([cmd])[cmd]
        e = torch.tensor(vec, dtype=torch.float32).unsqueeze(0)      # (1,emb)
        with torch.no_grad():
            p_hat = torch.sigmoid(self.model.logits(e, self.I))      # (1,K)
            I_ctx = self.I.unsqueeze(0)                              # (1,K,id)
            c_ctx = self.c_vec.unsqueeze(-1)                         # (1,K,1)
            p_ctx = p_hat.unsqueeze(-1)                              # (1,K,1)
            w = torch.tensor([[1.0, self.omega]], dtype=torch.float32)
            k = int(self.pol.logits(e, I_ctx, c_ctx, p_ctx, w).argmax(1).item())
        self._cache[cmd] = AGENTS[k]
        return AGENTS[k]


def _reference_cost_norm() -> dict:
    """Per-arm normalised cost from the reference run, the price list a
    deployment would hold in advance."""
    import json
    import sys
    _here = os.path.dirname(os.path.abspath(__file__))
    if _here not in sys.path:
        sys.path.insert(0, _here)
    from train_ml_router import ARMS, FIDELITY, per_arm_cost
    rows = {a: [json.loads(l) for l in
                open(os.path.join(FIDELITY, f"{a}.jsonl"), encoding="utf-8")]
            for a in ARMS}
    norm, _ = per_arm_cost(rows)
    return norm
