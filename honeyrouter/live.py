"""
honeyrouter/live.py -- pick the agent for one live command with the trained router.

Reads what `hp --router` saved: the policy and omega the operator approved, and
the weights under out/. Nothing here is configured by hand.

Cost is unknown until a command has run, so the policy gets each agent's MEAN
normalised cost (a price list), the same as it saw in training.
"""
import json
import os
import threading

from honeyrouter.action import AGENTS


class NotReady(RuntimeError):
    """The router is untrained or unapproved; the caller falls back."""


class LiveRouter:
    def __init__(self):
        from honeyrouter import cli as HR
        st = HR._read_state().get("approved")
        if not st:
            raise NotReady("no approved router: run `hp --router`, train and approve one")
        import torch
        from honeyrouter import predictor as P
        from honeyrouter.embeddings import MODEL
        from sentence_transformers import SentenceTransformer
        if not os.path.exists(os.path.join(HR.OUT_DIR, HR.ARTIFACTS["predictor"])):
            raise NotReady("trained weights are missing: run `hp --router`")
        pol = HR._policy(st["policy"])
        if pol is None:
            raise NotReady(f"no '{st['policy']}' policy in {HR.OUT_DIR}")
        # encoded directly: embeddings.embed() rewrites its cache file per new command
        self._torch, self._pol = torch, pol
        # CPU, always: the responder model owns the GPU, and this net is tiny
        self._enc = SentenceTransformer(MODEL, device="cpu")
        self.omega = float(st["omega"])
        self.model, _ = P.load()
        self.I = self.model.mu.detach()
        cost = st.get("cost_norm") or self._cost_from_training_data(HR)
        self.c_vec = torch.tensor([[float(cost[a]) for a in AGENTS]],
                                  dtype=torch.float32)
        self._cache = {}

    @staticmethod
    def _cost_from_training_data(HR) -> dict:
        d = HR._load_data()
        if d is None:
            raise NotReady("cannot work out agent costs: train the router again")
        m = d["cost_norm"].mean(0)
        return {a: float(m[k]) for k, a in enumerate(AGENTS)}

    def pick(self, cmd: str) -> str:
        if cmd in self._cache:
            return self._cache[cmd]
        torch = self._torch
        e = torch.tensor(self._enc.encode([cmd], normalize_embeddings=True, show_progress_bar=False)[0], dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            p_hat = torch.sigmoid(self.model.logits(e, self.I))
            w = torch.tensor([[1.0, self.omega]], dtype=torch.float32)
            k = int(self._pol.logits(e, self.I.unsqueeze(0), self.c_vec.unsqueeze(-1),
                                     p_hat.unsqueeze(-1), w).argmax(1).item())
        if len(self._cache) > 5000:
            self._cache.clear()
        self._cache[cmd] = AGENTS[k]
        return AGENTS[k]


_lock = threading.Lock()
_router = None
_failed = None


def pick(cmd: str):
    """Agent name, or None when the router cannot be used (reason in last_error())."""
    global _router, _failed
    if _failed:
        return None
    if _router is None:
        with _lock:
            if _router is None and not _failed:
                try:
                    _router = LiveRouter()
                except Exception as exc:       # untrained, no torch, bad files
                    _failed = f"{type(exc).__name__}: {exc}"
                    return None
    return _router.pick(cmd) if _router else None


def last_error():
    return _failed
