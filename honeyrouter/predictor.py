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

# HONEYROUTER_OUT redirects every artifact this stage reads or writes, so a
# hyperparameter sweep trains into its own directory instead of overwriting the
# production checkpoints cli.py maintains in out/. Reads follow for free: the
# loaders below default to these constants, so stage 2 picks up the predictor
# from whichever directory the run owns rather than production's.
_OUT_DIR = os.environ.get("HONEYROUTER_OUT") or os.path.join(_HERE, "out")
OUT = os.path.join(_OUT_DIR, "predictor.npz")   # mu + sigma, for inspection
CKPT = os.path.join(_OUT_DIR, "predictor.pt")   # full model, for inference


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

# ── Stage 1 alternative: one vector per arm, read not learned ───────────────
#
# The paper infers each arm's ability from our own replay, per command. This
# path instead describes each arm with ONE number that says how capable the
# model is, and never varies it per command.
#
# Artificial Analysis was tried first and dropped: it scores neither of our
# two models -- both pages list the evaluations by name and publish a value
# for none, and each record carries "intelligenceIndex": null (checked
# 2026-10-31). benchmarklist.com scores both, so that is the source.
#
# One JSON file per model, no key and no judge:
#   https://benchmarklist.com/model-data/<id>.json
# Both arms are present with results_truncated=false, so the fetch below sees
# every result either model has: 44 for deepseek, 112 for qwen.
#
# ONE shared capability axis exists. It is the intersection of {scored for
# both arms} and {shell or security}, and that intersection has exactly one
# member: Terminal-Bench 2.1, i.e. did the model actually finish a task in a
# real shell. Nothing else qualifies, because every other candidate is
# single-sided -- Terminal-Bench Hard (24.2) and Honeyval (63.1) score only
# qwen; CyberGym (88.1), CWE-bench v1 (55.0) and Terminal-Bench 3.0/4.0/
# Science score only deepseek -- and an axis one arm lacks cannot rank arms.
#
# CAVEAT, and it belongs in the write-up (checked 2026-10-31): the two arms'
# figures come from different reporters. deepseek's 90.6 is the VENDOR's own
# number -- llm-stats marks that model "Unverified", 53 self-reported results
# and 0 verified -- whereas vals.ai's own three-trial run of the same model
# gives 74.5 on this benchmark and 19.7 on Terminal-Bench 4.0. A single
# independent run covering both arms does not exist: vals.ai tested 47 models
# on CyberBench and 59 on Terminal-Bench 4.0 and qwen3.5-9b is in neither.
# That is a limitation of the published data, not of the router.
BL_MODEL_DATA = "https://benchmarklist.com/model-data/{id}.json"
BL_CACHE = os.path.join(_OUT_DIR, "benchmarklist.json")

# Arm -> benchmarklist model id. The only hand-written part: an id, not a
# score. cowrie is absent for the same reason as above -- a template engine is
# on no leaderboard, so it is described by its own replay instead.
#
# qwen-qwen3.5-9b carries is_reasoning_model=false and there is no separate
# reasoning record (that id 404s), so this is the same non-thinking build
# config.yaml serves. deepseek's record is is_reasoning_model=true, which
# matches the reasoning tokens the cloud arm is billed for.
BL_IDS = {
    "cloud":     "deepseek-deepseek-v4.1-flash",
    "on_device": "qwen-qwen3.5-9b",
}

# (benchmark_id, divisor). benchmarklist reports these as percentages, so the
# divisor is 100. A FIXED reference, not min-max across the arms: with two
# benchmarked arms min-max pins one row to 0 and the other to 1, which makes
# the axes collinear and the vector worth one bit. A fixed divisor also keeps
# a published figure meaning the same thing if a fourth arm is added.
#
# ONE capability axis at a time, but TWO are offered, because which one is
# chosen changes the routing and the thesis reports both (checked 2026-10-31,
# the 10 benchmark_ids published for both arms):
#
#   terminal_bench  Terminal-Bench 2.1, category "Coding & Software
#                   Engineering", 90.6 / 29.2 over a field of 196. The closest
#                   published axis to what a honeypot does. on_device's 29.2
#                   sits BELOW cowrie's own 60.9, and cowrie is free, so
#                   on_device is dominated on both objectives and the router
#                   picks it zero times at every omega.
#   gpqa            GPQA Diamond, category "Reasoning", 90.9 / 80.6 over a
#                   field of 478, and the `_epoch` suffix means Epoch AI ran
#                   both arms itself -- unlike Terminal-Bench 2.1, where
#                   deepseek's 90.6 is the vendor's own figure (see above).
#                   General ability, not shell behaviour, which is also what
#                   the paper's identity I_k is meant to be. on_device's 80.6
#                   clears cowrie, so the third arm becomes reachable.
#
# The other eight shared ids are rejected: aa_briefcase, gdpval_aa and
# aiiq_composite_iq are Elo/IQ scales, not percentages, so they cannot share a
# divisor with the rest without inventing a transform; hle, jobbench,
# matharena_apex and scicode put BOTH LLM arms under cowrie, which collapses
# every omega to all-cowrie; aa_lcr is long-context reasoning, which GPQA
# covers better on a wider field.
BENCH_PRICE = "price_output_per_million"
BL_AXES = {
    "terminal_bench": "vals_terminal_bench_2_1",
    "gpqa":           "gpqa_diamond_epoch",
}
BL_AXIS = os.environ.get("HONEYROUTER_BENCH_AXIS", "terminal_bench")
if BL_AXIS not in BL_AXES:
    raise SystemExit(f"HONEYROUTER_BENCH_AXIS={BL_AXIS!r}: expected one of "
                     f"{sorted(BL_AXES)}")

# Every axis is fetched, so switching costs no extra request and one cache
# serves both runs; only the selected one is read as capability. Price is not a
# benchmark -- it is the second objective Stage 2/3 trade against quality, so
# it stays. build_vector keeps only axes present for ALL arms and cowrie has
# just the selected one, so mu stays [capability, price] whichever is chosen.
BL_FIELDS = tuple((b, 100.0) for b in BL_AXES.values()) + ((BENCH_PRICE, 10.0),)

BL_CAPABILITY = (BL_AXES[BL_AXIS],)

# NO pinned numbers. Every figure is fetched from benchmarklist and written to
# BL_CACHE, which is data on disk, not source. The cache is what makes a thesis
# figure reproducible -- it carries the retrieval date and is read on every run
# after the first -- but nothing numeric is typed into this file by hand.
#
# What the rest of the file reads, so a different leaderboard is a change to
# these three lines and nothing else.
BENCH_FIELDS = BL_FIELDS
BENCH_CAPABILITY = BL_CAPABILITY
BENCH_CACHE = BL_CACHE


def bl_fetch(ids=None, cache=BL_CACHE, timeout=60):
    """Pull each arm's published scores from benchmarklist into `cache`.

    One request per arm against a static JSON file -- no key, no judge, and
    no scraping of rendered HTML, which is what made the AA attempt unsafe.

    Fetched once and pinned to disk rather than read every run: a leaderboard
    is re-measured over time, and a thesis figure that silently changes
    between runs is not reproducible. The cache records the retrieval date.
    """
    import datetime
    import json as _json
    import urllib.request

    ids = dict(ids or BL_IDS)
    want = [p for p, _ in BENCH_FIELDS]
    out = {"source": BL_MODEL_DATA.format(id="<id>"),
           "retrieved": datetime.date.today().isoformat(),
           "intelligence_index_version": None,
           "tier": "public JSON (CC BY-NC 4.0, data from benchmarklist.com)",
           "models": {}}

    for arm, mid in ids.items():
        url = BL_MODEL_DATA.format(id=mid)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            blob = _json.load(r)

        if blob.get("results_truncated"):
            print(f"[bl] WARNING {arm}: results_truncated -- an axis may be "
                  f"missing from the file rather than from the model")
        scores = {e.get("benchmark_id"): e.get("score")
                  for e in blob.get("results") or []}
        pricing = (blob.get("model") or {}).get("pricing") or {}
        scores[BENCH_PRICE] = pricing.get("output_per_million")

        row = {"slug": mid, "name": (blob.get("model") or {}).get("name"),
               "is_reasoning_model": (blob.get("model") or {})
               .get("is_reasoning_model"),
               **{p: scores[p] for p in want if scores.get(p) is not None}}
        missing = [p for p in want if p not in row]
        if missing:
            print(f"[bl] {arm}: no value for {missing}")
        out["models"][arm] = row
        print(f"[bl] {arm:10} {mid}  "
              + "  ".join(f"{p}={row[p]}" for p in want if p in row))

    os.makedirs(os.path.dirname(cache), exist_ok=True)
    with open(cache, "w", encoding="utf-8") as f:
        _json.dump(out, f, indent=2)
    print(f"[bl] -> {cache}")
    return out


def measured_profile(arm: str):
    """An arm's own figures, measured from the replay instead of a leaderboard.

    For cowrie, which no leaderboard lists: speed and price come from what it
    actually did, and the success rate stands in for a quality index. Same
    same axes as BENCH_FIELDS so every row of the table means the same thing.
    """
    import numpy as _np
    from honeyrouter.sessions import load_sessions as _ls
    rows = [c for v in _ls().values() for c in v]
    g = [r["agents"][arm] for r in rows
         if arm in r.get("agents", {})
         and r["agents"][arm].get("judge_score") is not None]
    if not g:
        raise ValueError(f"no replay rows for {arm}")
    tok = [x.get("completion_tokens") or 0 for x in g]
    usd = [x.get("cost_usd") or 0 for x in g]
    succ = float(_np.mean([x["judge_score"] >= 3 for x in g]))
    # No leaderboard runs these benchmarks against a template engine, so cowrie
    # has one capability number -- its judge success rate -- and it is repeated
    # across the capability axes to keep the table rectangular. This is the
    # ONLY place the judge still describes an arm, which is the trade this mode
    # accepts: the two LLM arms cost nothing to describe, and the one arm with
    # no public score costs a judge pass we have already paid for.
    prof = {f: succ * 100.0 for f in BENCH_CAPABILITY}
    prof[BENCH_PRICE] = (sum(usd) / sum(tok) * 1e6) if sum(tok) else 0.0
    prof["score"] = succ
    return prof


def vector_profile(cache=BENCH_CACHE):
    """{arm: {axis: value, 'score': p}}, plus per-arm provenance.

    This is Stage 1 as a TABLE, with nothing fitted. An arm a leaderboard
    covers is described by its published figures; cowrie, which none covers,
    is described by its own measured behaviour. Either way the numbers are
    read, not learned, so there is no network here and no per-command guess --
    every command sees the same row for a given arm.
    """
    table, prov = _bench_table(cache)
    out, src = {}, {}
    for arm in AGENTS:
        if arm in table:
            row = dict(table[arm])
            # Capability from the published benchmark, averaged over whichever
            # capability axes exist. NOT the judge: judging every command costs
            # real money per call, and paying for it would undo the whole
            # reason for this mode.
            cap = [float(row[f]) for f in BENCH_CAPABILITY
                   if row.get(f) is not None]
            if not cap:
                raise SystemExit(
                    f"no published capability score for '{arm}' "
                    f"({BL_IDS.get(arm)}).\n"
                    f"Expected one of {list(BENCH_CAPABILITY)} in "
                    f"{BL_MODEL_DATA.format(id=BL_IDS.get(arm))}\n"
                    f"Either that model is no longer scored on it, or the id "
                    f"changed -- check the page and update BL_IDS.")
            # /100 because benchmarklist reports percentages and `score` is a
            # probability the Stage 2/3 heads read through a sigmoid.
            row["score"] = sum(cap) / len(cap) / 100.0
            src[arm] = (f"{prov}; score=mean of "
                        f"{[f for f in BENCH_CAPABILITY if row.get(f) is not None]}")
            out[arm] = row
        else:
            out[arm] = measured_profile(arm)
            src[arm] = "measured from the Part C replay (no leaderboard entry)"
    return out, src


class VectorPredictor(nn.Module):
    """Stage 1 with nothing learned: identities and scores straight from a table.

    Deliberately NOT the paper's Stage 1. There is no backbone, no f/g head and
    no per-command prediction -- `logits` returns the same row for every
    command, because a published model score describes the model, not the
    command. Stage 2 and Stage 3 need only `.mu` and `.logits(E, I)`, so they
    consume this unchanged and carry all the per-command learning themselves.
    """

    def __init__(self, I: torch.Tensor, p: torch.Tensor):
        super().__init__()
        self.identity = "vector"
        self.register_buffer("mu", I)                      # (K, d)
        self.register_buffer("rho", torch.zeros_like(I))
        # Stored as a logit so `sigmoid(logits(...))` recovers p exactly, the
        # way Stage 2 and 3 already call it.
        p = p.clamp(1e-4, 1 - 1e-4)
        self.register_buffer("p_logit", torch.log(p / (1 - p)))

    def sigma(self):
        return torch.zeros_like(self.mu)

    def sample_identity(self, train: bool = True):
        return self.mu

    def logits(self, E: torch.Tensor, I: torch.Tensor = None):
        """(N, K), every row identical -- the arm's score, not the command's."""
        return self.p_logit.unsqueeze(0).expand(E.shape[0], -1)

    def pair_logits(self, E: torch.Tensor, I: torch.Tensor = None):
        return self.logits(E, I)

    def kl(self):
        return torch.zeros((), device=self.mu.device)


def build_vector(cache=BENCH_CACHE, verbose=True):
    """(model, profile, provenance) for --identity vector. Fits nothing."""
    prof, src = vector_profile(cache)
    axes = [p for p, _ in BENCH_FIELDS if all(p in prof[a] for a in AGENTS)]
    if not axes:
        raise SystemExit("no axis is present for every arm -- refresh the "
                         "benchmark cache or check BL_IDS")
    scale = dict(BENCH_FIELDS)
    I = torch.tensor([[float(prof[a][p]) / scale[p] for p in axes]
                      for a in AGENTS], dtype=torch.float32)
    p = torch.tensor([float(prof[a]["score"]) for a in AGENTS],
                     dtype=torch.float32)
    if verbose:
        print(f"[vector] axes={[x.split('.')[-1] for x in axes]}")
        for k, a in enumerate(AGENTS):
            print(f"  {a:10} score={p[k]:.3f}  mu={[round(v,4) for v in I[k].tolist()]}")
            print(f"             source: {src[a]}")
    return VectorPredictor(I, p), prof, src


def _bench_table(cache=BENCH_CACHE):
    """(per-arm figures, provenance string), fetched from the web if needed.

    First call with no cache fetches it; every later call reads the cache, so
    the numbers in a thesis run are fixed at a known retrieval date rather
    than drifting with the leaderboard. --refresh-benchmarks re-pulls.
    """
    import json as _json
    if not os.path.exists(cache):
        print(f"[bl] no cache at {cache} -- fetching from benchmarklist")
        bl_fetch(cache=cache)
    with open(cache, encoding="utf-8") as f:
        blob = _json.load(f)
    return (blob.get("models") or {},
            f"{blob.get('source')} retrieved {blob.get('retrieved')} "
            f"[{blob.get('tier')}]")


class Predictor(nn.Module):
    """Variational identity per arm + two heads over a shared backbone.

    q(I_k) = N(mu_k, diag sigma_k^2),  prior p(I_k) = N(0, I),  dim d.
    f  Eq (2) success head:  p_kn = sigmoid(f(e, I_k))
    g  Eq (3) pairwise head: p_n  = sigmoid(g(e, I_a) - g(e, I_b))

    f and g share the backbone and differ only in their final linear layer
    (App E.3), so one identity vector serves both objectives.
    """

    def __init__(self, emb_dim: int, n_arms: int, dim: int = 128,
                 hidden: int = 128, identity: str = "irt"):
        super().__init__()
        self.identity = identity
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
        s, mu = self.sigma(), self.mu
        return (0.5 * (s ** 2 + mu ** 2 - 1.0 - 2.0 * torch.log(s))
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
          w_pair=1.0, w_kl=None, seed=0, verbose=True, identity="irt"):
    """Fit the variational IRT model: minimise L_irt + w_pair*L_pair + beta*L_KL.

    w_kl None -> beta = 1/N (faithful ELBO amortisation, see module docstring).
    Optimiser is App E.3: Adam 1e-3, lr x0.95/epoch, batch 256, 10 epochs.

    identity "vector" skips all of this: one published figure per arm, read
    not fitted -- see BL_IDS / bl_fetch.
    """
    torch.manual_seed(seed)

    # --identity vector: Stage 1 is a table, so there is nothing to fit. Built,
    # saved in the same shape Stage 2/3 load, and returned without an optimiser.
    if identity == "vector":
        model, prof, src = build_vector(verbose=verbose)
        E, Y, raw, sids, eta = build_dataset()      # only for the saved eta
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        np.savez(OUT, identity=model.mu.numpy(), sigma=model.sigma().numpy(),
                 agents=np.array(AGENTS), eta=eta, dim=int(model.mu.shape[1]))
        torch.save({"state_dict": model.state_dict(),
                    "emb_dim": int(E.shape[1]),
                    "dim": int(model.mu.shape[1]),
                    "agents": list(AGENTS), "eta": float(eta), "beta": 0.0,
                    "identity": "vector", "provenance": src}, CKPT)
        if verbose:
            print(f"[stage1] vector table, nothing trained -> {CKPT}")
        return model, (E, Y, raw, sids, eta), split_by_session(sids, seed=seed)

    E, Y, raw, sids, eta = build_dataset()
    tr, va = split_by_session(sids, seed=seed)

    Et, Yt, Rt = (torch.tensor(x[tr]) for x in (E, Y, raw))
    Ev, Yv, Rv = (torch.tensor(x[va]) for x in (E, Y, raw))

    model = Predictor(E.shape[1], len(AGENTS), dim=dim, identity=identity)
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
                "beta": float(beta), "identity": identity}, CKPT)
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
    # Default "irt": checkpoints trained before the vector path existed carry
    # no "identity" key and must keep loading unchanged.
    ident = ckpt.get("identity", "irt")
    if ident == "vector":
        sd = ckpt["state_dict"]
        model = VectorPredictor(sd["mu"], torch.sigmoid(sd["p_logit"]))
        model.eval()
        return model, ckpt
    model = Predictor(ckpt["emb_dim"], len(ckpt["agents"]), dim=ckpt["dim"],
                      identity=ident)
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
    ap.add_argument("--identity", choices=("irt", "vector"), default="irt",
                    help="irt: learn each arm's ability from the replay (the "
                         "paper). vector: one published figure per arm, read "
                         "not learned -- same for every command")
    ap.add_argument("--refresh-benchmarks", action="store_true",
                    help="re-pull the scores from benchmarklist.com before "
                         "training, instead of reusing the cached copy")
    a = ap.parse_args()
    if a.refresh_benchmarks:
        bl_fetch()
    model, data, _ = train(dim=a.dim, epochs=a.epochs, lr=a.lr, batch=a.batch,
                           lr_decay=a.lr_decay, w_pair=a.w_pair, w_kl=a.w_kl,
                           identity=a.identity)
    E, Y, raw, sids, eta = data
    with torch.no_grad():
        mu = model.mu
        print("\n=== identities ===")
        for k, name in enumerate(AGENTS):
            src = "learned" if a.identity == "irt" else a.identity
            print(f"  {name:10} [{src:9}] |mu|={mu[k].norm():.3f}  "
                  f"mean sigma={model.sigma()[k].mean():.4f}  "
                  f"mu={mu[k].tolist() if mu.shape[1] <= 4 else '...'}")
        logits = model.logits(torch.tensor(E), mu)
        p = torch.sigmoid(logits).numpy()
        print("\n=== predicted vs observed success rate (all rows) ===")
        for k, name in enumerate(AGENTS):
            print(f"  {name:10} predicted {p[:, k].mean():.1%}   "
                  f"observed {Y[:, k].mean():.1%}")


if __name__ == "__main__":
    main()
