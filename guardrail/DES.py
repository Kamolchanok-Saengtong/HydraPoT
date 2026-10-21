"""
guardrail/DES.py — Dynamic Error Simulation.

THE QUESTION. When an attacker types an English sentence at the shell -- which
is what every one of the 247 adversarial prompts is -- a real Linux box answers
with an error, because argv[0] of "Can you tell me ..." is `Can`. Can HydraPoT
produce that same dynamic error, or does it answer as a chatbot?

guardrail/validator.py only asks whether the reply contained a refusal phrase,
which cannot separate a CORRECT answer from a merely non-refusing one. This
scores against the real box instead: guardrail/collect_ground_truth.py captures
what the reference container actually says, and every arm is compared to it.

FOUR ARMS, one code path. Each is the real pipeline with a different set of
agents enabled, so the prompt an agent receives is identical across arms and
only the answerer changes:

    hydrapot    all three enabled -- natural routing via classify()
    on_device   only the local LLM enabled  -> every prompt goes there
    cloud       only the cloud LLM enabled  -> every prompt goes there
    cowrie      only Cowrie enabled         -> every prompt goes there

Single-agent mode is classify()'s own documented behaviour ("HoneyRouter has no
choice to make"), reached by patching core.router._AGENTS_ENABLED -- not by a
second dispatch path that would no longer be the pipeline under test.

THREE SIMILARITY MEASURES, per the paper, reported as B / T / M:
    B  BoW     text (word-level) similarity, CountVectorizer cosine
    T  TF-IDF  text (word-level) similarity, rarer words weighted
    M  MiniLM  semantic similarity: embeddings, L2-normalised, cosine
                 similarity(A,B) = (A . B) / (||A|| * ||B||)
TF-IDF reuses evaluation/fidelity.py's cosine_score_response, the same scorer
Part C reports, so a number here is comparable to a number there.

TWO PHASES, because the responses are expensive and the scoring is not. `run`
persists every reply; `score` reads them back. A missing embedding model or a
bad metric can then never cost a second round of LLM calls.

    python guardrail/DES.py run                        # all four arms
    python guardrail/DES.py run --arms cowrie,on_device
    python guardrail/DES.py run --limit 5              # smoke test
    python guardrail/DES.py score
    python guardrail/DES.py score --no-minilm          # skip the GPU/embed step
    python guardrail/DES.py score --summarize         # reprint saved scores

FIVE FILES, no more. One per arm plus one summary, so the whole evaluation can
be read by hand:

    guardrail/results/des/responses_<arm>.json   prompt, ground truth, the arm's
                                                 answer and its own B/T/M — every
                                                 number in the table traceable to
                                                 the pair that produced it
    guardrail/results/des/des_scores.json        the aggregates, plus `comparison`:
                                                 one entry per prompt with all four
                                                 arms beside the ground truth

The handler's own session logs are NOT an output of this evaluation -- they are
a second copy of the same answers -- so they go to a temp dir and the results
folder stays readable.
"""
import argparse
import json
import os
import sys
import tempfile
import time
from collections import defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))                   # guardrail/
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT,
          os.path.join(_ROOT, "evaluation"),
          os.path.join(_ROOT, "experiment_data"),
          os.path.join(_ROOT, "experiment_data", "PartA")):
    if p not in sys.path:
        sys.path.insert(0, p)

GT_DIR = os.path.join(_HERE, "groundtruth")
# Results live under the evaluation's own name, beside the guardrail code.
OUT_DIR = os.path.join(_HERE, "results", "des")

ARMS = ["hydrapot", "on_device", "cloud", "cowrie"]
# Which agents each arm leaves enabled. hydrapot keeps all three so classify()
# routes naturally; the others are single-agent mode.
ARM_AGENTS = {
    "hydrapot":  {"cowrie": True,  "on_device": True,  "cloud": True},
    "on_device": {"cowrie": False, "on_device": True,  "cloud": False},
    "cloud":     {"cowrie": False, "on_device": False, "cloud": True},
    "cowrie":    {"cowrie": True,  "on_device": False, "cloud": False},
}
MINILM_DEFAULT = "sentence-transformers/all-MiniLM-L6-v2"


# ─── ground truth ─────────────────────────────────────────────────────────────

def load_ground_truth():
    """[(dataset, category, prompt, ground_truth)] from both collected files.

    The two datasets stay separate downstream, but share one pass here so an
    arm answers every prompt in one session, as an attacker would.
    """
    rows, skipped = [], {}
    for name in ("scope", "malicious_instruct"):
        path = os.path.join(GT_DIR, f"{name}_ground_truth.json")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        kept = 0
        why = defaultdict(int)
        for r in data:
            # A prompt with no reference answer cannot be scored. Counted and
            # reported rather than dropped quietly, so a shrinking n is never
            # mistaken for a dataset that was always this size.
            if r.get("blocked"):
                why["blocked (unsafe, never run)"] += 1
            elif r.get("unscorable"):
                why["unscorable (incomplete command)"] += 1
            elif r.get("ground_truth") is None:
                why["no ground truth (collection error)"] += 1
            else:
                rows.append(r)
                kept += 1
        skipped[name] = (len(data), kept, dict(why))
    for name, (total, kept, why) in skipped.items():
        print(f"[des] {name}: {kept}/{total} scorable")
        for reason, k in sorted(why.items()):
            print(f"[des]     -{k} {reason}")
    return rows


# ─── phase 1: collect each arm's answers ──────────────────────────────────────

def run(arms, limit):
    gt = load_ground_truth()
    if not gt:
        sys.exit(f"[des] no ground truth in {os.path.relpath(GT_DIR, _ROOT)}/ — "
                 f"run guardrail/collect_ground_truth.py first")
    if limit:
        gt = gt[:limit]
    print(f"[des] {len(gt)} prompts x {len(arms)} arms")

    from core.config_loader import load_config
    from core import router
    from agent_manager.cowrie_agent import CowrieAgent
    from overhead import _FakeChannel
    import main as hydrapot_main

    config = load_config()
    need = {a for arm in arms for a, on in ARM_AGENTS[arm].items() if on}

    ondevice = cloud = cowrie = None
    if "on_device" in need:
        from agent_manager.ondevice_agent import OnDeviceAgent
        c = config.agents.on_device
        print("[des] loading on-device model ...")
        ondevice = OnDeviceAgent(model=c.model, quantization=c.quantization,
                                 gguf_file=c.gguf_file, temperature=c.temperature,
                                 max_tokens=c.max_tokens, do_sample=c.do_sample)
    if "cloud" in need:
        from agent_manager.cloud_agent import CloudAgent
        c = config.agents.cloud
        cloud = CloudAgent(provider=c.provider, model=c.model,
                           base_url=getattr(c, "base_url", None),
                           temperature=c.temperature, max_tokens=c.max_tokens)
    if "cowrie" in need:
        c = config.agents.cowrie
        cowrie = CowrieAgent(host=c.host, port=c.port, username=c.username,
                             password=c.password)
        # Connected explicitly and NOT tolerated on failure: send() returns
        # ("", "") on a dead shell, which would score as a silent arm rather
        # than an outage -- the same reason validator.py connects eagerly.
        cowrie._connect()

    hydrapot_main.config = config
    hydrapot_main.ondevice = ondevice
    hydrapot_main.cloud = cloud

    os.makedirs(OUT_DIR, exist_ok=True)
    # store="json" and not the sqlite default: that would write 247 adversarial
    # prompts into hydrapot.db alongside real sensor traffic. The jsonl and
    # impactful.json it produces duplicate what responses_<arm>.json already
    # holds, so they go to a temp dir rather than cluttering the results folder.
    log_dir = tempfile.mkdtemp(prefix="des_sessions_")
    print(f"[des] handler session logs -> {log_dir} (not an output)")
    saved_enabled = dict(router._AGENTS_ENABLED)
    try:
        for arm in arms:
            router._AGENTS_ENABLED = dict(ARM_AGENTS[arm])
            handle = hydrapot_main.make_command_handler(
                cowrie, src_ip=f"des_{arm}", public_ip=f"des_{arm}",
                plugins=None, sri_max_events=20, capture_cost=True,
                store="json", store_dir=os.path.join(log_dir, arm),
            )
            out, t0 = [], time.time()
            for i, r in enumerate(gt, 1):
                prompt = " ".join((r["prompt"] or "").split())
                ch = _FakeChannel()
                t = time.perf_counter()
                try:
                    ret = handle(prompt, ch.write, ch.read)
                    text = (ret[0] if isinstance(ret, tuple) else None) or ch.text()
                    err = None
                except Exception as e:
                    text, err = "", f"{type(e).__name__}: {e}"
                out.append({
                    "dataset": r["dataset"], "category": r["category"],
                    "prompt": r["prompt"], "ground_truth": r["ground_truth"],
                    "response": (text or "").strip(),
                    "agent": getattr(handle, "last_agent", "unknown"),
                    "latency_ms": round((time.perf_counter() - t) * 1000, 2),
                    **({"error": err} if err else {}),
                })
                if i % 25 == 0 or i == len(gt):
                    print(f"  [{arm}] {i}/{len(gt)}  ({time.time() - t0:.0f}s)",
                          flush=True)
            path = os.path.join(OUT_DIR, f"responses_{arm}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
            print(f"[des] {os.path.relpath(path, _ROOT)}  ({len(out)} answers)")
    finally:
        router._AGENTS_ENABLED = saved_enabled


# ─── phase 2: score against the ground truth ──────────────────────────────────

def _bow_cosine(pred, gt):
    """Bag-of-words cosine: raw word counts, no IDF weighting."""
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    if not pred and not gt:
        return 1.0
    if not pred or not gt:
        return 0.0
    try:
        m = CountVectorizer().fit_transform([pred, gt])
    except ValueError:
        return 0.0            # both sides stop-words only -> no vocabulary
    return float(cosine_similarity(m[0], m[1])[0][0])


def _minilm_cosines(pairs, model_name):
    """Cosine per pair from L2-normalised MiniLM embeddings.

    Batched in one encode() call: 247 x 4 arms one-at-a-time is dominated by
    per-call overhead. normalize_embeddings=True makes the dot product the
    cosine directly, which is Eq. 3 with no separate division step.
    """
    from sentence_transformers import SentenceTransformer
    import numpy as np
    model = SentenceTransformer(model_name)
    preds = [p or "" for p, _ in pairs]
    gts = [g or "" for _, g in pairs]
    ep = model.encode(preds, normalize_embeddings=True, batch_size=64,
                      show_progress_bar=False)
    eg = model.encode(gts, normalize_embeddings=True, batch_size=64,
                      show_progress_bar=False)
    sims = np.sum(np.asarray(ep) * np.asarray(eg), axis=1)
    # An empty string still embeds, so an empty-vs-empty pair would score on
    # whatever the model makes of "". Decided here, as fidelity.py does.
    out = []
    for (p, g), s in zip(pairs, sims):
        if not (p or "").strip() and not (g or "").strip():
            out.append(1.0)
        elif not (p or "").strip() or not (g or "").strip():
            out.append(0.0)
        else:
            out.append(float(s))
    return out


def score(skip_minilm, model_name):
    from fidelity import cosine_score_response          # TF-IDF, Part C's own

    files = {a: os.path.join(OUT_DIR, f"responses_{a}.json") for a in ARMS}
    files = {a: p for a, p in files.items() if os.path.exists(p)}
    if not files:
        sys.exit(f"[des] no responses in {os.path.relpath(OUT_DIR, _ROOT)}/ — "
                 f"run `python guardrail/DES.py run` first")

    summary, rows_by_arm = {}, {}
    for arm, path in files.items():
        with open(path, encoding="utf-8") as f:
            rows = json.load(f)
        rows_by_arm[arm] = rows
        for r in rows:
            pred, gt = r.get("response") or "", r.get("ground_truth") or ""
            r["bow"] = _bow_cosine(pred, gt)
            r["tfidf"] = cosine_score_response(pred, gt)["cosine_score"]
            r["exact"] = 1.0 if pred.strip() == gt.strip() else 0.0

    if not skip_minilm:
        print(f"[des] embedding with {model_name} ...")
        for arm, rows in rows_by_arm.items():
            sims = _minilm_cosines(
                [(r.get("response") or "", r.get("ground_truth") or "")
                 for r in rows], model_name)
            for r, s in zip(rows, sims):
                r["minilm"] = s

    metrics = ["bow", "tfidf", "exact"] + ([] if skip_minilm else ["minilm"])
    for arm, rows in rows_by_arm.items():
        per_ds = defaultdict(list)
        for r in rows:
            per_ds[r["dataset"]].append(r)
        summary[arm] = {"n": len(rows)}
        for ds, rs in sorted(per_ds.items()):
            summary[arm][ds] = {
                "n": len(rs),
                **{m: round(sum(r[m] for r in rs if m in r) / max(1, len(rs)), 4)
                   for m in metrics},
            }
        summary[arm]["overall"] = {
            m: round(sum(r[m] for r in rows if m in r) / max(1, len(rows)), 4)
            for m in metrics}
        summary[arm]["routed_to"] = dict(
            sorted(defaultdict(int, {a: sum(1 for r in rows if r.get("agent") == a)
                                     for a in set(r.get("agent") for r in rows)}
                               ).items()))

    # Scores go back into the arm's own file, next to the pair that produced
    # them. Scoring used to compute these and throw them away, which left no
    # way to ask "which prompts dragged this mean down" without rescoring.
    for arm, rows in rows_by_arm.items():
        with open(files[arm], "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)

    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, "des_scores.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"metric_labels": METRIC_LABEL,
                   "arms": summary,
                   "comparison": comparison(rows_by_arm, metrics)},
                  f, ensure_ascii=False, indent=2)
    print_summary(summary)
    print(f"\n[des] {os.path.relpath(out, _ROOT)}  "
          f"(aggregates + per-prompt comparison)")
    for arm in rows_by_arm:
        print(f"[des] {os.path.relpath(files[arm], _ROOT)}  "
              f"({len(rows_by_arm[arm])} scored pairs)")


def comparison(rows_by_arm, metrics):
    """One entry per prompt, every arm's answer beside the ground truth.

    Checking fidelity by eye means reading all four answers to the SAME prompt
    together; the per-arm files cannot show that because each holds one arm.
    """
    order, by_key = [], {}
    for arm in ARMS:
        for r in rows_by_arm.get(arm, []):
            key = (r.get("dataset"), r.get("prompt"))
            if key not in by_key:
                order.append(key)
                by_key[key] = {
                    "dataset": r.get("dataset"), "category": r.get("category"),
                    "prompt": r.get("prompt"),
                    "ground_truth": r.get("ground_truth"), "arms": {},
                }
            by_key[key]["arms"][arm] = {
                "response": r.get("response"),
                "answered_by": r.get("agent"),
                **{METRIC_LABEL.get(m, m): round(r[m], 4)
                   for m in metrics if m in r},
            }
    return [by_key[k] for k in order]


# The paper's own column labels and grouping: word-level overlap vs meaning.
# `exact` is ours, kept in the JSON but outside the two reported groups so a
# table copied from this terminal matches the paper's columns exactly.
METRIC_LABEL = {"bow": "B", "tfidf": "T", "minilm": "M"}
METRIC_NAME = {"bow": "BoW", "tfidf": "TF-IDF", "minilm": "MiniLM"}
METRIC_GROUP = [("word-level", ["bow", "tfidf"]),
                ("semantic", ["minilm"])]


def print_summary(summary):
    """The terminal table, labelled B / T / M as the paper reports them.

    Columns come from the summary itself, so a file scored with --no-minilm
    prints without M instead of crashing on a key the run never produced.
    """
    arms = [a for a in ARMS if a in summary]
    if not arms:
        print("[des] (no arms in summary)")
        return
    have = summary[arms[0]].get("overall", {})
    metrics = [m for _g, ms in METRIC_GROUP for m in ms if m in have]

    # group banner sits over the columns its metrics occupy
    groups = "  " + " " * 38
    for name, ms in METRIC_GROUP:
        w = 8 * len([m for m in ms if m in have])
        if w:
            groups += name.center(w)
    hdr = (f"  {'arm':11}{'dataset':22}{'n':>5}"
           + "".join(f"{METRIC_LABEL[m]:>8}" for m in metrics))

    print("\n" + "=" * max(len(hdr), len(groups)))
    print("  DYNAMIC ERROR SIMULATION — similarity to the real shell's answer")
    print("=" * max(len(hdr), len(groups)))
    print(groups)
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for arm in arms:
        for ds in [k for k in summary[arm] if k not in ("n", "overall", "routed_to")]:
            d = summary[arm][ds]
            print(f"  {arm:11}{ds:22}{d['n']:>5}"
                  + "".join(f"{d[m]:>8.3f}" for m in metrics))
        d = summary[arm]["overall"]
        print(f"  {arm:11}{'OVERALL':22}{summary[arm]['n']:>5}"
              + "".join(f"{d[m]:>8.3f}" for m in metrics))
        print("  " + "-" * (len(hdr) - 2))

    # Arms side by side -- the shape a paper table wants, which the per-arm
    # blocks above cannot show because they interleave. The legend is built
    # from the columns actually present: a fixed string advertising M on a
    # --no-minilm file reads as "M is zero" rather than "M was never scored".
    legend = "   ".join(f"{METRIC_LABEL[m]} = {METRIC_NAME[m]}" for m in metrics)
    print(f"\n  OVERALL, arms side by side        {legend}")
    print(f"  {'arm':11}{'n':>5}" + "".join(f"{METRIC_LABEL[m]:>8}" for m in metrics))
    print("  " + "-" * (16 + 8 * len(metrics)))
    for arm in arms:
        d = summary[arm]["overall"]
        print(f"  {arm:11}{summary[arm]['n']:>5}"
              + "".join(f"{d[m]:>8.3f}" for m in metrics))
    missing = [m for m in METRIC_LABEL if m not in have]
    if missing:
        print("\n  " + ", ".join(f"{METRIC_LABEL[m]} ({METRIC_NAME[m]})"
                                 for m in missing)
              + " not in this file — it was scored with --no-minilm."
              "\n  Rerun `python guardrail/DES.py score` without that flag.")
    if "exact" in have:
        print("\n  exact match (not a reported metric, kept for reference): "
              + ", ".join(f"{a}={summary[a]['overall']['exact']:.3f}" for a in arms))
    print()
    for arm in arms:
        print(f"[des]   {arm:11} answered by {summary[arm].get('routed_to')}")


def summarize():
    """Reprint the saved scores. No responses re-read, nothing re-embedded."""
    path = os.path.join(OUT_DIR, "des_scores.json")
    if not os.path.exists(path):
        sys.exit(f"[des] no saved scores at {os.path.relpath(path, _ROOT)} — "
                 f"run `python guardrail/DES.py score` first")
    with open(path, encoding="utf-8") as f:
        saved = json.load(f)
    # The file carries the comparison block too; the table only needs "arms".
    summary = saved.get("arms", saved)
    print(f"[des] {os.path.relpath(path, _ROOT)}")
    print_summary(summary)
    n = len(saved.get("comparison", []))
    if n:
        print(f"\n[des] {n} per-prompt comparisons in the same file "
              f"(ground truth + each arm's response)")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run", help="collect each arm's answers")
    p_run.add_argument("--arms", default=",".join(ARMS))
    p_run.add_argument("--limit", type=int, default=0)
    p_sc = sub.add_parser("score", help="score saved answers vs ground truth")
    p_sc.add_argument("--no-minilm", action="store_true",
                      help="skip the embedding metric (no model download/GPU)")
    p_sc.add_argument("--minilm-model", default=MINILM_DEFAULT)
    p_sc.add_argument("--summarize", action="store_true",
                      help="just reprint des_scores.json — no rescoring")
    args = ap.parse_args()

    if args.cmd == "run":
        arms = [a.strip() for a in args.arms.split(",") if a.strip()]
        bad = [a for a in arms if a not in ARM_AGENTS]
        if bad:
            sys.exit(f"[des] unknown arm(s): {bad}; choose from {ARMS}")
        run(arms, args.limit)
    elif args.summarize:
        summarize()
    else:
        score(args.no_minilm, args.minilm_model)


if __name__ == "__main__":
    main()
