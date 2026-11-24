"""
experiment_data/PartC/run/onboard_live.py -- run the onboarded model LIVE through the router.

onboard_new_model.py fitted a 3-number vector for glm-5.3 from a few prompts and scored it
offline. This puts that vector into the frozen network, then for each omega:

    1. the trained policy picks an agent per command (glm-5.3 sits in the cloud slot)
    2. the picked agent is really called (run_partC.py, arm irt_router)
    3. every response is judged by the LLM judge and scored by the semantic metrics
    4. one table compares the omegas with the forced glm-5.3 run and the old router

The vector comes from the prompt-budget fit, never from the full retrain.

    python experiment_data/PartC/run/onboard_live.py
"""
import argparse
import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "score"))

RES = os.path.join(ROOT, "experiment_data", "results")
OMEGAS = "0,0.1,0.2,0.25,0.5,1.0,2.0"


def write_identity(src, budget, seed, slot, path):
    """The fitted vector for this budget and seed. results.json holds only the
    budget fits; the full-retrain ruler is not stored there."""
    res = json.load(open(src, encoding="utf-8"))
    vecs = {k.strip(): v for k, v in res["vectors"].items()}
    key = f"{budget} prompts"
    if key not in vecs:
        sys.exit(f"no '{key}' in {src}; have {sorted(vecs)}")
    vec = vecs[key][seed]
    json.dump({"slot": slot, "vector": vec, "source": os.path.relpath(src, ROOT),
               "budget": budget, "seed": seed}, open(path, "w"), indent=2)
    return vec


def run(cmd):
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def judge_mean(d):
    files = glob.glob(os.path.join(d, "judge", "irt_router", "judge_scored_*.jsonl"))
    if not files:
        return None, 0
    s = [r["judge_score"] for r in map(json.loads, open(files[0], encoding="utf-8"))
         if isinstance(r.get("judge_score"), (int, float))]
    return (sum(s) / len(s) if s else None), len(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-name", default="live_no_benchmark_60prompts")
    ap.add_argument("--source", default=os.path.join(
        RES, "partC_onboarding", "budget_sweep", "no_benchmark", "results.json"))
    ap.add_argument("--budget", type=int, default=60, help="number of fit prompts")
    ap.add_argument("--seed", type=int, default=0, help="which of the seeds' vectors")
    ap.add_argument("--slot", default="cloud")
    ap.add_argument("--cloud-model", default="z-ai/glm-5.3")
    ap.add_argument("--config-dir", default=os.path.join(RES, "partC_ml_router", "bench+2learn+net"),
                    help="the trained network and policy (frozen)")
    ap.add_argument("--sessions", default="dataset/partC_stateful_sessions.json")
    ap.add_argument("--omegas", default=OMEGAS)
    ap.add_argument("--true-dir", default=os.path.join(RES, "partC_onboarding", "glm-5.3_true_run"))
    args = ap.parse_args()

    out = os.path.join(RES, "partC_onboarding", args.run_name)
    os.makedirs(out, exist_ok=True)
    ident = os.path.join(out, "identity.json")
    vec = write_identity(args.source, args.budget, args.seed, args.slot, ident)
    print(f"{args.slot} vector from {args.budget} prompts (seed {args.seed}): {vec}", flush=True)

    from train_ml_router import score_vs_partc          # noqa: E402

    table = []
    for om in [float(x) for x in args.omegas.split(",")]:
        d = os.path.join(out, f"omega_{om}")
        rows_file = os.path.join(d, "irt_router.jsonl")
        if not os.path.isfile(rows_file):
            run([sys.executable, "-u", os.path.join(HERE, "run_partC.py"),
                 "--sessions", args.sessions, "--arms", "irt_router",
                 "--irt-config-dir", args.config_dir, "--irt-omega", str(om),
                 "--irt-identity-file", ident, "--cloud-model", args.cloud_model,
                 "--out-dir", d])
        run([sys.executable, "-u", os.path.join(HERE, "..", "judge", "llm_judge_score.py"),
             "score", "--results-dir", d, "--arms", "irt_router", "--concurrency", "8"])

        rows = [json.loads(l) for l in open(rows_file, encoding="utf-8")]
        for r in rows:
            r["arm"] = "ml_router"
        sc = score_vs_partc(rows)
        jm, jn = judge_mean(d)
        dist = {}
        for r in rows:
            dist[r.get("routed_to")] = dist.get(r.get("routed_to"), 0) + 1
        table.append({"omega": om, "n": len(rows), "routing": dist,
                      "judge_mean": jm, "judge_n": jn,
                      "cosine": sc["fidelity"]["ml_router"]["cosine_score"],
                      "usd": sc["cost"]["ml_router"]["total_usd"]})
        json.dump({"identity": ident, "points": table}, open(os.path.join(out, "summary.json"), "w"), indent=2)

    # reference: glm-5.3 forced on every command (the true run)
    ref = []
    jf = glob.glob(os.path.join(args.true_dir, "judge", "*", "judge_scored_*.jsonl"))
    if jf:
        s = [r["judge_score"] for r in map(json.loads, open(jf[0], encoding="utf-8"))
             if isinstance(r.get("judge_score"), (int, float))]
        ref.append(("glm-5.3 forced on every command", sum(s) / len(s)))

    lines = [f"Onboarded {args.cloud_model} in the '{args.slot}' slot, vector fitted from "
             f"{args.budget} prompts; frozen network {os.path.relpath(args.config_dir, ROOT)}",
             "agents called live; judge = llm_judge_score.py (1-5); cosine = semantic score vs ground truth", "",
             f"{'omega':>6}{'cowrie':>8}{'on_dev':>8}{'cloud':>7}{'judge':>8}{'cosine':>8}{'usd':>9}"]
    for t in table:
        d = t["routing"]
        lines.append(f"{t['omega']:>6g}{d.get('cowrie', 0):>8}{d.get('on_device', 0):>8}{d.get('cloud', 0):>7}"
                     f"{(t['judge_mean'] or float('nan')):>8.2f}{t['cosine']:>8.3f}{t['usd']:>9.4f}")
    for name, m in ref:
        lines.append(f"reference: {name}: judge {m:.2f}")
    text = "\n".join(lines)
    open(os.path.join(out, "summary.txt"), "w").write(text + "\n")
    print("\n" + text)


if __name__ == "__main__":
    main()
