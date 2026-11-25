"""All metrics per omega for the live onboarding run, plus a per-command file with the ground truth.

    python experiment_data/PartC/run/onboard_live_table.py
"""
import csv, glob, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "score"), ROOT]
from score_all_metrics import _fast_metrics, METRICS  # noqa: E402

D = os.path.join(ROOT, "experiment_data", "results", "partC_onboarding", "live_no_benchmark_60prompts")
KS = [(k, l) for k, l in METRICS if k != "bert_f1"]
OM = sorted(float(os.path.basename(p)[6:]) for p in glob.glob(os.path.join(D, "omega_*")))

rows_out, table = [], []
for om in OM:
    d = os.path.join(D, f"omega_{om}")
    rows = [json.loads(l) for l in open(os.path.join(d, "irt_router.jsonl"), encoding="utf-8")]
    judge = {}
    jf = glob.glob(os.path.join(d, "judge", "irt_router", "judge_scored_*.jsonl"))
    if jf:
        for r in map(json.loads, open(jf[0], encoding="utf-8")):
            judge[(str(r.get("session_id")), r.get("position_in_session"))] = r.get("judge_score")
    acc = {k: [] for k, _ in KS}; js = []
    for r in rows:
        fm = _fast_metrics(r.get("response"), r.get("ground_truth"))
        for k, _ in KS:
            acc[k].append(fm[k])
        j = judge.get((str(r["session_id"]), r["position_in_session"]))
        if isinstance(j, (int, float)):
            js.append(j)
        rows_out.append({"omega": om, "session": r["session_id"], "pos": r["position_in_session"],
                         "routed_to": r["routed_to"], "command": r["cmd"],
                         "ground_truth": r["ground_truth"], "response": r["response"],
                         "judge": j, **{k: round(fm[k], 4) for k, _ in KS}})
    table.append((om, len(rows), {k: sum(v) / len(v) for k, v in acc.items()}, sum(js) / len(js) if js else float("nan")))

head = f"{'omega':>6}{'n':>6}" + "".join(f"{l.split(' (')[0][:11]:>13}" for _, l in KS) + f"{'judge(1-5)':>12}"
print(head)
for om, n, m, j in table:
    print(f"{om:>6g}{n:>6}" + "".join(f"{m[k]:>13.3f}" for k, _ in KS) + f"{j:>12.2f}")
print("(BERTScore left out: it needs the GPU, which is busy)")

out = os.path.join(D, "per_command_vs_ground_truth.jsonl")
with open(out, "w", encoding="utf-8") as fh:
    for r in rows_out:
        fh.write(json.dumps(r, ensure_ascii=False) + "\n")
print("per-command file:", os.path.relpath(out, ROOT))
