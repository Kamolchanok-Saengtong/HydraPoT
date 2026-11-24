"""experiment_data/guardrail/show_tables.py -- print the validator and detector tables from the saved CSVs.

    python experiment_data/guardrail/show_tables.py
"""
import csv, glob, os, collections
R = "experiment_data/guardrail/results"
T = ("true", "1")
print("VALIDATOR: persona breaks (model answered as an AI)   guard off -> on")
print(f"{'model':10}{'dataset':20}{'n':>5}{'broke 1st try off':>20}{'on':>5}{'after retry off':>18}{'on':>5}")
for f in sorted(glob.glob(f"{R}/validator/*.csv")):
    b = os.path.basename(f)[len("validator_"):-4]
    model = "on_device" if b.startswith("on_device") else "cloud"
    data = b[len(model) + 1:]
    g = collections.defaultdict(lambda: [0, 0, 0, False])
    for x in csv.DictReader(open(f)):
        a = g[x["guard"]]; a[0] += 1
        a[1] += x["broke_first"].lower() in T
        if "broke_retry" in x:
            a[2] += x["broke_retry"].lower() in T; a[3] = True
    off, on = g["off"], g["on"]
    rt = (lambda a: a[2]) if off[3] else (lambda a: "-")
    print(f"{model:10}{data:20}{off[0]:>5}{off[1]:>20}{on[1]:>5}{rt(off):>18}{rt(on):>5}")
print("\nDETECTOR RECALL (score >= 0.5)")
for f in sorted(glob.glob(f"{R}/detector/*.csv")):
    rows = list(csv.DictReader(open(f))); c = collections.defaultdict(lambda: [0, 0])
    for x in rows:
        c[x["category"]][0] += float(x["score"]) >= 0.5; c[x["category"]][1] += 1
    hit = sum(v[0] for v in c.values())
    print(f"{os.path.basename(f)[9:-4]:20} {hit}/{len(rows)} = {hit/len(rows):.1%}")
    for k, v in c.items():
        if len(c) > 1: print(f"   {k:24}{v[0]}/{v[1]}")
