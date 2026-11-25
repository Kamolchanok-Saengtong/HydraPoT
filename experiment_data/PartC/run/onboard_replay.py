"""
experiment_data/PartC/run/onboard_replay.py -- the omega sweep for two glm-5.3 vectors, side by side.

    full  : the vector fitted on ALL labelled training commands (the "true" glm-5.3 vector)
    60    : the vector fitted on 60 prompts (the one the live run used)

For each omega the frozen policy picks an agent per command. The picked agent's answer is
taken from a run that already happened: Cowrie and on-device from the fidelity run, glm-5.3
from the true run (glm-5.3 on every command). Nothing is called live, so the two vectors
are compared on exactly the same answers. Scored with the same metrics and the same judge.

    CUDA_VISIBLE_DEVICES= python experiment_data/PartC/run/onboard_replay.py
"""
import glob
import json
import os
import sys
from multiprocessing import Pool

import numpy as np
import torch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path[:0] = [ROOT, HERE, os.path.join(HERE, "..", "score")]

RES = os.path.join(ROOT, "experiment_data", "results")
LIVE = os.path.join(RES, "partC_onboarding", "live_no_benchmark_60prompts")
TRUE = os.path.join(RES, "partC_onboarding", "glm-5.3_true_run")
FID = os.path.join(RES, "partC", "fidelity")
CONFIG = os.path.join(RES, "partC_ml_router", "bench+2learn+net")
OMEGAS = [0, 0.1, 0.2, 0.25, 0.5, 1.0, 2.0]
KS = ["cosine_score", "levenshtein_score", "jaro_winkler_score", "sequence_score", "bleu_score", "exact_match"]
key = lambda r: (str(r["session_id"]), int(r["position_in_session"]))


def fit_full_vector(path):
    import onboard_new_model as ONM
    import onboarding as OB
    from honeyrouter import predictor as P
    from honeyrouter.action import AGENTS
    from honeyrouter.sessions import load_sessions
    k = AGENTS.index("cloud")
    E, Y_old, raw_old, sids, eta = P.build_dataset()
    sess = load_sessions()
    keys = [(str(s), int(c["position"])) for s, cmds in sess.items() for c in cmds]
    true = ONM.load_true_scores(TRUE)
    valid = np.array([kk in true for kk in keys])
    raw = np.array([true.get(kk, np.nan) for kk in keys])
    y = torch.tensor(((np.clip((raw - 1.0) / 4.0, 0.0, 1.0)) > eta).astype(np.float32))
    model, _ = P.load()
    tr, _ = P.split_by_session(sids, seed=0)
    trn = np.flatnonzero(tr & valid)
    mean_existing = model.mu.detach().mean(0)
    g = torch.Generator().manual_seed(1000)                       # same start as exp B, seed 0
    s0 = mean_existing + 0.1 * torch.randn(mean_existing.shape[0], generator=g)
    I = OB.fit_identity(model, torch.tensor(E)[trn], y[trn], s0)
    vec = [round(float(x), 5) for x in I]
    json.dump({"slot": "cloud", "vector": vec, "fitted_on": f"all {len(trn)} labelled training commands"},
              open(path, "w"), indent=2)
    return vec


def _score(args):
    resp, gt = args
    from score_all_metrics import _fast_metrics
    fm = _fast_metrics(resp, gt)
    return [fm[k] for k in KS]


def main():
    cloud = {key(r): r for r in map(json.loads, open(os.path.join(TRUE, "cloud.jsonl"), encoding="utf-8"))}
    arms = {"cloud": cloud}
    for a in ("cowrie", "on_device"):
        arms[a] = {key(r): r for r in map(json.loads, open(os.path.join(FID, f"{a}.jsonl"), encoding="utf-8"))}
    judge = {}
    for a, d in (("cloud", os.path.join(TRUE, "judge", "cloud")),
                 ("cowrie", os.path.join(FID, "judge", "cowrie")),
                 ("on_device", os.path.join(FID, "judge", "on_device"))):
        f = sorted(glob.glob(os.path.join(d, "judge_scored_*.jsonl")))[0]
        judge[a] = {key(r): r["judge_score"] for r in map(json.loads, open(f, encoding="utf-8"))
                    if isinstance(r.get("judge_score"), (int, float))}
    live = [json.loads(l) for l in open(os.path.join(LIVE, "omega_0.0", "irt_router.jsonl"), encoding="utf-8")]
    keys = [key(r) for r in live if all(key(r) in arms[a] for a in arms)]
    cmd_of = {key(r): r["cmd"] for r in live}
    gt_of = {key(r): r["ground_truth"] for r in live}
    print(f"{len(keys)} commands, same answers for every vector", flush=True)

    full_path = os.path.join(LIVE, "identity_full.json")
    if not os.path.isfile(full_path):
        print("fitted full vector:", fit_full_vector(full_path), flush=True)
    vectors = {"full (all labels)": full_path, "60 prompts": os.path.join(LIVE, "identity.json")}

    jobs = [(arms[a][kk].get("response"), gt_of[kk]) for a in arms for kk in keys]
    with Pool(12) as p:
        flat = p.map(_score, jobs, chunksize=64)
    met, i = {}, 0
    for a in arms:
        for kk in keys:
            met[(a, kk)] = flat[i]
            i += 1

    def agg(pick):
        m = np.mean([met[(pick[kk], kk)] for kk in keys], axis=0)
        j = [judge[pick[kk]][kk] for kk in keys if kk in judge[pick[kk]]]
        return m, float(np.mean(j))

    from irt_router_live import IrtRouter
    head = f"{'':<22}{'cowrie':>7}{'on_dev':>7}{'cloud':>6}" + "".join(
        f"{n:>9}" for n in ("cosine", "lev", "jaro", "seq", "bleu", "exact")) + f"{'judge':>7}"
    lines = [head]

    def row(label, pick):
        c = {a: sum(1 for kk in keys if pick[kk] == a) for a in arms}
        m, j = agg(pick)
        lines.append(f"{label:<22}{c['cowrie']:>7}{c['on_device']:>7}{c['cloud']:>6}"
                     + "".join(f"{x:>9.3f}" for x in m) + f"{j:>7.2f}")

    row("glm-5.3 on every cmd", {kk: "cloud" for kk in keys})
    for name, path in vectors.items():
        lines.append(f"-- vector: {name}")
        for om in OMEGAS:
            r = IrtRouter(CONFIG, which="rl", omega=om, identity_file=path)
            row(f"  omega {om:g}", {kk: r.pick(cmd_of[kk]) for kk in keys})
    text = "\n".join(lines)
    open(os.path.join(LIVE, "replay_full_vs_60.txt"), "w").write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
