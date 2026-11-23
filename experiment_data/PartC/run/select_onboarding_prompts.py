"""
experiment_data/PartC/run/select_onboarding_prompts.py -- pick the prompts a new model is fitted on.

Uses the production network and the three existing arms (nothing about the new model),
through honeyrouter/onboarding.py, so the same set serves every later model and every
experiment. Writes ONE file: partC_onboarding/selected_prompts.json.

    python experiment_data/PartC/run/select_onboarding_prompts.py
"""
import json
import os
import sys

import numpy as np
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, ROOT)

from honeyrouter import onboarding as OB                     # noqa: E402
from honeyrouter import predictor as P                       # noqa: E402
from honeyrouter.sessions import load_sessions               # noqa: E402

BASE = os.path.join(ROOT, "experiment_data", "results", "partC_onboarding")
N_FIT, N_CHECK, STRATA = 50, 10, 5


def main():
    model, meta = P.load()
    E, Y, raw, sids, eta = P.build_dataset()
    tr, va = P.split_by_session(sids, seed=0)
    rows = [(sid, pos, c["cmd"]) for sid, cmds in load_sessions().items() for pos, c in enumerate(cmds)]
    pool = np.flatnonzero(tr)
    texts = [rows[i][2] for i in pool]

    psi = OB.discrimination(model, torch.tensor(E[pool]), torch.tensor(Y[pool]))
    fit = OB.stratified_select(psi, N_FIT, n_strata=STRATA, seed=0, groups=texts)
    chk = OB.stratified_select(psi, N_CHECK, n_strata=STRATA, seed=1, groups=texts, exclude=fit)
    stratum = np.empty(len(psi), dtype=int)
    for s, part in enumerate(np.array_split(np.argsort(psi, kind="stable"), STRATA), start=1):
        stratum[part] = s

    def rec(i):
        sid, pos, cmd = rows[pool[i]]
        return {"session_id": str(sid), "position_in_session": pos, "cmd": cmd,
                "psi": round(float(psi[i]), 4), "stratum": int(stratum[i])}

    out = {"formula": "psi_n = mean over existing arms k of BCE(p_kn, y_kn)   (LLM Bandit Eq. 7)",
           "existing_arms": list(meta["agents"]), "n_strata": STRATA,
           "pool": f"{len(pool)} commands from training sessions",
           "fit_prompts": [rec(i) for i in fit], "check_prompts": [rec(i) for i in chk],
           "heldout_session_ids": sorted({str(s) for s in sids[va]})}
    os.makedirs(BASE, exist_ok=True)
    with open(os.path.join(BASE, "selected_prompts.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)
    print(f"pool {len(pool)} training commands, psi {psi.min():.3f}..{psi.max():.3f}, mean {psi.mean():.3f}")
    counts = np.bincount([r["stratum"] for r in out["fit_prompts"]], minlength=STRATA + 1)[1:]
    print(f"chosen {len(fit)} fit + {len(chk)} check prompts; per stratum (easy->hard): {counts.tolist()}")
    print("examples:")
    for r in out["fit_prompts"][:8]:
        print(f"  stratum {r['stratum']}  psi {r['psi']:.3f}  {r['cmd'][:60]}")


if __name__ == "__main__":
    main()
