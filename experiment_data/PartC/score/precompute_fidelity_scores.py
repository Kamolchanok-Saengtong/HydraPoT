"""Precompute per-row fidelity metrics for the big arm files so the omega sweep
reads cached scores instead of recomputing them for every omega point.
Same _fast_metrics() the sweep scores with -- no BERTScore, CPU only."""
import os
import sys
import json
import argparse

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                       # score_all_metrics is a sibling
from score_all_metrics import _fast_metrics      # noqa: E402

ARMS = ("cowrie", "on_device", "cloud", "honeyrouter")


def score_file(src, dst):
    n = kept = 0
    with open(src, encoding="utf-8") as fin, open(dst, "w", encoding="utf-8") as fout:
        for line in fin:
            r = json.loads(line)
            n += 1
            resp, gt = r.get("response"), r.get("ground_truth")
            # leave unscorable rows untouched; the sweep's _load_valid skips them
            if (gt is not None and resp is not None and r.get("ok")
                    and not (isinstance(resp, str) and resp.startswith("[cloud error"))):
                r.update(_fast_metrics(resp, gt))
                kept += 1
            fout.write(json.dumps(r) + "\n")
    print(f"  {os.path.basename(src):<16} {kept}/{n} scored -> {os.path.basename(dst)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fidelity-dir", required=True,
                    help="e.g. experiment_data/results/partC/fidelity_50000")
    ap.add_argument("--out-dir", default=None,
                    help="where to write the <arm>.scored.jsonl files. Default: "
                         "results/partC/semantic_analysis/<fidelity-dir-name>/ "
                         "so scored output lives with the other metric "
                         "artifacts, not beside the raw generations.")
    a = ap.parse_args()

    out_dir = a.out_dir
    if out_dir is None:
        _HERE = os.path.dirname(os.path.abspath(__file__))        # .../PartC/score
        _RESULTS = os.path.join(_HERE, "..", "..", "results", "partC")
        out_dir = os.path.normpath(os.path.join(
            _RESULTS, "semantic_analysis",
            os.path.basename(os.path.normpath(a.fidelity_dir))))
    os.makedirs(out_dir, exist_ok=True)
    print(f"  out -> {out_dir}")

    for arm in ARMS:
        src = os.path.join(a.fidelity_dir, f"{arm}.jsonl")
        if not os.path.exists(src):
            print(f"  skip {arm}: {src} missing")
            continue
        score_file(src, os.path.join(out_dir, f"{arm}.scored.jsonl"))


if __name__ == "__main__":
    main()
