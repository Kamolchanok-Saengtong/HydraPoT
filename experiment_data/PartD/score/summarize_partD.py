"""
experiment_data/PartD/score/summarize_partD.py — Part D obfuscation results.

Part D asks what Bashfuscator-level-1 obfuscation does to the honeypot. Two
experiments, written by PartD/run/obfuscation_robustness.py, summarised here:

  routing-gap        results.json       where an obfuscated command ROUTES --
                                         how many real Cowrie-bound commands get
                                         escalated off Cowrie once obfuscated.
  cowrie-robustness  cowrie_success.json does COWRIE ITSELF still answer -- each
                                         obfuscated command forced to Cowrie,
                                         its reply compared to the dataset's
                                         ground truth.

Reads only what the run already wrote; nothing is recomputed. cowrie_success
.json is large (one row per command), so its aggregates are read from the head
of the file without loading the rows.

    python experiment_data/PartD/score/summarize_partD.py
"""
import argparse
import json
import os

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # PartD/
_REPO = os.path.join(_HERE, "..", "..")
OUT_DIR = os.path.join(_HERE, "..", "results", "partD", "obfuscation_robustness")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _read_aggregates(path):
    """Top-level scalar fields only, without loading the "rows" array.

    The writer puts every aggregate before "rows", so reading up to "rows":
    and closing the object gives the summary at a few KB instead of the file's
    full size (cowrie_success.json is ~160MB of per-command rows).
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read(1 << 20)          # 1 MB is far past the scalar header
    cut = text.find('"rows"')
    if cut == -1:
        return json.loads(text)          # no rows key -> small file, parse whole
    head = text[:cut].rstrip().rstrip(",")
    return json.loads(head + "}")


def _pct(num, denom):
    return 100 * num / denom if denom else 0.0


def summarize_routing_gap(path):
    """results.json: obfuscation pushes Cowrie-bound commands off Cowrie."""
    if not os.path.isfile(path):
        print(f"  (skipped: {os.path.relpath(path, _REPO)} not found)\n")
        return
    d = _read(path)
    total = d.get("total_variants", 0) or 1
    rc = d.get("route_counts", {})

    print("=" * 72)
    print("  ROUTING GAP -- where an obfuscated Cowrie-bound command routes")
    print("=" * 72)
    print(f"  baseline commands (real FI0, routed cowrie): {d.get('baseline_n')}")
    print(f"  variants per command:                        {d.get('variants_per_command')}")
    print(f"  Bashfuscator layers:                         {d.get('layers')}")
    print(f"  total obfuscated variants:                   {d.get('total_variants')}")
    print()
    print(f"  {'routed to':<14}{'count':>8}{'share':>9}")
    print("  " + "-" * 30)
    for arm, n in sorted(rc.items(), key=lambda kv: -kv[1]):
        print(f"  {arm:<14}{n:>8}{_pct(n, total):>8.1f}%")
    esc = d.get("escalated_off_cowrie", 0)
    cloud = d.get("escalated_to_cloud", 0)
    print()
    print(f"  escalated OFF Cowrie:     {esc}/{total}  ({_pct(esc, total):.1f}%)")
    print(f"  escalated to Cloud:       {cloud}/{total}  ({_pct(cloud, total):.1f}%)")
    print()


def summarize_cowrie_robustness(path):
    """cowrie_success.json: can Cowrie still answer the obfuscated command?"""
    if not os.path.isfile(path):
        print(f"  (skipped: {os.path.relpath(path, _REPO)} not found)\n")
        return
    d = _read_aggregates(path)
    sent = d.get("sent", 0) or 1
    match = d.get("match", 0)
    clean = d.get("gt_clean", 0)
    match_clean = d.get("match_given_gt_clean", 0)

    print("=" * 72)
    print("  COWRIE ROBUSTNESS -- does Cowrie answer the obfuscated command?")
    print("=" * 72)
    print(f"  dataset:            {d.get('dataset')}")
    print(f"  sessions replayed:  {d.get('sessions')}")
    print(f"  Bashfuscator layers:{d.get('layers')}")
    print(f"  commands sent:      {d.get('sent')}")
    if d.get("obfuscation_failed"):
        print(f"  could not obfuscate:{d.get('obfuscation_failed')}")
    print()
    print(f"  {'metric':<46}{'count':>9}{'rate':>9}")
    print("  " + "-" * 64)
    print(f"  {'matched ground truth (Cowrie handled it)':<46}"
          f"{match:>9}{_pct(match, sent):>8.1f}%")
    print(f"  {'...where plain answer is a real response':<46}"
          f"{match_clean:>9}/{clean:<3}{_pct(match_clean, clean):>5.1f}%")
    print()
    failed = sent - match
    print(f"  Cowrie FAILED on {failed}/{sent} obfuscated commands "
          f"({_pct(failed, sent):.1f}%).")
    if match_clean == 0 and clean:
        print(f"  Of the {clean} commands that should give a real answer, "
              f"Cowrie got 0 right.")
    print()


# Each PartD experiment: label -> (output file, summarize function).
EXPERIMENTS = {
    "routing-gap": ("results.json", summarize_routing_gap),
    "cowrie-robustness": ("cowrie_success.json", summarize_cowrie_robustness),
}


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", choices=sorted(EXPERIMENTS),
                    help="summarise just one experiment (default: all)")
    ap.add_argument("--dir", default=OUT_DIR,
                    help="folder holding the result files "
                         "(default: results/partD/obfuscation_robustness)")
    args = ap.parse_args()

    chosen = [args.only] if args.only else list(EXPERIMENTS)
    for label in chosen:
        fname, fn = EXPERIMENTS[label]
        fn(os.path.join(args.dir, fname))


if __name__ == "__main__":
    main()
