"""
threat_intel/validate_rules.py — score every mapper rule against an external
reference so "is this rule trustworthy?" has a reproducible answer.

Reference corpus
----------------
Red Canary's Atomic Red Team publishes executable tests for ATT&CK techniques,
each labelled with its official technique ID and supported platforms. The
combined index (atomics/Indexes/index.yaml) carries the actual command for
every test, which makes it the closest thing to ground truth that exists for
"what does technique T look like as a shell command on Linux".

We keep only tests whose executor is sh/bash and whose supported_platforms
includes linux — 482 tests across 116 techniques at time of writing.

What is measured
----------------
For each technique T that one of our rules targets:

  detection rate  of ART's Linux tests labelled T, how many did we tag T?
                  This is a clean recall figure: ART says these commands ARE
                  technique T, so failing to tag them is unambiguously a miss.

  cross-tags      how often we put T on a test ART labelled something else.

Cross-tags are reported but deliberately NOT called false positives. ART labels
a test by the technique it was written to demonstrate, not by every technique
the command exhibits — an ART T1082 test that runs `ls -la` really does perform
file discovery, so our T1083 tag on it is correct, not an error. The examples
are printed so a human can judge. A rule with a high cross-tag rate AND a low
detection rate is the genuinely suspicious combination.

Caveats worth stating in any write-up
-------------------------------------
  * ART is a corpus of *tests*, not captured attacker traffic. It is biased
    toward clean, canonical forms of each technique.
  * A technique with no Linux atomics cannot be validated here at all; those
    rules are reported UNVALIDATED rather than silently passed.
  * Detection rate on ART is not the same as precision on live honeypot data.
    Both numbers are reported; neither substitutes for the other.

Usage
-----
    python threat_intel/validate_rules.py              # cached ART, full report
    python threat_intel/validate_rules.py --refresh    # re-download ART first
    python threat_intel/validate_rules.py --json out.json
    python threat_intel/validate_rules.py --corpus     # also fire rules at the honeypot DB
"""

import argparse
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

from threat_intel.mitre_mapper import (  # noqa: E402
    load_rules, load_errors, classify_all, tag_all,
)

ART_URL = ("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
           "master/atomics/Indexes/index.yaml")
CACHE_DIR  = os.path.join(_HERE, ".art_cache")
ART_CACHE  = os.path.join(CACHE_DIR, "art_index.yaml")

# thresholds for the verdict column
GOOD_DETECTION = 0.70
WEAK_DETECTION = 0.30
HIGH_CROSS     = 0.25


# ── reference corpus ─────────────────────────────────────────────────────────

def fetch_art(refresh: bool = False) -> str:
    """Return a path to the ART index, downloading it once and caching."""
    if os.path.exists(ART_CACHE) and not refresh:
        return ART_CACHE
    os.makedirs(CACHE_DIR, exist_ok=True)
    import urllib.request
    print(f"[validate] downloading Atomic Red Team index…")
    with urllib.request.urlopen(ART_URL, timeout=120) as r:
        data = r.read()
    with open(ART_CACHE, "wb") as f:
        f.write(data)
    print(f"[validate] cached {len(data)/1e6:.1f} MB -> {ART_CACHE}")
    return ART_CACHE


_PLACEHOLDER = re.compile(r"#\{([^}]+)\}")


def _fill_placeholders(cmd: str, inputs: dict) -> str:
    """ART commands template their arguments as #{name}. Substitute the test's
    own documented default so the command reads like something a real operator
    would run; fall back to the bare name when no default is given."""
    def sub(m):
        key = m.group(1)
        spec = (inputs or {}).get(key) or {}
        val = spec.get("default")
        return str(val) if val not in (None, "") else key
    return _PLACEHOLDER.sub(sub, cmd)


def load_art_linux(path: str) -> list:
    """[{technique, tactic, test, command}] for Linux sh/bash atomics.

    Multi-line commands are split into individual lines: each line is a command
    the test actually runs, and our mapper works per command, not per script.
    """
    import yaml
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)

    out = []
    for tactic, techniques in (doc or {}).items():
        if not isinstance(techniques, dict):
            continue
        for tid, node in techniques.items():
            if not isinstance(node, dict):
                continue
            for test in node.get("atomic_tests") or []:
                ex = test.get("executor") or {}
                plats = [p.lower() for p in (test.get("supported_platforms") or [])]
                if ex.get("name") not in ("sh", "bash") or "linux" not in plats:
                    continue
                raw = ex.get("command") or ""
                filled = _fill_placeholders(raw, test.get("input_arguments"))
                for line in filled.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    out.append({"technique": tid, "tactic": tactic,
                                "test": test.get("name", ""), "command": line})
    return out


# ── scoring ──────────────────────────────────────────────────────────────────

def evaluate(art_rows: list) -> dict:
    """Score each technique we target against ART.

    Scoring is per TEST, not per line. An atomic test is one labelled unit that
    may span many lines — a T1543.002 test spends most of its lines echoing a
    unit file into place (`echo "Type=simple"`), and only one line actually
    installs the service. Scoring line-by-line would count every setup line as
    a missed detection and make a correct rule look broken, so a test counts as
    detected when ANY of its lines carries the technique.

    Cross-tags stay line-level: there the question is "how often does this rule
    fire on something ART labelled differently", which is a per-command
    property.
    """
    rules = load_rules()
    targeted = sorted({r.technique for r in rules})

    # one pass over the corpus; store the full multi-tag result per line
    tagged = [(row, set(classify_all(row["command"]))) for row in art_rows]

    # regroup lines into the tests they came from
    tests = {}
    for row, tags in tagged:
        key = (row["technique"], row["test"])
        t = tests.setdefault(key, {"technique": row["technique"],
                                   "test": row["test"], "tags": set(),
                                   "lines": []})
        t["tags"] |= tags
        t["lines"].append(row["command"])

    art_techniques = {r["technique"] for r in art_rows}
    results = {}
    for tid in targeted:
        truth = [t for t in tests.values() if t["technique"] == tid]
        hit   = [t for t in truth if tid in t["tags"]]
        miss  = [t for t in truth if tid not in t["tags"]]
        cross = [(r, s) for r, s in tagged if r["technique"] != tid and tid in s]

        results[tid] = {
            "technique": tid,
            "art_available": tid in art_techniques,
            "art_total": len(truth),
            "art_lines": sum(len(t["lines"]) for t in truth),
            "detected": len(hit),
            "detection_rate": (len(hit) / len(truth)) if truth else None,
            "cross_tags": len(cross),
            "cross_rate": (len(cross) / max(1, len(tagged))),
            "miss_examples": [f"{t['test'][:44]} :: {t['lines'][0][:60]}"
                              for t in miss[:3]],
            "cross_examples": [f"[{r['technique']}] {r['command'][:80]}"
                               for r, _ in cross[:3]],
        }

    for tid, res in results.items():
        res["verdict"] = _verdict(res)
    return {"results": results, "corpus_size": len(art_rows),
            "tests": len(tests), "art_techniques": len(art_techniques)}


def _verdict(res: dict) -> str:
    if not res["art_available"] or res["art_total"] == 0:
        return "UNVALIDATED"
    dr = res["detection_rate"]
    if dr >= GOOD_DETECTION:
        return "GOOD" if res["cross_rate"] < HIGH_CROSS else "GOOD/NOISY"
    if dr >= WEAK_DETECTION:
        return "PARTIAL"
    return "SUSPECT" if res["cross_tags"] else "MISSES"


# ── honeypot corpus context ──────────────────────────────────────────────────

def corpus_stats() -> dict:
    """How often each rule actually fires on the honeypot's own data.

    A rule can score well on ART and never fire here (or the reverse); both
    facts matter when deciding whether to trust it.
    """
    import storage
    rows = storage.query_all_df().to_dict("records")
    cmds = [(r.get("cmd") or "").strip() for r in rows]
    uniq = [c for c in dict.fromkeys(cmds) if c]

    per_tech_rows, per_tech_uniq = {}, {}
    lut = {c: classify_all(c) for c in uniq}
    for c in uniq:
        for t in lut[c]:
            per_tech_uniq[t] = per_tech_uniq.get(t, 0) + 1
    for c in cmds:
        for t in lut.get(c, ()):
            per_tech_rows[t] = per_tech_rows.get(t, 0) + 1

    tagged_rows = sum(1 for c in cmds if c and lut.get(c))
    return {"rows": len(cmds), "unique": len(uniq),
            "tagged_rows": tagged_rows,
            "coverage_rows": tagged_rows / max(1, len([c for c in cmds if c])),
            "per_technique_rows": per_tech_rows,
            "per_technique_unique": per_tech_uniq}


# ── report ───────────────────────────────────────────────────────────────────

def print_report(ev: dict, corpus: dict = None):
    results = ev["results"]
    print("=" * 78)
    print("MITRE RULE VALIDATION — Atomic Red Team (Linux sh/bash atomics)")
    print("=" * 78)
    print(f"reference corpus : {ev['corpus_size']} command lines in {ev['tests']} tests, "
          f"{ev['art_techniques']} techniques")
    print(f"rules loaded     : {len(load_rules())} "
          f"targeting {len(results)} techniques")
    errs = load_errors()
    if errs:
        print(f"rule load errors : {len(errs)}")
        for rel, msg in errs:
            print(f"    {rel}: {msg}")
    print()

    order = {"SUSPECT": 0, "MISSES": 1, "PARTIAL": 2, "GOOD/NOISY": 3,
             "GOOD": 4, "UNVALIDATED": 5}
    rows = sorted(results.values(), key=lambda r: (order.get(r["verdict"], 9),
                                                   -(r["detection_rate"] or 0)))

    print(f"  {'TECHNIQUE':<12} {'VERDICT':<12} {'DETECT':>8} {'TESTS':>6} "
          f"{'CROSS':>6}   NOTE")
    print("  " + "-" * 74)
    for r in rows:
        dr = "   n/a" if r["detection_rate"] is None else f"{r['detection_rate']*100:5.0f}%"
        note = ""
        if r["verdict"] == "UNVALIDATED":
            note = "no Linux atomics for this technique"
        elif r["miss_examples"]:
            note = "misses: " + r["miss_examples"][0][:38]
        print(f"  {r['technique']:<12} {r['verdict']:<12} {dr:>8} "
              f"{r['art_total']:>5} {r['cross_tags']:>6}   {note}")

    flagged = [r for r in rows if r["verdict"] in ("SUSPECT", "MISSES", "PARTIAL")]
    if flagged:
        print("\n" + "-" * 78)
        print("RULES NEEDING REVIEW")
        print("-" * 78)
        for r in flagged:
            print(f"\n{r['technique']}  [{r['verdict']}]  "
                  f"detected {r['detected']}/{r['art_total']}")
            for m in r["miss_examples"]:
                print(f"    MISSED  {m}")
            for c in r["cross_examples"]:
                print(f"    CROSS   {c}")

    unval = [r for r in rows if r["verdict"] == "UNVALIDATED"]
    if unval:
        print("\n" + "-" * 78)
        print(f"UNVALIDATED ({len(unval)}) — no external reference exists, "
              "these rest on our judgement alone:")
        print("    " + ", ".join(r["technique"] for r in unval))

    if corpus:
        print("\n" + "=" * 78)
        print("HONEYPOT CORPUS — how often each rule actually fires")
        print("=" * 78)
        print(f"  {corpus['rows']} rows, {corpus['unique']} unique commands, "
              f"coverage {corpus['coverage_rows']*100:.1f}% of rows")
        per = corpus["per_technique_rows"]
        never = [t for t in results if t not in per]
        print(f"\n  {'TECHNIQUE':<12} {'ROWS':>8} {'UNIQUE':>8}   VERDICT")
        for t, n in sorted(per.items(), key=lambda kv: -kv[1]):
            print(f"  {t:<12} {n:>8} {corpus['per_technique_unique'].get(t,0):>8}"
                  f"   {results.get(t,{}).get('verdict','-')}")
        if never:
            print(f"\n  never fires on this corpus: {', '.join(sorted(never))}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh", action="store_true",
                    help="re-download the Atomic Red Team index")
    ap.add_argument("--corpus", action="store_true",
                    help="also report how often each rule fires on the honeypot DB")
    ap.add_argument("--json", metavar="PATH", help="write the full result as JSON")
    args = ap.parse_args()

    art_path = fetch_art(args.refresh)
    art_rows = load_art_linux(art_path)
    if not art_rows:
        print("[validate] ERROR: no Linux atomics parsed — the ART index format "
              "may have changed. Re-run with --refresh, and check load_art_linux().")
        return 1

    ev = evaluate(art_rows)
    corpus = corpus_stats() if args.corpus else None
    print_report(ev, corpus)

    if args.json:
        payload = {"evaluation": ev, "corpus": corpus}
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        print(f"\n[validate] wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
