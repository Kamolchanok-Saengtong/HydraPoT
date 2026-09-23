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
import collections
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
# NO GRADING THRESHOLDS. Atomic Red Team IS the baseline: it says these
# commands ARE technique T, so the only honest figure is "of ART's atomics for
# T, how many did we tag T". A cut-off like "70% = GOOD" would be a number we
# invented, and a verdict resting on it would measure our own generosity.


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
    """[{technique, tactic, test, executor, command}] for Linux sh/bash atomics.

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
                    # rstrip only: a LEADING space can itself be the technique
                    # (T1070.003), so stripping both ends would destroy it.
                    line = line.rstrip()
                    if not line.strip() or line.strip().startswith("#"):
                        continue
                    out.append({"technique": tid, "tactic": tactic,
                                "test": test.get("name", ""),
                                "description": test.get("description", ""),
                                "executor": ex.get("name", ""), "command": line})
    return out


# ── what HydraPoT can possibly observe ──────────────────────────────────────
# ART is a test suite for fully instrumented endpoints. HydraPoT sees ONE
# thing: the text of a command typed into an SSH session. It has no process
# tree, no file-content monitor, no network flow, no GUI and no second host.
#
# Scoring those atomics as misses measures the sensor, not the rules -- and
# quietly rewards writing patterns for commands that can never arrive. So each
# test is classified first, the reason is printed, and BOTH rates are reported:
# raw (every Linux atomic) and in-scope (the ones a shell sensor could see).
#
# The rules below are deliberately about the ATOMIC's requirements, never
# about whether we happen to detect it. Nothing here may reference our own
# rule set; if it did, the scope would shrink to fit the score.

OUT_OF_SCOPE = (
    ("gui",
     r"\b(?:xwd|xwud|xdotool|scrot|import\s+-window|gnome-screenshot|"
     r"xrandr|Xvfb|DISPLAY=)",
     "needs an X11 session; an SSH honeypot has no display"),
    ("compiled-artifact",
     r"PathToAtomicsFolder/\S+/(?:bin|src)/|\bgcc\b|\bg\+\+\b|\bmake\b\s|"
     r"\.c\b|\.so\b\s*$|/tmp/T\d{4}\d*(?:own)?\s",
     "runs a binary compiled from the ART repo, not a shell command"),
    ("cloud-api",
     r"^\s*(?:aws|az|gcloud|oci|kubectl|stratus|doctl|ibmcloud)\s",
     "calls a cloud provider API with credentials the honeypot has none of"),
    ("windows-tooling",
     r"\bpsexec\b|\.exe\b|\.ps1\b|powershell|\bwmic\b",
     "Windows tooling invoked through sh"),
    ("second-host",
     r"\bsshpass\b|@localhost|\bexpect\s+-c|\bdocker\s+(?:run|exec|container)",
     "needs a second reachable host or container runtime"),
    ("non-command-telemetry",
     r"/proc/\d+/(?:maps|mem)\b|\bptrace\b|\bgcore\b|\bLD_PRELOAD=\S+\s+\S|"
     r"\bprctl\b|\btcpdump\b|\btshark\b",
     "the effect is only visible in memory or packet capture, not in the command"),
)

_SCOPE_RE = [(name, re.compile(pat, re.I), why) for name, pat, why in OUT_OF_SCOPE]


# A test whose DESCRIPTION names a characteristic its own `command` field does
# not contain. ART's index stores the commands to run, not how to type them, so
# where the technique IS the typing the index cannot express it.
#
# Narrow on purpose: the description must name the characteristic AND the
# command must provably lack it. This is a property of ART's data, checkable by
# anyone with the index -- not a judgement about our rules.
_DESC_NOT_IN_COMMAND = (
    (r"space before|leading space|prepend(?:ing)? a space",
     lambda lines: not any(l[:1] in (" ", "\t") for l in lines),
     "ART's command field omits the leading space that IS this technique"),
)


def unexpressed(description: str, lines) -> str:
    """Reason this test cannot be measured from ART's index, or ""."""
    d = description or ""
    for pat, missing, why in _DESC_NOT_IN_COMMAND:
        if re.search(pat, d, re.I) and missing(lines):
            return why
    return ""


def scope_of(lines) -> tuple:
    """(in_scope: bool, reason: str) for one atomic test's command lines.

    A test is OUT of scope only when EVERY line that does real work is out of
    scope. One unobservable line in an otherwise shell-based test does not
    excuse the test -- the observable lines still had their chance.
    """
    verdicts = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        hit = next(((n, w) for n, rx, w in _SCOPE_RE if rx.search(stripped)), None)
        verdicts.append(hit)
    if not verdicts:
        return True, ""
    if all(v is not None for v in verdicts):
        return False, verdicts[0][1]
    return True, ""


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
        # Deliberately NOT keyed on tactic. ART's index nests tests under
        # doc[tactic][technique], so a technique belonging to two tactics has
        # its tests listed twice (T1497.001 appears under both discovery and
        # stealth). 63 such pairs exist and all use the same executor, so those
        # 87 listings are 87 duplicates, not distinct tests. Keying on
        # (technique, name, executor) collapses them correctly: 482 -> 395.
        key = (row["technique"], row["test"], row.get("executor", ""))
        t = tests.setdefault(key, {"technique": row["technique"],
                                   "test": row["test"], "tags": set(),
                                   "lines": []})
        t["tags"] |= tags
        t["lines"].append(row["command"])
        t.setdefault("description", row.get("description", ""))

    # Classify each test against what a shell sensor can observe, BEFORE any
    # scoring, so the in-scope rate cannot be shaped by what we detect.
    for t in tests.values():
        why = unexpressed(t.get("description", ""), t["lines"])
        if why:
            t["in_scope"], t["out_reason"] = False, why
        else:
            t["in_scope"], t["out_reason"] = scope_of(t["lines"])

    art_techniques = {r["technique"] for r in art_rows}
    results = {}
    scope_counts = collections.Counter(
        "in" if t["in_scope"] else t["out_reason"] for t in tests.values())
    for tid in targeted:
        truth = [t for t in tests.values() if t["technique"] == tid]
        scoped = [t for t in truth if t["in_scope"]]
        hit   = [t for t in truth if tid in t["tags"]]
        miss  = [t for t in truth if tid not in t["tags"]]
        s_hit = [t for t in scoped if tid in t["tags"]]
        cross = [(r, s) for r, s in tagged if r["technique"] != tid and tid in s]
        in_scope_lines = [(r, s) for r, s in tagged
                          if tests.get((r["technique"], r["test"],
                                        r.get("executor", "")), {}).get("in_scope", True)]
        cross_in = [(r, s) for r, s in in_scope_lines
                    if r["technique"] != tid and tid in s]

        results[tid] = {
            "technique": tid,
            "art_available": tid in art_techniques,
            "art_total": len(truth),
            "art_lines": sum(len(t["lines"]) for t in truth),
            "detected": len(hit),
            "detection_rate": (len(hit) / len(truth)) if truth else None,
            # In-scope = atomics a shell sensor could observe at all. This is
            # the rate that measures the RULES; the raw one above also
            # measures the sensor.
            "in_scope_total": len(scoped),
            "in_scope_detected": len(s_hit),
            "in_scope_rate": (len(s_hit) / len(scoped)) if scoped else None,
            "out_of_scope": len(truth) - len(scoped),
            "out_reasons": sorted({t["out_reason"] for t in truth
                                   if not t["in_scope"]}),
            "cross_tags": len(cross_in),
            # Denominator matches the grade this feeds: in-scope lines only.
            "cross_rate": (len(cross_in) / max(1, len(in_scope_lines))),
            "miss_examples": [f"{t['test'][:44]} :: {t['lines'][0][:60]}"
                              for t in miss[:3]],
            "cross_examples": [f"[{r['technique']}] {r['command'][:80]}"
                               for r, _ in cross[:3]],
        }

    for tid, res in results.items():
        res["verdict"] = _verdict(res)
    return {"results": results, "corpus_size": len(art_rows),
            "tests": len(tests), "art_techniques": len(art_techniques),
            "scope": dict(scope_counts),
            "in_scope_tests": scope_counts.get("in", 0)}


def _verdict(res: dict) -> str:
    """Only what ART can actually support.

    NO_ATOMIC       ART publishes no Linux atomic for this technique, so
                    nothing external can measure it.
    NOT_OBSERVABLE  atomics exist but none is a shell command this sensor
                    could see.
    Otherwise the score itself is the answer -- there is no pass mark, because
    no external source defines one.
    """
    if not res["art_available"] or res["art_total"] == 0:
        return "NO_ATOMIC"
    if res.get("in_scope_total", 0) == 0:
        return "NOT_OBSERVABLE"
    return "MEASURED"


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

    # What a shell sensor could observe at all. Printed BEFORE any score, with
    # the reason for every exclusion, so the in-scope rate can be audited.
    sc = ev.get("scope") or {}
    ins = ev.get("in_scope_tests", 0)
    out = ev["tests"] - ins
    print(f"\nSCOPE — HydraPoT observes shell command text and nothing else")
    print(f"  in scope     : {ins}/{ev['tests']} tests  "
          f"({ins/max(1,ev['tests'])*100:.1f}%)")
    print(f"  out of scope : {out}")
    for reason, n in sorted(((k, v) for k, v in sc.items() if k != "in"),
                            key=lambda kv: -kv[1]):
        print(f"      {n:>4}  {reason}")

    tot_raw = sum(r["art_total"] for r in results.values())
    det_raw = sum(r["detected"] for r in results.values())
    tot_in  = sum(r.get("in_scope_total", 0) for r in results.values())
    det_in  = sum(r.get("in_scope_detected", 0) for r in results.values())
    print(f"\nDETECTION over the techniques these rules target")
    print(f"  raw      : {det_raw}/{tot_raw} atomics "
          f"({det_raw/max(1,tot_raw)*100:.1f}%)   -- measures rules AND sensor")
    print(f"  in scope : {det_in}/{tot_in} atomics "
          f"({det_in/max(1,tot_in)*100:.1f}%)   -- measures the RULES")
    errs = load_errors()
    if errs:
        print(f"rule load errors : {len(errs)}")
        for rel, msg in errs:
            print(f"    {rel}: {msg}")
    print()

    order = {"MEASURED": 0, "NOT_OBSERVABLE": 1, "NO_ATOMIC": 2}
    rows = sorted(results.values(), key=lambda r: (order.get(r["verdict"], 9),
                                                   -(r.get("in_scope_rate") or 0)))

    print(f"  {'TECHNIQUE':<12} {'ART':>5} {'OBSERVABLE':>11} {'DETECTED':>9} {'SCORE':>7}")
    print("  " + "-" * 50)
    for r in rows:
        n = r.get("in_scope_total", 0)
        if not n:
            why = "no atomic" if r["verdict"] == "NO_ATOMIC" else "not observable"
            print(f"  {r['technique']:<12} {r['art_total']:>5} {'0':>11} "
                  f"{'-':>9} {why:>16}")
            continue
        print(f"  {r['technique']:<12} {r['art_total']:>5} {n:>11} "
              f"{r['in_scope_detected']:>9} {r['in_scope_rate']*100:6.0f}%")

    flagged = [r for r in rows if r["verdict"] in ("SUSPECT", "MISSES", "PARTIAL")]
    if flagged:
        print("\n" + "-" * 78)
        print("RULES NEEDING REVIEW")
        print("-" * 78)
        for r in flagged:
            print(f"\n{r['technique']}  [{r['verdict']}]  "
                  f"in-scope {r.get('in_scope_detected',0)}/{r.get('in_scope_total',0)}"
                  f"   raw {r['detected']}/{r['art_total']}"
                  + (f"   ({r['out_of_scope']} out of scope)" if r.get("out_of_scope") else ""))
            for m in r["miss_examples"]:
                print(f"    MISSED  {m}")
            for c in r["cross_examples"]:
                print(f"    CROSS   {c}")

    measured = [r for r in rows if r["verdict"] == "MEASURED"]
    if measured:
        det = sum(r["in_scope_detected"] for r in measured)
        tot = sum(r["in_scope_total"] for r in measured)
        raw_d = sum(r["detected"] for r in rows)
        raw_t = sum(r["art_total"] for r in rows)
        print("\n" + "=" * 78)
        print("SCORE AGAINST ATOMIC RED TEAM")
        print("=" * 78)
        print(f"  techniques measured : {len(measured)} of {len(rows)} targeted")
        print(f"  ART atomics         : {raw_d}/{raw_t}  "
              f"({raw_d/max(1,raw_t)*100:.1f}%)   every Linux atomic")
        print(f"  observable only     : {det}/{tot}  "
              f"({det/max(1,tot)*100:.1f}%)   excluding what this sensor cannot see")
        print()
        print("  ART is the baseline: it labels each command with the technique")
        print("  it demonstrates, so the score is simply how many of its atomics")
        print("  we tagged the same way. There is no pass mark here -- no")
        print("  external source defines one, so none is invented.")

    noatomic = [r for r in rows if r["verdict"] == "NO_ATOMIC"]
    if noatomic:
        print("\n" + "-" * 78)
        print(f"NO ATOMIC ({len(noatomic)}) — ART publishes no Linux test for these,")
        print("so nothing external can measure them:")
        print("    " + ", ".join(r["technique"] for r in noatomic))
    notobs = [r for r in rows if r["verdict"] == "NOT_OBSERVABLE"]
    if notobs:
        print(f"\nNOT OBSERVABLE ({len(notobs)}) — atomics exist but none is a shell")
        print("command this sensor could see:")
        print("    " + ", ".join(r["technique"] for r in notobs))

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
