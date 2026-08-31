"""
threat_intel/validate_traffic.py — validate HydraPoT's ATT&CK tagging against
MITRE CAR (Cyber Analytics Repository) using EXTERNAL honeypot traffic.

Pipeline
--------
  1. Ingest   dataset/cyberlab_*.json  (real Cowrie capture, not our own DB)
  2. Tag      every command through main.py's mitre_tag  (mitre_mapper.tag)
  3. Verify   each emitted technique against MITRE CAR's analytic model
  4. Report   totals, corroboration, discordances, rate

What MITRE CAR is, and what it can honestly validate
----------------------------------------------------
CAR is 102 analytics (verified 2026-08-26). Each carries a `coverage:` block
naming the ATT&CK techniques it detects, and `implementations:` written as
pseudocode/Splunk/EQL over CAR's *data model* — `process/create/command_line`,
`flow/start/dest_port`, `registry/...`. It is detection THEORY, not a labelled
corpus.

CAR therefore CANNOT provide command-level ground truth. It ships no labelled
example commands, so it cannot tell you "this command is really T1083". Any
number here that called itself "accuracy against CAR" would be invented.

What CAR CAN do, and what this script actually measures:

  A. CORROBORATION — does MITRE publish a detection analytic for the technique
     we emitted at all? A technique with a CAR analytic is one MITRE considers
     detectable and has modelled. One without is not wrong, it is unmodelled.

  B. TELEMETRY FEASIBILITY — CAR states which data-model objects an analytic
     needs. Our sensor observes shell command text only (process/command_line).
     If every CAR analytic for a technique needs `flow`, `registry`, `service`
     or `thread` data, then CAR's own theory says that technique is not
     detectable from what we can see, and tagging it from command text alone
     is theoretically unsupported. That is a real, objective finding.

  C. DISCORDANCE — 48 of the 102 analytics reference `command_line` and some
     embed literal match patterns. Where a command matches such an analytic,
     CAR names the technique it expects. If we emitted a different one, that
     is a genuine specification-level disagreement and is reported per-command.

Usage
-----
    python threat_intel/validate_traffic.py                 # default dataset
    python threat_intel/validate_traffic.py --sync-car      # refresh CAR
    python threat_intel/validate_traffic.py --dataset dataset/cyberlab_2019-05-13.json
    python threat_intel/validate_traffic.py --limit 5000 --json out.json
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required: pip install pyyaml")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from threat_intel.mitre_mapper import tag as mitre_tag, tag_all  # noqa: E402

CAR_CACHE = os.path.join(_HERE, ".car_cache")
CAR_API = "https://api.github.com/repos/mitre-attack/car/contents/analytics"
DEFAULT_DATASETS = [
    os.path.join(_ROOT, "dataset", "cyberlab_2019-08-05.json"),
    os.path.join(_ROOT, "dataset", "cyberlab_2019-05-13.json"),
]

# CAR data-model objects an SSH honeypot can actually observe. Our sensor sees
# the command line a user typed; it does not see registry writes, kernel
# threads, driver loads or netflow.
OBSERVABLE_OBJECTS = {"process"}
UNOBSERVABLE_HINT = {
    "flow": "network flow records", "registry": "Windows registry",
    "service": "Windows service control", "thread": "thread/injection telemetry",
    "driver": "kernel driver events", "module": "module load events",
    "user_session": "logon session telemetry", "email": "mail gateway logs",
    "http": "HTTP proxy logs", "socket": "socket table", "file": "file system events",
    "authentication": "authentication logs",
}


# ══════════════════════════════════════════════════════════════════════════════
# 1. INGEST — external cyberlab Cowrie capture
# ══════════════════════════════════════════════════════════════════════════════
# The dataset is one large JSON array of {session_id: [events]}. The 2019-08-05
# file is 519 MB, so it is scanned as text in overlapping chunks rather than
# parsed into memory. Commands appear in two shapes:
#     "eventid": "cowrie.command.input"    -> "message": "CMD: <command>"
#     "eventid": "cowrie.command.success"  -> "message": "Command found: <command>"
#     "eventid": "cowrie.command.failed"   -> "message": "Command not found: <command>"
# The `failed` variant matters: it is 426 of the 2,848 command events in these
# two files, and an unrecognised command is still attacker intent worth tagging.
_EVENT_CMD = re.compile(
    r'"eventid":\s*"cowrie\.command\.(?:input|success|failed)"'
    r'.{0,600}?"message":\s*"(?:CMD:|Command (?:not )?found:)\s*(.*?)(?<!\\)"',
    re.S,
)
_CHUNK = 4 << 20          # 4 MB
_OVERLAP = 8192           # enough to span one record


def _unescape(s: str) -> str:
    try:
        return json.loads(f'"{s}"')
    except Exception:
        return s.replace('\\"', '"').replace("\\\\", "\\").replace("\\n", "\n")


def ingest(paths, limit=None, verbose=True):
    """Yield command strings from cyberlab Cowrie logs."""
    seen = 0
    for path in paths:
        if not os.path.exists(path):
            if verbose:
                print(f"[ingest] missing, skipped: {path}")
            continue
        size = os.path.getsize(path)
        if verbose:
            print(f"[ingest] {os.path.basename(path)}  ({size/1048576:.0f} MB)")
        # Carry the unconsumed remainder after the last complete match, not a
        # fixed-size tail. A fixed tail re-scans text already emitted, which
        # double-counts every record inside the overlap window, and can still
        # drop a record longer than the window.
        tail = ""
        with open(path, encoding="utf-8", errors="replace") as f:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                buf = tail + chunk
                end = 0
                for m in _EVENT_CMD.finditer(buf):
                    end = m.end()
                    cmd = _unescape(m.group(1)).strip()
                    if not cmd:
                        continue
                    seen += 1
                    yield cmd
                    if limit and seen >= limit:
                        return
                # keep everything after the last full match so a record split
                # across the seam is still matched next round
                tail = buf[end:] if end else buf[-_OVERLAP:]
                if len(tail) > 4 * _OVERLAP:
                    tail = tail[-4 * _OVERLAP:]
            # final flush for a record sitting in the last tail
            for m in _EVENT_CMD.finditer(tail):
                cmd = _unescape(m.group(1)).strip()
                if cmd:
                    seen += 1
                    yield cmd
                    if limit and seen >= limit:
                        return


# ══════════════════════════════════════════════════════════════════════════════
# 2. MITRE CAR
# ══════════════════════════════════════════════════════════════════════════════
def sync_car(verbose=True) -> int:
    os.makedirs(CAR_CACHE, exist_ok=True)
    req = urllib.request.Request(CAR_API, headers={"User-Agent": "HydraPoT-CAR"})
    idx = json.loads(urllib.request.urlopen(req, timeout=30).read())
    n = 0
    for e in idx:
        if e.get("type") != "file" or not e["name"].endswith((".yaml", ".yml")):
            continue
        dest = os.path.join(CAR_CACHE, e["name"])
        if not os.path.exists(dest):
            r = urllib.request.Request(e["download_url"], headers={"User-Agent": "HydraPoT-CAR"})
            open(dest, "wb").write(urllib.request.urlopen(r, timeout=30).read())
        n += 1
    if verbose:
        print(f"[car] {n} analytics cached -> {CAR_CACHE}")
    return n


# Literal patterns embedded in CAR pseudocode, e.g.
#     filter processes where (command_line == "*net* group*")
_CAR_CMDPAT = re.compile(r'command_line\s*(?:==|=~|LIKE)\s*"([^"]+)"', re.I)

# Literals too generic to carry a technique claim on their own.
_CAR_GENERIC = {"echo", "query", "process", "call", "create", "node",
                "processcallcreate", "/node:", "pipe"}


def load_car(verbose=True) -> dict:
    """-> {analytics, by_technique, cmd_patterns}"""
    if not os.path.isdir(CAR_CACHE):
        sync_car(verbose=verbose)
    analytics, by_tech, patterns = [], collections.defaultdict(list), []
    for fn in sorted(os.listdir(CAR_CACHE)):
        if not fn.endswith((".yaml", ".yml")):
            continue
        try:
            d = yaml.safe_load(open(os.path.join(CAR_CACHE, fn), encoding="utf-8"))
        except Exception as e:
            print(f"[car] skip {fn}: {e}")
            continue
        if not isinstance(d, dict):
            continue
        techs = []
        for c in d.get("coverage") or []:
            if c.get("technique"):
                techs.append(c["technique"])
            for s in c.get("subtechniques") or []:
                techs.append(s)
        objs = {r.split("/")[0] for r in (d.get("data_model_references") or [])}
        rec = {"id": d.get("id", fn), "title": d.get("title", ""),
               "techniques": sorted(set(techs)), "objects": sorted(objs),
               "coverage": [c.get("coverage") for c in (d.get("coverage") or [])]}
        analytics.append(rec)
        for t in rec["techniques"]:
            by_tech[t].append(rec)
        body = "\n".join(str(i.get("code", "")) for i in (d.get("implementations") or []))
        for raw in _CAR_CMDPAT.findall(body):
            # Reject degenerate wildcards. CAR-2014-07-001 (Unquoted Service
            # Path) literally specifies command_line == "* *", which matches
            # any command containing a space and would flag every row as a
            # discordance. Require real literal content before trusting a
            # pattern as a specification statement.
            literal = re.sub(r"[\s*?]", "", raw).lower()
            if len(literal) < 4:
                continue
            # Context-free tokens. CAR-2021-02-002 (a Windows named-pipe sudo
            # -caching analytic) specifies command_line == "*echo*"; on Linux
            # traffic that matches every echo and asserts T1548, which is
            # meaningless. A pattern only counts as a specification statement
            # when its literal names something distinctive.
            if literal in _CAR_GENERIC:
                continue
            rx = re.escape(raw).replace(r"\*", ".*")
            try:
                patterns.append({"analytic": rec["id"], "raw": raw,
                                 "re": re.compile(rx, re.I),
                                 "techniques": rec["techniques"]})
            except re.error:
                pass
    if verbose:
        print(f"[car] {len(analytics)} analytics, {len(by_tech)} techniques, "
              f"{len(patterns)} command_line patterns")
    return {"analytics": analytics, "by_technique": dict(by_tech), "cmd_patterns": patterns}


def technique_verdict(tid: str, car: dict) -> tuple:
    """-> (verdict, detail). Parent technique is consulted for sub-techniques."""
    hits = car["by_technique"].get(tid) or car["by_technique"].get(tid.split(".")[0]) or []
    if not hits:
        return "NO_CAR_ANALYTIC", "MITRE CAR publishes no analytic for this technique"
    if any(set(a["objects"]) & OBSERVABLE_OBJECTS or not a["objects"] for a in hits):
        ids = ",".join(a["id"] for a in hits[:3])
        return "CAR_SUPPORTED", f"process/command-line analytic exists ({ids})"
    need = sorted({o for a in hits for o in a["objects"]})
    pretty = ", ".join(UNOBSERVABLE_HINT.get(o, o) for o in need)
    return "CAR_TELEMETRY_MISMATCH", f"CAR analytics need {pretty}; a shell sensor cannot see it"


# ══════════════════════════════════════════════════════════════════════════════
# 3+4. VALIDATE AND REPORT
# ══════════════════════════════════════════════════════════════════════════════
def validate(paths, limit=None, verbose=True) -> dict:
    car = load_car(verbose=verbose)
    counts = collections.Counter()
    verdicts = collections.Counter()
    per_tech = collections.defaultdict(collections.Counter)
    discord, agreements, unmatched_examples = [], [], []
    freq = collections.Counter()

    for cmd in ingest(paths, limit=limit, verbose=verbose):
        counts["records"] += 1
        freq[cmd] += 1

    if verbose:
        print(f"[ingest] {counts['records']} command records, {len(freq)} unique\n")

    tagcache = {}
    for cmd, n in freq.items():
        t = tagcache.get(cmd)
        if t is None:
            t = tagcache[cmd] = mitre_tag(cmd)
        if not t:
            counts["untagged"] += n
            if len(unmatched_examples) < 15:
                unmatched_examples.append((n, cmd))
            continue
        counts["tagged"] += n
        tid = t["technique_id"]
        v, detail = technique_verdict(tid, car)
        verdicts[v] += n
        per_tech[tid][v] += n

        # C. discordance — CAR's own command_line patterns
        for p in car["cmd_patterns"]:
            if p["re"].search(cmd):
                expected = set(p["techniques"])
                got = {x["technique_id"] for x in tag_all(cmd)}
                agree = bool(expected & got) or any(
                    e.split(".")[0] in {g.split(".")[0] for g in got} for e in expected)
                counts["car_pattern_hits"] += n
                if agree:
                    counts["car_pattern_agree"] += n
                    agreements.append({"command": cmd, "rows": n,
                                       "hydrapot": sorted(got),
                                       "car_expects": sorted(expected),
                                       "car_analytic": p["analytic"],
                                       "car_pattern": p["raw"]})
                else:
                    discord.append({"command": cmd, "rows": n, "hydrapot": sorted(got),
                                    "car_expects": sorted(expected),
                                    "car_analytic": p["analytic"], "car_pattern": p["raw"]})
                break

    return {"counts": counts, "verdicts": verdicts, "per_tech": per_tech,
            "discord": discord, "agreements": agreements,
            "unmatched": unmatched_examples,
            "car": {"analytics": len(car["analytics"]),
                    "techniques": len(car["by_technique"]),
                    "patterns": len(car["cmd_patterns"])},
            "freq": freq, "tagcache": tagcache}


def report(res: dict):
    c, v = res["counts"], res["verdicts"]
    total, tagged = c["records"], c["tagged"]
    corro = v["CAR_SUPPORTED"]
    W = 78
    print("=" * W)
    print("HydraPoT ATT&CK TAGGING — VALIDATION AGAINST MITRE CAR")
    print("=" * W)
    print(f"external traffic  : cyberlab Cowrie capture (not HydraPoT's own DB)")
    print(f"CAR reference     : {res['car']['analytics']} analytics, "
          f"{res['car']['techniques']} techniques, {res['car']['patterns']} command_line patterns")
    print()
    print(f"  Total records evaluated        : {total}")
    print(f"  Tagged with an ATT&CK ID       : {tagged}  ({tagged/max(1,total):.1%})")
    print(f"  Produced no tag                : {c['untagged']}  ({c['untagged']/max(1,total):.1%})")
    print()
    print("  Of the tagged records, MITRE CAR says:")
    print(f"    CAR_SUPPORTED             {v['CAR_SUPPORTED']:>7}  "
          f"({v['CAR_SUPPORTED']/max(1,tagged):>6.1%})  analytic exists and is command-line observable")
    print(f"    CAR_TELEMETRY_MISMATCH    {v['CAR_TELEMETRY_MISMATCH']:>7}  "
          f"({v['CAR_TELEMETRY_MISMATCH']/max(1,tagged):>6.1%})  CAR requires telemetry a shell sensor lacks")
    print(f"    NO_CAR_ANALYTIC           {v['NO_CAR_ANALYTIC']:>7}  "
          f"({v['NO_CAR_ANALYTIC']/max(1,tagged):>6.1%})  MITRE publishes no analytic for it")
    print()
    print(f"  >>> CAR CORROBORATION RATE : {corro}/{tagged} = {corro/max(1,tagged):.1%}")
    print("      (share of emitted tags whose technique MITRE CAR models with an")
    print("       analytic our sensor could actually implement. NOT accuracy —")
    print("       CAR ships no labelled commands, so it cannot score correctness.)")
    print()
    print("-" * W)
    print("PER-TECHNIQUE BREAKDOWN")
    print("-" * W)
    print(f"  {'TECHNIQUE':12} {'ROWS':>7}  VERDICT")
    rows = sorted(res["per_tech"].items(), key=lambda kv: -sum(kv[1].values()))
    for tid, vc in rows:
        top = vc.most_common(1)[0][0]
        print(f"  {tid:12} {sum(vc.values()):>7}  {top}")
    print()
    print("-" * W)
    print(f"DIRECT SPEC CHECK — CAR's own command_line patterns")
    print("-" * W)
    hits = res["counts"]["car_pattern_hits"]
    agree = res["counts"]["car_pattern_agree"]
    print(f"  records matching a usable CAR pattern : {hits}")
    if hits:
        print(f"    agreed with CAR : {agree}  ({agree/hits:.1%})")
        print(f"    disagreed       : {hits-agree}  ({(hits-agree)/hits:.1%})")
    print("  NOTE: 17 of CAR's 18 command_line patterns are Windows-specific")
    print("  (sekurlsa, scrobj.dll, %COMSPEC%, \\pipe\\, .exe\\). Only")
    print("  CAR-2019-07-001 ('chmod *' -> T1222) applies to Linux, so this")
    print("  check has almost no surface here by construction.")
    print()
    for a in sorted(res["agreements"], key=lambda x: -x["rows"])[:6]:
        print(f"  AGREE [{a['rows']:>5} rows] {a['command'][:50]}")
        print(f"        HydraPoT {a['hydrapot']} == CAR {a['car_analytic']} {a['car_expects']}")
    if not res["discord"]:
        print("  none: no ingested command matched a CAR command_line pattern with a")
        print("  conflicting technique. CAR's literal patterns are overwhelmingly")
        print("  Windows-oriented (net.exe, reg.exe, wmic), so this check has very")
        print("  little surface on Linux honeypot traffic — read 'none' as 'not")
        print("  exercised', not as 'verified correct'.")
    else:
        for d in sorted(res["discord"], key=lambda x: -x["rows"])[:25]:
            print(f"  [{d['rows']:>5} rows] {d['command'][:56]}")
            print(f"          HydraPoT -> {d['hydrapot']}")
            print(f"          CAR {d['car_analytic']} expects {d['car_expects']} "
                  f"(pattern {d['car_pattern']!r})")
    print()
    print("-" * W)
    print("TOP UNTAGGED COMMANDS (coverage gaps, not errors)")
    print("-" * W)
    for n, cmd in sorted(res["unmatched"], reverse=True)[:12]:
        print(f"  {n:>6}x  {cmd[:64]}")
    print("=" * W)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dataset", action="append",
                    help="cyberlab JSON to ingest (repeatable). Default: both.")
    ap.add_argument("--limit", type=int, help="stop after N command records")
    ap.add_argument("--sync-car", action="store_true", help="download CAR analytics first")
    ap.add_argument("--json", help="write the full result to this path")
    a = ap.parse_args()

    if a.sync_car:
        sync_car()
    paths = a.dataset or DEFAULT_DATASETS
    res = validate(paths, limit=a.limit)
    report(res)

    if a.json:
        out = {"counts": dict(res["counts"]), "verdicts": dict(res["verdicts"]),
               "car": res["car"], "discord": res["discord"],
               "per_technique": {k: dict(v) for k, v in res["per_tech"].items()}}
        json.dump(out, open(a.json, "w"), indent=1)
        print(f"\n[json] written -> {a.json}")


if __name__ == "__main__":
    main()
