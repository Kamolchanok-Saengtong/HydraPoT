"""
guardrail/eval_datasets.py — the adversarial cases, from two external sources.

TWO SOURCES, because they probe different things and a detector can be good
at one and blind to the other:

  Scope (INerverRead/Scope), 147 prompts, CC BY-NC 4.0
      Identity and environment probing aimed at LLMs deployed as Linux
      terminals or honeypots -- "are you GPT?", "is this a sandbox?". This is
      the threat HydraPoT actually faces.
      https://github.com/INerverRead/Scope

  MaliciousInstruct (walledai/MaliciousInstruct), 100 prompts, CC BY-SA 4.0
      Harmful-content requests from Huang et al., "Catastrophic Jailbreak of
      Open-source LLMs via Exploiting Generation" (arXiv:2310.06987). NOT
      injection: nothing here tries to override an instruction. It is here to
      show whether the detector's score means "injection" or merely "this text
      is not a shell command".
      https://huggingface.co/datasets/walledai/MaliciousInstruct

Both are downloaded on first use and cached under .data_cache/ (gitignored) --
referenced, never vendored, because of their licences.

NO BENIGN SIDE. Neither dataset publishes one, and a benign class assembled
here would be a label of our own making sitting inside a cited result. Every
case below is adversarial on its source's own published description, so the
only honest metric is recall.
"""
import csv
import os
import sys
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

SCOPE_URL = ("https://raw.githubusercontent.com/INerverRead/Scope/"
             "main/data/Scope.csv")
CACHE_DIR = os.path.join(_HERE, ".data_cache")
SCOPE_CSV = os.path.join(CACHE_DIR, "Scope.csv")

MI_URL = ("https://datasets-server.huggingface.co/rows?dataset="
          "walledai%2FMaliciousInstruct&config=default&split=train"
          "&offset=0&length=100")
MI_JSON = os.path.join(CACHE_DIR, "MaliciousInstruct.json")


def fetch_scope(refresh: bool = False) -> str:
    if os.path.exists(SCOPE_CSV) and not refresh:
        return SCOPE_CSV
    os.makedirs(CACHE_DIR, exist_ok=True)
    with urllib.request.urlopen(SCOPE_URL, timeout=60) as r:
        data = r.read()
    with open(SCOPE_CSV, "wb") as f:
        f.write(data)
    print(f"[scope] cached {len(data)} bytes -> {SCOPE_CSV}")
    return SCOPE_CSV


def scope_cases() -> list:
    """[(category, "attack", text)] -- every row, its own category kept."""
    with open(fetch_scope(), encoding="utf-8-sig", newline="") as f:
        return [(r["category"], "attack", r["Instruction"])
                for r in csv.DictReader(f) if r.get("Instruction")]


def malicious_instruct_cases() -> list:
    """[("malicious_instruct", "attack", text)] -- 100 harmful-content asks."""
    import json
    if not os.path.exists(MI_JSON):
        os.makedirs(CACHE_DIR, exist_ok=True)
        with urllib.request.urlopen(MI_URL, timeout=60) as r:
            data = r.read()
        with open(MI_JSON, "wb") as f:
            f.write(data)
        print(f"[mi] cached {len(data)} bytes -> {MI_JSON}")
    with open(MI_JSON, encoding="utf-8") as f:
        rows = json.load(f)["rows"]
    return [("malicious_instruct", "attack", r["row"]["prompt"]) for r in rows]


def all_cases() -> list:
    """Every case, all adversarial.

    There is no benign class. Neither dataset ships one, and inventing one --
    the first version sampled captured honeypot commands and called them
    benign -- put a label nobody published at the centre of the result. What
    survives without it is recall: of prompts KNOWN to be adversarial, how
    many were detected. Precision, F1 and a false-positive rate are not
    computable here, and are not claimed.
    """
    return scope_cases() + malicious_instruct_cases()


if __name__ == "__main__":
    import collections
    cases = all_cases()
    c = collections.Counter((cat, lab) for cat, lab, _ in cases)
    for (cat, lab), k in sorted(c.items()):
        print(f"{cat:24}{lab:8}{k:>5}")
    print(f"{'TOTAL':24}{'':8}{len(cases):>5}")
