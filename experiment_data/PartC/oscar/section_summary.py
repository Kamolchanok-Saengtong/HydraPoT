"""
experiment_data/PartC/oscar/section_summary.py -- one OSCAR paper section at a time.

Each section reads its own folder in experiment_data/results/OSCAR_VI-*.

    python section_summary.py --section B     # Table I   create-revisit trilemma
    python section_summary.py --section C     # Table II  12 oracle signatures
    python section_summary.py --section XIV   # Table XIV contradictions vs length
    python section_summary.py --section D     # Tables III/IV ATT&CK kill chain
    python section_summary.py --section E     # Table V   held-out commands
    python section_summary.py --section H     # component ablation (gate off)
    python section_summary.py --section I     # Table XI  wild replay
    python section_summary.py --section all
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import paper_suite as ps                      # noqa: E402
import paper_summary as pm                    # noqa: E402
import summarize as sm                        # noqa: E402
from probe import CREATE                      # noqa: E402

RESULTS = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "results")
DIRS = {
    "B": "OSCAR_VI-B_VI-C_create_revisit_TableI_II_XIV",
    "D": "OSCAR_VI-D_attack_killchain",
    "E": "OSCAR_VI-E_heldout",
    "H": "OSCAR_VI-H_component_ablation_gate_off",
    "I": "OSCAR_VI-I_wild_replay",
}
DIRS["C"] = DIRS["XIV"] = DIRS["B"]


def folder(key):
    return os.path.join(RESULTS, DIRS[key])


def version(key):
    path = os.path.join(folder(key), "CODE_VERSION")
    return open(path).read().strip() if os.path.isfile(path) else "see folder"


def head(title, key):
    print(f"\n{'=' * 78}\n{title}\n  folder: {DIRS[key]}\n  code:   {version(key)}\n{'=' * 78}")


def runs(key, name):
    return sm.load(os.path.join(folder(key), name))


def sec_b():
    head("Section VI-B  Table I -- create-then-revisit trilemma (old HydraPoT vs new)", "B")
    old, new = runs("B", "table1_old.json"), runs("B", "table1_new.json")
    print(f"  {'system':<6} {'N':>3}  {'contra/session':>14}   fallback")
    for label, rs in (("old", old), ("new", new)):
        if rs:
            sm.table1(rs, label)


def sec_c():
    head("Section VI-C  Table II -- contradictions by oracle signature (12 signatures)", "C")
    sets = [(label, runs("C", f"table1_{label}.json") + runs("C", f"table14_{label}.json"))
            for label in ("old", "new")]
    sm.signatures([s for s in sets if s[1]])


def sec_xiv():
    head("Table XIV -- mean contradictions vs session length L", "XIV")
    sm.table14(runs("XIV", "table14_old.json"), runs("XIV", "table14_new.json"))


def sec_d():
    head("Section VI-D  Tables III/IV -- ATT&CK kill chain, 10 tactics", "D")
    rows = pm.load(os.path.join(folder("D"), "attack*.json"))
    print(pm.HEAD)
    for tactic in ps.TACTICS:
        print(pm.line(tactic, [r for r in rows if r["label"] == tactic]))
    print(pm.line("MEAN over all", rows))


def sec_e():
    head("Section VI-E  Table V -- held-out commands, gate on vs off", "E")
    print(pm.HEAD)
    lo, hi = len(CREATE), len(CREATE) + len(ps.HELDOUT)
    for name, pattern in (("gate ON", "heldout_gate_on*.json"), ("gate OFF", "heldout_gate_off*.json")):
        rows = pm.load(os.path.join(folder("E"), pattern))
        print(pm.line(name, rows))
        if rows:
            miss = [sum(1 for i in range(lo, hi) if ps.failed(r["transcript"][i][1], r["real"][i]))
                    for r in rows]
            print(f"  {'  held-out commands only':<24} answered "
                  f"{1 - sum(miss) / (len(miss) * len(ps.HELDOUT)):5.3f}")


def sec_h():
    head("Section VI-H  Component ablation -- gate OFF vs full system (Table I probe)", "H")
    full = runs("B", "table1_new.json")
    off = runs("H", "table1_new.json")
    print(f"  {'system':<22} {'N':>3}  {'contra/session':>14}   fallback")
    for label, rs in (("old (no ontology)", runs("B", "table1_old.json")),
                      ("OSCAR minus gate", off), ("OSCAR full", full)):
        if rs:
            sm.table1(rs, label)
    print("  (prompt-only, no-rule-core and no-procedural-FS rows are not run yet)")


def sec_i():
    head("Section VI-I  Table XI -- wild replay of real captured sessions", "I")
    print(pm.HEAD)
    print(pm.line("ml4net", pm.load(os.path.join(folder("I"), "wild_ml4net_*.json"))))
    print(pm.line("cyberlab", pm.load(os.path.join(folder("I"), "wild_cyberlab.json"))))


SECTIONS = {"B": sec_b, "C": sec_c, "XIV": sec_xiv, "D": sec_d, "E": sec_e, "H": sec_h, "I": sec_i}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--section", required=True, choices=[*SECTIONS, "all"])
    key = ap.parse_args().section
    for name in (SECTIONS if key == "all" else [key]):
        SECTIONS[name]()


if __name__ == "__main__":
    main()
