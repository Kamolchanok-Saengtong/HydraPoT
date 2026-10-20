"""
experiment_data/_paths.py — where an experiment arm's session log belongs.

Sandbox-only. Production never imports this.

Why it exists
-------------
Session logs were first routed by *which file created the handler*, which is
wrong for agents.py: it lives at the sandbox root but builds the three Part A
arms, so parta_cowrie / parta_on_device / parta_cloud landed in
experiment_data/sessions/ instead of PartA/sessions/ — away from the rest of
the Part A data.

Routing by ARM NAME fixes that, and uses exactly the mapping the one-time
migration used, so a new run lands beside the data already exported for the
same arm rather than starting a second pile somewhere else.

  parta_*                 -> PartA/sessions/
  eval_*                  -> PartB/sessions/   (sync_on/off, sri_on/off, hi_ablation)
  partc_*, hrreplay_*     -> PartC/sessions/
  anything else           -> the caller's own folder

The fallback matters: module_overhead.py uses src_ip="p" and
test_cloud_obfuscation_hypothesis.py uses "test". Neither name says which Part
it is, but the file's own location does, so an unrecognised arm stays next to
the script that produced it instead of being guessed into the wrong Part.
"""
import os

_HERE = os.path.dirname(os.path.abspath(__file__))

_ARM_PART = (
    ("parta",    "PartA"),
    ("eval_",    "PartB"),
    ("partc",    "PartC"),
    ("hrreplay", "PartC"),   # Part C's HoneyRouter replay arm
)


def session_dir_for(src_ip: str, caller_file: str) -> str:
    """Absolute path of the sessions/ folder this arm should write to.

    caller_file is the calling module's __file__ — used only when the arm name
    itself does not identify a Part.
    """
    for prefix, part in _ARM_PART:
        if src_ip.startswith(prefix):
            return os.path.join(_HERE, part, "sessions")
    return os.path.join(os.path.dirname(os.path.abspath(caller_file)), "sessions")


# ── where results go ────────────────────────────────────────────────────────
# One results/ tree with a folder per part, so scripts and outputs are never
# mixed. Defined here rather than joined in 25 scripts: the previous layout
# had Part B writing to the top-level results/ while A and C wrote inside
# their own folder, and nothing said which was correct.

RESULTS = os.path.join(_HERE, "results")


def results_dir(part: str) -> str:
    """Absolute results folder for 'A', 'B', 'C', or 'shared'."""
    key = part.strip().upper()
    name = "shared" if key == "SHARED" else f"part{key}"
    return os.path.join(RESULTS, name)
