"""
experiment_data/PartA/run/guardrail_overhead.py — full-pipeline response
time, guard off vs on. Part A: guardrail overhead.

Not the detector in isolation -- the whole request, end to end: build_prompt()
+ agent.send(), timed once with guardrail OFF and once ON, same prompts, same
loaded agent. The difference is what the guardrail actually costs a real
session, detector included.

Layout, one folder per arm (named "<arm>_overhead" so an arbitrary number of
arms stay distinguishable at a glance), one file per pipeline inside it:

    experiment_data/results/partA/guardrail_overhead/<arm>_overhead/on_device.json
    experiment_data/results/partA/guardrail_overhead/<arm>_overhead/cloud.json
    experiment_data/results/partA/guardrail_overhead/<arm>_overhead/hydrapot.json

WHICH AGENT ANSWERS IS config.yaml's DECISION, NOT A FLAG
---------------------------------------------------------
Edit agents.*.enabled in config.yaml and run; the filename follows:

  only on_device enabled -> on_device.json
  only cloud enabled     -> cloud.json
  all three enabled      -> hydrapot.json   (real routing per command)

There is no --pipelines. core/router.py reads agents.*.enabled at IMPORT
time from the file on disk (router.py:18-24), so an in-memory override never
reaches the router -- the file is the only switch that works. With one agent
enabled, classify() short-circuits to it for every command with no routing
decision at all (router.py:180), which is exactly a forced single-agent run;
with several it is real HydraPoT routing, where "guard on" only changes
latency for commands routed to an LLM, since Cowrie never sees the guardrail
(shell/session.py:882).

Guard off vs on is the ONE thing still toggled in memory, per prompt, because
the two conditions have to alternate inside a single run -- see the
interleaving note in run_one(). Measuring it by editing the file instead
would put the conditions in two runs separated by minutes, which is the
block-ordering bias that made the guardrail look FASTER than no guardrail.

Two arms, as requested: prompt_guard2 and nemo. Each run reuses
guardrail/validator.py's agent/prompt-manager builders so this measures the
same call shape session.py makes, not a stand-in.

SCORE FIRST, REWRITE ONLY WHAT IS FLAGGED
-----------------------------------------
Guard-on honours config.yaml's fence_on_detect, as session.py does: the
detector scores the command, and the fence applies only if it flags. With
fence_on_detect false every prompt is rewritten, so the model answers
DIFFERENT text under guard-on than guard-off and the measured difference is
mostly that, not the detector. `flagged_on` in each result file says how many
prompts were rewritten; the rest got a byte-identical prompt in both
conditions, which is what makes the delta the detector's own cost.

PROMPT SIDE ONLY, BY DEFAULT
----------------------------
What is timed is the prompt side: the detector's score, the fence, the
sanitiser. The OUTPUT side -- validate the answer, re-ask the model once if it
broke persona, then fall back to Cowrie -- is implemented in _answer() but
follows config.yaml, where validate/retry_on_break currently ship FALSE. A
retry is a second full LLM call, so it belongs to its own experiment rather
than sitting inside this one's number; set both true in config.yaml to
include it, and the run prints which way it went.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics as stats
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, _ROOT)

from guardrail.validator import ask, build_agent, make_prompt_manager

OUT_DIR = os.path.join(_ROOT, "experiment_data", "results", "partA", "guardrail_overhead")
ARMS = ("prompt_guard2", "nemo")
# No PIPELINES constant: the pipeline is whatever config.yaml enabled, and
# _pipeline_label() reads it from there.


def _stats(ms: list[float]) -> dict:
    if not ms:
        # Every call in this condition failed (e.g. cloud API down for the
        # whole run) -- report it as empty rather than crash statistics.mean()
        # on [], which would kill every arm/pipeline still queued after this one.
        return {"n": 0, "mean_ms": float("nan"), "median_ms": float("nan"),
                "p95_ms": float("nan"), "max_ms": float("nan")}
    s = sorted(ms)
    n = len(s)
    pct = lambda p: s[min(int(n * p), n - 1)]
    return {"n": n, "mean_ms": stats.mean(s), "median_ms": stats.median(s),
            "p95_ms": pct(0.95), "max_ms": s[-1]}


def _arm_matches(provider, arm) -> bool:
    """Do these two names select the same arm module?

    Compared through the registry, not as strings: config.yaml ships
    `provider: llama`, which is one of prompt_guard2's ALIASES, so a plain
    `==` against "prompt_guard2" would say no.
    """
    from guardrail import detector_arm

    def _canonical(p):
        want = (p or "").strip().lower()
        for a in detector_arm.ARMS:
            if want == a.NAME or want in a.ALIASES:
                return a.NAME
        return want

    return _canonical(provider) == _canonical(arm)


def _set_detector(config, arm):
    """Point the CONFIG at `arm`, as if config.yaml had named it.

    Written into the config rather than passed around it, so the arm reaches
    the detector the way production's does -- through
    guardrail.detector.provider -- and this measures the real HydraPoT layer
    instead of a side channel. detector.enabled must be True too, or
    session.py's guard block never runs at all (session.py:435); config.yaml
    ships it False.

    detector.model is cleared unless config.yaml's own provider IS this arm.
    Every arm resolves `cfg["model"] or DEFAULT_MODEL`, so handing one arm's
    checkpoint to another silently loads the wrong weights -- a protectai run
    would have scored Llama-Prompt-Guard-2-86M and still reported itself as
    protectai. Cleared, each arm resolves its own DEFAULT_MODEL.
    """
    import dataclasses
    d = config.guardrail.detector
    model = d.model if _arm_matches(d.provider, arm) else ""
    config.guardrail.detector = dataclasses.replace(
        d, enabled=True, provider=arm, model=model)


def _build_detector(config):
    """The detector built FROM THE CONFIG, exactly as shell/session.py builds
    it (session.py:439-444) -- same provider/model/device/threshold, read from
    the same place. Loaded ONCE per arm, outside any timed region, same
    principle as build_agent()."""
    from guardrail.detector import make_detector
    d = config.guardrail.detector
    det = make_detector({"provider": d.provider, "model": d.model,
                         "device": d.device, "threshold": d.threshold})
    # The HF arms load lazily -- _ensure_loaded() plus resolve_labels()' two
    # probe forward passes fire on the FIRST classify(), which would otherwise
    # land inside the first timed guard-on sample and bill the model load to
    # the guardrail. Burn that call here, outside the timing, as build_agent()
    # already does for the responder.
    det.classify("warmup")
    return det


def _set_guard(config, on: bool):
    """Guard off vs on -- the ONE thing toggled in memory, because the two
    conditions have to alternate inside a single run (see run_one).

    OFF is enabled=False alone: PromptManager._guard() short-circuits on it
    (prompt_manager.py:132), and this script skips the detector and the
    output validator to match.

    ON is config.yaml VERBATIM -- sanitize, isolate, validate,
    retry_on_break, fence_on_detect and the detector stay exactly as the
    operator set them in the file. Nothing is forced here, so "on" is the
    guardrail that is actually deployed rather than a subset this script
    picked; apply_guard() is deliberately NOT used, since it forces
    validate/retry_on_break off and would hide the output-side cost.
    """
    import dataclasses
    config.guardrail = dataclasses.replace(config.guardrail, enabled=on)


def _build_validator(config):
    """The output validator, built as session.py does (session.py:430-432) --
    only when config.yaml asks for it."""
    if not config.guardrail.validate:
        return None
    from guardrail.validator import OutputValidator
    return OutputValidator()


def _build_cowrie_fallback(config):
    """Cowrie, for the last step of a break: session.py hands a still-broken
    answer to the real emulator (session.py:412-415), which cannot break
    character. Only built when config.yaml has Cowrie enabled -- in a
    single-agent on_device/cloud run there is no Cowrie to fall back to, and
    pretending otherwise would measure a path production does not have.
    Not fatal if the container is down; the run then just skips that step.
    """
    # Nothing can reach the fallback with no validator to detect a break, and
    # building it would open an SSH connection per run for nothing.
    if not config.guardrail.validate or not config.agents.cowrie.enabled:
        return None
    try:
        agent, _kind = build_agent("cowrie", config)
        return agent
    except Exception as e:
        print(f"  [warn] no Cowrie fallback ({type(e).__name__}: {e}); "
              f"breaks that survive the retry stop at the retry")
        return None


def _ms(v) -> str:
    """A latency cell that stays column-aligned when the call failed."""
    return f"{v:>6.0f}m" if isinstance(v, (int, float)) else f"{'--':>7}"


def _failed(out) -> bool:
    """CloudAgent.send() swallows network errors and returns "" instead of
    raising (agent_manager/cloud_agent.py:140-152, no retry) -- that empty
    string is a failed call, not a fast one, so it must not count as a real
    latency sample. ask()'s own except returns "<ERROR ...>" for anything
    that does raise."""
    return not out or str(out).startswith("<ERROR ")


def _answer(agent, built_kind, config, text, flagged, validator, cowrie):
    """One answer, with the OUTPUT side as session.py:385-417 does it.

    validate -> if the answer broke persona, make the model guess AGAIN (same
    prompt, a second full LLM call) -> if it is still broken, hand it to
    Cowrie. This is the expensive half of the guardrail and the benchmark used
    to leave it out entirely, so "overhead" covered only the prompt side.

    Mirrors session.py, not validator.py's harness: validate(out) with no
    prompt argument, and `broke_persona` (Zou et al.'s 29 refusal prefixes),
    which is what the live path checks.
    """
    out = ask(agent, built_kind, config, text, flagged=flagged)
    if validator is None or _failed(out):
        return out
    broke = validator.validate(out)
    if not broke.broke_persona:
        return out
    if config.guardrail.retry_on_break:
        retry = ask(agent, built_kind, config, text, flagged=flagged)
        if not _failed(retry) and not validator.validate(retry).broke_persona:
            return retry
        out = retry
    if cowrie is not None:
        try:
            fallback, _ = cowrie.send(text)
        except Exception:
            return out
        return fallback or out
    return out


def _ask_once(agent_cache, config, text, detector, validator, cowrie):
    """One real request, agent resolved from the warm cache -- shared by both
    guard conditions so neither gets a cold-start advantage. When `detector`
    is not None, its classify() call (shell/session.py:895's real per-command
    guardrail check) is timed too -- that inference is the thing this script
    is supposed to measure the cost of, and previously never ran at all.
    Returns (elapsed_ms, ok, flagged, kind) -- ok=False means exclude this
    sample, a failed call's latency is not a real data point; kind is the agent
    the router picked, recorded per row."""
    # ALWAYS through the router, never a forced agent: which agent answers is
    # config.yaml's decision (agents.*.enabled), the same way production
    # decides it. With one agent enabled this is router.py:180's single-agent
    # mode and returns that agent for every command; with several it is real
    # HydraPoT routing.
    from core.router import classify
    kind = classify(text, [])
    if kind not in agent_cache:
        agent_cache[kind] = build_agent(kind, config)
    agent, built_kind = agent_cache[kind]
    t0 = time.perf_counter()
    # Matches shell/session.py:881-897: the gate first (a command Cowrie
    # answers never reaches the detector -- skipped there "BELOW the
    # boundary"), then SCORE, and only a flagged command is sanitised and
    # fenced. Passing flagged=False and letting the guard rewrite every prompt
    # measured the model answering different text, not the detector: the
    # rewritten prompt changes what the model generates, which moved latency
    # far more than the detector's own inference did.
    flagged = False
    if detector is not None and kind != "cowrie":
        flagged = bool(detector.classify(text).is_attack)
    out = _answer(agent, built_kind, config, text, flagged, validator, cowrie)
    elapsed = (time.perf_counter() - t0) * 1000.0
    return elapsed, not _failed(out), flagged, kind


def _snapshot(path, meta, ms, failed, n_flagged, rows):
    """Write the WHOLE result file, from scratch, after every command.

    One file, always valid JSON, always current: the run can be read live and
    a killed run still leaves a usable result instead of nothing. Rewriting
    ~60KB a couple of hundred times is free next to a 1.5s LLM call.

    Written to a .tmp and renamed, because os.replace is atomic -- a reader
    tailing the file never catches it half-written.
    """
    results = {"off": _stats(ms[False]), "on": _stats(ms[True]),
               "failed_off": failed[False], "failed_on": failed[True],
               "flagged_on": n_flagged}
    off, on = results["off"]["mean_ms"], results["on"]["mean_ms"]
    results["overhead_ms"] = on - off
    results["overhead_pct"] = (on - off) / off * 100 if off else float("nan")
    results["rows"] = rows          # last, so the aggregate stays on top
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({**meta, **results}, fh, indent=2)
    os.replace(tmp, path)
    return results


def run_one(arm, cases, config, path, meta):
    # Build/load every agent, and the detector, ONCE, up front, and reuse
    # the same warm instances for every timing. Guard state only flows
    # through config at ask()-time (build_agent() doesn't take it), so this
    # is safe.
    agent_cache = {}
    _set_detector(config, arm)
    detector = _build_detector(config)
    validator = _build_validator(config)
    cowrie = _build_cowrie_fallback(config)
    print(f"  detector: provider={config.guardrail.detector.provider} "
          f"model={config.guardrail.detector.model or '<arm default>'}")
    print(f"  output side: validate={config.guardrail.validate} "
          f"retry_on_break={config.guardrail.retry_on_break} "
          f"cowrie_fallback={cowrie is not None}")

    # Interleave guard off/on per prompt, alternating which one goes first,
    # instead of running the whole dataset off-then-on. A fixed off-first
    # order lets ANY drift across the run -- cache warm-up, GPU clock
    # ramp-up, thermal throttling -- show up as fake "overhead", since
    # on=second always benefits from it. Alternating gives both conditions
    # equal exposure to "goes first" across the dataset, so drift cancels
    # out instead of masquerading as the guardrail's cost. Each prompt's two
    # latencies therefore come from adjacent calls, which is also what makes
    # the per-row overhead_ms below a fair within-command comparison.
    ms = {False: [], True: []}
    failed = {False: 0, True: 0}
    n_flagged = 0
    rows = []
    # Every command is printed as it finishes and the result file is rewritten,
    # so a long run can be watched live instead of looking frozen for the ~12
    # minutes 247 prompts take.
    for i, (dataset, category, text) in enumerate(cases):
        order = (False, True) if i % 2 == 0 else (True, False)
        row = {"dataset": dataset, "category": category, "cmd": text,
               "routed_to": None, "ms_off": None, "ms_on": None,
               "overhead_ms": None, "flagged": False,
               # Which condition ran first for THIS prompt. Recorded so the
               # alternation can be checked after the fact rather than trusted.
               "first": "on" if order[0] else "off"}
        for guard_on in order:
            # Only `enabled` is toggled; every other layer stays as config.yaml
            # set it. Guard-off therefore skips the detector and the output
            # validator too, matching session.py:427's own _guard_on gate.
            _set_guard(config, guard_on)
            d = detector if guard_on else None
            v = validator if guard_on else None
            c = cowrie if guard_on else None
            elapsed, ok, flagged, kind = _ask_once(agent_cache, config, text,
                                                   d, v, c)
            row["routed_to"] = kind
            row["ms_on" if guard_on else "ms_off"] = (round(elapsed, 1) if ok
                                                      else None)
            if guard_on:
                row["flagged"] = bool(flagged)
            if ok:
                ms[guard_on].append(elapsed)
            else:
                failed[guard_on] += 1
            n_flagged += flagged
        if row["ms_off"] is not None and row["ms_on"] is not None:
            row["overhead_ms"] = round(row["ms_on"] - row["ms_off"], 1)
        rows.append(row)

        d = row["overhead_ms"]
        delta = f"{d:>+6.0f}m" if d is not None else f"{'failed':>7}"
        print(f"  {i + 1:>4}/{len(cases)}  {dataset[:18]:<18}"
              f" off {_ms(row['ms_off'])}  on {_ms(row['ms_on'])}"
              f"  d {delta}  {'FLAG' if row['flagged'] else '    '}  "
              f"{str(row['routed_to']):<9} {text[:46]!r}", flush=True)
        _snapshot(path, meta, ms, failed, n_flagged, rows)

    if failed[False] or failed[True]:
        print(f"  [warn] excluded failed calls from timing: "
              f"off={failed[False]} on={failed[True]}")
    # The unflagged guard-on calls sent the SAME prompt as guard-off, so their
    # difference is the detector alone. A flagged one was rewritten on purpose
    # -- production does that too -- so a high count means the number mixes
    # the detector's cost with the model answering fenced text.
    print(f"  detector flagged {n_flagged}/{len(cases)} guard-on prompts "
          f"(those were sanitised + fenced; the rest got the same prompt as "
          f"guard-off)")

    # Final write. Identical to the per-command ones -- the file has been
    # complete and valid all along; this is just the last of them. Rows carry
    # each prompt's dataset, category, routed agent and both latencies, so the
    # result can be re-cut by dataset or category (Scope and MaliciousInstruct
    # are two different populations) without paying for 247 agent calls again.
    return _snapshot(path, meta, ms, failed, n_flagged, rows)


def _arms_from(spec: str) -> list[str]:
    """`--arms all` means every arm the registry knows.

    Read from guardrail/detector_arm's registry rather than a list kept here,
    so dropping a new arm module in there makes it testable without editing
    this file. The DEFAULT stays the two-arm subset: `all` is 4 arms x 3
    pipelines of real agent calls, which is not what a bare run should cost.
    """
    if spec.strip().lower() == "all":
        from guardrail import detector_arm
        return detector_arm.names()
    return [a.strip() for a in spec.split(",") if a.strip()]


_SMOKE_DEFAULT = 5          # prompts per dataset when --smoke names no count


def _smoke_limit(spec) -> int:
    """Prompts per dataset, 0 meaning the whole dataset.

    The full run is the default because that is what the paper needs; a smoke
    test is the exception and has to ask. `--smoke`, `--smoke true` and
    `--smoke 20` are all accepted -- a full run is expensive enough that
    rejecting it over the spelling of a flag just wastes a launch.
    """
    if spec is None:
        return 0
    s = str(spec).strip().lower()
    if s in ("", "true", "yes", "on"):
        return _SMOKE_DEFAULT
    if s in ("false", "no", "off"):
        return 0
    try:
        return max(0, int(s))
    except ValueError:
        raise SystemExit(f"--smoke: want a count or true/false, got {spec!r}")


CONFIG_PATH = os.path.join(_ROOT, "config.yaml")

# Which agents each pipeline leaves enabled in config.yaml. One agent enabled
# is router.py:180's single-agent mode -- every command goes there with no
# routing decision, which is exactly a forced run. All three is real routing.
PIPELINE_AGENTS = {
    "on_device": {"cowrie": False, "on_device": True,  "cloud": False},
    "cloud":     {"cowrie": False, "on_device": False, "cloud": True},
    "hydrapot":  {"cowrie": True,  "on_device": True,  "cloud": True},
}


def _arm_default_model(arm: str) -> str:
    """The arm's OWN checkpoint, so config.yaml truthfully says what ran.

    Every arm resolves `cfg["model"] or DEFAULT_MODEL`, so leaving another
    arm's id in detector.model silently loads the wrong weights -- a protectai
    run would score Llama-Prompt-Guard-2-86M and still call itself protectai.
    """
    from guardrail import detector_arm
    want = (arm or "").strip().lower()
    for a in detector_arm.ARMS:
        if want == a.NAME or want in a.ALIASES:
            return a.DEFAULT_MODEL
    raise SystemExit(f"unknown guardrail arm: {arm!r}; "
                     f"choose from {detector_arm.names()}")


def _rewrite_config(text: str, arm: str, agents: dict) -> str:
    """config.yaml with detector.provider/model and agents.*.enabled set.

    A TARGETED LINE EDIT, not a yaml round-trip: config.yaml carries comments
    explaining why half its values are what they are, and safe_load/dump would
    delete every one of them. Only the handful of lines below change; byte for
    byte, nothing else does.
    """
    lines = text.splitlines(keepends=True)
    section = None       # current top-level key
    sub = None           # current 2-space key under it
    seen = set()
    model = _arm_default_model(arm)

    def _put(i, raw, indent, key, value):
        end = "\n" if raw.endswith("\n") else ""
        trailing = raw.rstrip("\n").split("#", 1)
        comment = f"   #{trailing[1]}" if len(trailing) > 1 else ""
        lines[i] = f"{' ' * indent}{key}: {value}{comment}{end}"

    for i, raw in enumerate(lines):
        line = raw.rstrip("\n")
        if re.match(r"^\S", line):
            section = line.split(":", 1)[0].strip()
            sub = None
            continue
        m = re.match(r"^  (\w+):\s*$", line)
        if m:
            sub = m.group(1)
            continue
        if section == "agents" and sub in agents:
            if re.match(r"^    enabled:\s*\S+", line):
                _put(i, raw, 4, "enabled", str(agents[sub]).lower())
                seen.add(f"agents.{sub}.enabled")
        elif section == "guardrail" and sub == "detector":
            if re.match(r"^    enabled:\s*\S+", line):
                _put(i, raw, 4, "enabled", "true")
                seen.add("detector.enabled")
            elif re.match(r"^    provider:\s*\S+", line):
                _put(i, raw, 4, "provider", arm)
                seen.add("detector.provider")
            elif re.match(r"^    model:\s*\S+", line):
                _put(i, raw, 4, "model", model)
                seen.add("detector.model")

    need = {f"agents.{a}.enabled" for a in agents} | {
        "detector.enabled", "detector.provider", "detector.model"}
    missing = need - seen
    if missing:
        raise SystemExit("config.yaml is missing " + ", ".join(sorted(missing))
                         + " -- refusing to rewrite it")
    return "".join(lines)


def _pipeline_label(config) -> str:
    """Name the run after what config.yaml ENABLED, not after a CLI flag.

    agents.*.enabled is what decides where a command goes, and core/router.py
    reads it at IMPORT time from the file on disk (router.py:18-24), so it can
    only be set by editing config.yaml -- an in-memory override never reaches
    the router. One agent enabled is router.py's single-agent mode
    (router.py:180): every command goes there with no routing decision at all,
    which is exactly a forced on_device/cloud run. Two or more is real
    HydraPoT routing.
    """
    on = [a for a in ("cowrie", "on_device", "cloud")
          if getattr(config.agents, a).enabled]
    if not on:
        raise SystemExit("config.yaml has every agent disabled -- enable the "
                         "one you want to measure")
    return on[0] if len(on) == 1 else "hydrapot"


def _drive(arms, pipelines, smoke):
    """Rewrite config.yaml per (arm, pipeline) and run a CHILD process on it.

    A fresh interpreter per combination, because core/router.py snapshots
    agents.*.enabled at IMPORT time (router.py:18-33): rewriting the file in a
    running process never reaches classify(), and reloading the module would
    rebuild the shared FIScorer while other modules still hold the old one.

    The child reads the arm and the agent set out of config.yaml, so every
    measured run really did go through the file production reads -- nothing is
    passed around it.

    config.yaml is copied to a .bak first and restored in a finally block, so
    a crash or Ctrl-C cannot leave it pinned to an experiment's settings.
    """
    original = open(CONFIG_PATH, encoding="utf-8").read()
    backup = f"{CONFIG_PATH}.bak.{time.strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(CONFIG_PATH, backup)
    print(f"config.yaml -> backed up to {os.path.basename(backup)}")
    print(f"arms: {', '.join(arms)}")
    print(f"pipelines: {', '.join(pipelines)}\n")

    failures = []
    try:
        for pipeline in pipelines:
            for arm in arms:
                print("=" * 70)
                print(f"  config.yaml: detector.provider={arm}  "
                      f"agents -> " + ", ".join(
                          f"{a}={str(v).lower()}"
                          for a, v in PIPELINE_AGENTS[pipeline].items()))
                print("=" * 70, flush=True)
                with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
                    fh.write(_rewrite_config(original, arm,
                                             PIPELINE_AGENTS[pipeline]))
                cmd = [sys.executable, os.path.abspath(__file__), "--child"]
                if smoke is not None:
                    cmd += ["--smoke", str(smoke)]
                rc = subprocess.run(cmd, cwd=_ROOT).returncode
                if rc != 0:
                    failures.append((arm, pipeline, rc))
                    print(f"  [warn] {arm}/{pipeline} exited {rc}; "
                          f"continuing\n", flush=True)
    finally:
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            fh.write(original)
        print(f"\nconfig.yaml restored (backup kept at "
              f"{os.path.basename(backup)})")

    if failures:
        print("  failed: " + ", ".join(f"{a}/{p} rc={r}"
                                       for a, p, r in failures))
        raise SystemExit(1)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--arms", default=",".join(ARMS),
                    help=f"comma-separated arms (default {','.join(ARMS)}), "
                         f"or 'all' for every arm registered in "
                         f"guardrail/detector_arm/")
    ap.add_argument("--pipelines", default=",".join(PIPELINE_AGENTS),
                    help=f"comma-separated, from {sorted(PIPELINE_AGENTS)}; "
                         f"each one is written into config.yaml's "
                         f"agents.*.enabled before its run")
    ap.add_argument("--smoke", nargs="?", const="true", default=None,
                    help=f"shrink to a smoke test: --smoke takes "
                         f"{_SMOKE_DEFAULT} prompts per dataset, --smoke N "
                         f"takes N. Omitted, the whole dataset runs.")
    ap.add_argument("--child", action="store_true",
                    help="internal: measure config.yaml exactly as it stands, "
                         "one arm and one pipeline, and write its result")
    args = ap.parse_args()

    if not args.child:
        pipelines = [p.strip() for p in args.pipelines.split(",") if p.strip()]
        unknown = [p for p in pipelines if p not in PIPELINE_AGENTS]
        if unknown:
            raise SystemExit(f"unknown pipeline(s) {unknown}; "
                             f"choose from {sorted(PIPELINE_AGENTS)}")
        return _drive(_arms_from(args.arms), pipelines, args.smoke)

    from core.config_loader import load_config
    from guardrail import eval_datasets as ds

    limit = _smoke_limit(args.smoke)
    # (dataset, category, text) -- the dataset name and the case's own category
    # are carried into every row, so a result can be cut by either.
    cases = []
    for name, c in ds.cases_by_dataset():
        for cat, _label, text in (c[:limit] if limit else c):
            cases.append((name, cat, text))

    # Both come OUT of config.yaml, not off the command line: the parent wrote
    # them there, and reading them back is what proves the run used the file
    # production reads rather than a value passed around it.
    config = load_config()
    pipeline = _pipeline_label(config)
    arm = config.guardrail.detector.provider
    print(f"{len(cases)} prompts per condition"
          f"{f'  (SMOKE: {limit} per dataset)' if limit else '  (full dataset)'}")
    print(f"pipeline: {pipeline}   arm: {arm}   "
          f"(both from config.yaml)\n")

    arm_dir = os.path.join(OUT_DIR, f"{arm}_overhead")
    os.makedirs(arm_dir, exist_ok=True)
    path = os.path.join(arm_dir, f"{pipeline}.json")
    meta = {"arm": arm, "pipeline": pipeline, "n_prompts": len(cases),
            "detector_model": config.guardrail.detector.model,
            "validate": config.guardrail.validate,
            "retry_on_break": config.guardrail.retry_on_break}
    print(f"=== {arm} / {pipeline} ===")
    # Rewritten after every command, so this is readable while the run goes.
    print(f"  live -> {os.path.relpath(path, _ROOT)}")
    r = run_one(arm, cases, config, path, meta)
    print(f"\n  off: {r['off']['mean_ms']:.1f} ms   "
          f"on: {r['on']['mean_ms']:.1f} ms   "
          f"overhead: {r['overhead_ms']:+.1f} ms "
          f"({r['overhead_pct']:+.1f}%)")
    print(f"  wrote {path}\n")


if __name__ == "__main__":
    main()
