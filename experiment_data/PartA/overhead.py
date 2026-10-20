"""
experiment_data/overhead.py — Architecture Overhead measurement (Part A)
─────────────────────────────────────────────────────────────────
ONE callable: run_overhead(agents, commands, trials, measures)

Idea:
  For each command, we measure SEVEN arms — cowrie/on_device/cloud each run
  twice (pure vs. inside HydraPoT), plus HoneyRouter's own natural routing:

    - "cowrie_pure":         raw Cowrie, no HydraPoT at all —
                              agents.direct_pure("cowrie", cmd)
    - "on_device_pure":      raw on-device LLM, no HydraPoT at all —
                              agents.direct_pure("on_device", cmd)
    - "cloud_pure":          raw cloud LLM, no HydraPoT at all —
                              agents.direct_pure("cloud", cmd)
    - "cowrie_hydrapot":     same agent, forced through HydraPoT's real
                              pipeline — agents.handle_cowrie(cmd, ..., force_agent="cowrie")
    - "on_device_hydrapot":  agents.handle_on_device(cmd, ..., force_agent="on_device")
    - "cloud_hydrapot":      agents.handle_cloud(cmd, ..., force_agent="cloud")
    - "honeyrouter":         full HydraPoT pipeline, natural routing via
                              classify() — agents.handle(cmd, ...) (HoneyRouter, 100% real)

  Overhead per agent type = *_hydrapot vs *_pure for the same command: the
  hydrapot arm carries the SSH-server proxy, router/classify, PromptManager's
  hydrapot-flavored prompt, real SYSTEM_STATE mutation and FI scoring — the
  pure arm carries none of that.

  "Pure" is deliberately zero HydraPoT involvement, not just "stateless":
    - cowrie_pure   -> raw SSH send straight to the Cowrie container
    - on_device_pure/cloud_pure -> the LLM gets the mrheinen dataset's own
      "instruction" field (the dataset author's generic terminal-emulation
      prompt) instead of HydraPoT's PromptManager. No hostname/OS persona,
      no Hi/SRi history, no SYSTEM_STATE of any kind — see
      Agents.direct_pure() in agents.py.

  Each *_hydrapot arm is its OWN make_command_handler() closure with an
  isolated SYSTEM_STATE/fi_manager (agents.handle_cowrie/handle_on_device/
  handle_cloud) — not shared with each other or with the honeyrouter arm's
  `agents.handle`. Same isolation pattern as run_partC.py's
  _make_arm_sessions(). The agent that actually ran for the honeyrouter arm
  is read back AFTER agents.handle() runs, via handle.last_agent — never
  guessed via agents.route().

Pluggable measurement:
  `measures` is a list of measurement functions. Each one wraps a call and
  returns a dict of fields. Today: [latency, resources]. Later you add
  tokens, fidelity, etc. WITHOUT touching this file.

  A measure has signature:  measure(fn, *args, **kwargs) -> (result, fields_dict)

Usage:
    from agents import build_agents
    from overhead import run_overhead, latency
    from workloads import load_mrheinen_raw

    ag      = build_agents()
    cmds    = load_mrheinen_raw()
    records = run_overhead(ag, cmds, trials=1, measures=[latency])
─────────────────────────────────────────────────────────────────
"""

import os
import json
import time


# ─── Fake SSH channel (handle() writes streamed output here) ──────────────────

class _FakeChannel:
    def __init__(self):
        self._buf = []
    def write(self, s):           # write_fn
        self._buf.append(s)
    def read(self, *_a, **_k):    # read_fn (interactive path, unused in A)
        return ""
    def text(self):
        return "".join(self._buf)


# ─── PLUGGABLE MEASURES ───────────────────────────────────────────────────────
# Each measure wraps a call and returns (result, {fields}).
# Add new ones here or in your own module; pass them in `measures=[...]`.

def latency(fn, *args, **kwargs):
    """Wall-clock latency in ms."""
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    ms = round((time.perf_counter() - t0) * 1000, 2)
    return result, {"latency_ms": ms}


def resources(fn, *args, **kwargs):
    """
    CPU% (sampled across the call), process RAM, and GPU VRAM — all captured
    around a SINGLE execution of fn. GGUF-safe (VRAM via nvidia-smi).
    """
    import os as _os, sys as _sys
    _r = _os.path.abspath(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', '..'))
    if _r not in _sys.path:
        _sys.path.insert(0, _r)   # measure.py is at the project root
    import measure as M
    ram_before  = round(M.get_ram_mb(), 2)
    vram_before = M.get_vram_mb()
    sampler = M.CPUSampler().start()

    result = fn(*args, **kwargs)

    cpu_pct    = sampler.stop()
    ram_after  = round(M.get_ram_mb(), 2)
    vram_after = M.get_vram_mb()
    return result, {
        "cpu_pct":        cpu_pct,
        "ram_after_mb":   ram_after,
        "ram_delta_mb":   round(ram_after - ram_before, 2),
        "vram_after_mb":  vram_after,
        "vram_delta_mb":  (round(vram_after - vram_before, 2)
                           if (vram_before is not None and vram_after is not None)
                           else None),
    }


# default measure set for Part A: everything.
ALL_MEASURES = [latency, resources]


def _apply_measures(fn, args, measures):
    """
    Run `fn(*args)` once, collecting fields from every measure.

    NOTE: measures wrap the SAME logical call, but each wrapper calls fn itself.
    To avoid running fn N times, we run fn ONCE under the first measure and reuse
    its timing; remaining measures that need their own execution are layered by
    composing around the first. For simplicity and correctness we execute fn
    once per measure ONLY if a measure needs to (latency/cpu must time the real
    call). Default path uses a single measure (latency), one execution.

    For multiple measures we nest: the outermost measure times the inner stack.
    """
    if not measures:
        return fn(*args), {}

    fields = {}
    call = fn
    call_args = args

    for m in reversed(measures):
        inner_call = call
        inner_args = call_args
        def make(m, inner_call, inner_args):
            def wrapped():
                res, f = m(inner_call, *inner_args)
                fields.update(f)
                return res
            return wrapped
        call = make(m, inner_call, inner_args)
        call_args = ()

    result = call()
    return result, fields


# ─── output routing: one subfolder per arm, results/architecture_overhead/ ────

AGENT_TYPES  = ("cowrie", "on_device", "cloud")
# Arm LABELS (also the result-folder names). "standalone_*" is the bare agent
# OUTSIDE the HydraPoT pipeline; "*_hydrapot" is the same agent THROUGH it. The
# on-device agent is labelled "local" everywhere the experiment is read/plotted.
_LABEL = {"cowrie": "cowrie", "on_device": "local", "cloud": "cloud"}
PURE_ARMS     = tuple(f"standalone_{_LABEL[a]}" for a in AGENT_TYPES)
HYDRAPOT_ARMS = tuple(f"{_LABEL[a]}_hydrapot" for a in AGENT_TYPES)
ALL_ARMS      = PURE_ARMS + HYDRAPOT_ARMS + ("honeyrouter",)


def _clean_cloud_latency(rec, agents, is_cloud):
    """Use the successful-request time for cloud, so proxy 502 retries/waits
    (a measurement artefact) don't inflate the latency."""
    if is_cloud:
        clean = getattr(getattr(agents, "cloud", None), "last_request_ms", None)
        if clean is not None:
            rec["latency_ms"] = round(clean, 2)


def make_arm_writers(results_dir, run_id, arms=None):
    """
    Returns (writer_fn, close_fn).

    writer_fn(rec) appends rec, pretty-printed, to:
      results/partA/{arm}/{arm}.jsonl
    based on rec["arm"] (folder name == arm label, one-to-one). No timestamp in
    the path: a rerun overwrites the same files, so results never pile up.
    run_id is still recorded INSIDE each record for provenance.

    Each record is a full pretty-printed JSON object (indent=2) followed by a
    blank line, so the file is human-readable; read with json.loads per
    blank-line-separated block.
    close_fn() closes all open file handles.
    """
    base_dir = results_dir

    handles = {}
    for arm in (arms or ALL_ARMS):
        arm_dir = os.path.join(base_dir, arm)
        os.makedirs(arm_dir, exist_ok=True)
        path = os.path.join(arm_dir, f"{arm}.jsonl")
        handles[arm] = open(path, "a")        # append — a new trial extends the file

    def writer_fn(rec):
        arm = rec.get("arm", "unknown")
        fh = handles.get(arm)
        if fh is None:
            # unexpected arm label — still capture it instead of losing data
            arm_dir = os.path.join(base_dir, arm)
            os.makedirs(arm_dir, exist_ok=True)
            path = os.path.join(arm_dir, f"{arm}.jsonl")
            fh = handles[arm] = open(path, "a")
        fh.write(json.dumps(rec, indent=2, ensure_ascii=False) + "\n\n")
        fh.flush()

    def close_fn():
        for fh in handles.values():
            try:
                fh.close()
            except Exception:
                pass

    return writer_fn, close_fn


# ─── CORE: the one function you call ──────────────────────────────────────────

def run_overhead(agents, commands, trials=30, measures=None, warmup=3,
                 exclude=None, on_record=None, trial_offset=0, arms=None):
    """
    Measure architecture overhead for each command, SEVEN arms.

    Args:
      agents    : bundle from build_agents() — needs .direct_pure(agent_name, cmd),
                  .handle_cowrie/.handle_on_device/.handle_cloud (force-routed,
                  isolated per arm), .handle (natural routing, honeyrouter)
      commands  : list of (fi_band, command_str) OR list of command_str
      trials    : repetitions per command (report percentiles downstream)
      measures  : list of measure fns; default ALL_MEASURES
      warmup    : unrecorded calls to prime models/caches
      exclude   : set of command base-words to skip (interactive cmds)
      on_record : optional callback(record_dict) — e.g. write JSONL live.
                  Use make_arm_writers() to get a writer that splits by arm
                  into results/architecture_overhead/{arm}/{arm}_{run_id}.jsonl

    Returns:
      list of record dicts:
        {arm, agent, fi_band, command, trial, response, ok, **measured_fields}

      arm is one of: "cowrie_pure"/"on_device_pure"/"cloud_pure" (zero
      HydraPoT involvement), "cowrie_hydrapot"/"on_device_hydrapot"/
      "cloud_hydrapot" (forced through HydraPoT's real pipeline), or
      "honeyrouter" (real HoneyRouter routing decision via classify()).
      agent is the agent that actually executed the command for that row —
      for pure/hydrapot arms agent == the agent type (forced); for
      "honeyrouter" it's whatever handle.last_agent reports (the real router
      decision, never guessed/predicted).
      response is the actual text the agent returned (truncated to 2000
      chars to keep files sane; full output still available via re-running
      that single command if you need it raw).
    """
    if measures is None:
        measures = ALL_MEASURES
    # arms: which of ALL_ARMS to measure. Re-measuring one arm must not
    # re-pay for the other six, and must not touch their logs.
    _sel = set(arms) if arms else set(ALL_ARMS)
    _unknown = _sel - set(ALL_ARMS)
    if _unknown:
        raise ValueError(f"unknown arm(s) {sorted(_unknown)}; pick from {ALL_ARMS}")

    if exclude is None:
        exclude = {"passwd", "adduser", "useradd", "userdel",
                   "vim", "vi", "nano", "emacs", "top", "less", "more"}

    # normalize commands to (fi_band, cmd)
    norm = []
    for c in commands:
        if isinstance(c, (tuple, list)):
            norm.append((c[0], c[1]))
        else:
            norm.append((None, c))

    records = []

    def _emit(rec):
        records.append(rec)
        if on_record:
            on_record(rec)

    def _clip(text, limit=2000):
        if text is None:
            return None
        text = str(text)
        return text if len(text) <= limit else text[:limit] + f"...[truncated, {len(text)} chars total]"

    def _unwrap(ret):
        """
        handle() always returns a (output, "") tuple (see main.py _finish()),
        same contract agents.direct_pure() relies on via `out, _ = self.cowrie.send(cmd)`.
        Pull just the output string back out so we never str()-ify the raw tuple
        into the logged response (that's what produced response strings like
        "('bash: /bin/busybox: command not found', '')").
        """
        if isinstance(ret, tuple):
            return ret[0] if ret else None
        return ret

    def _hydrapot_handle(agent_type):
        return getattr(agents, f"handle_{agent_type}")

    # ── warmup (not recorded) ─────────────────────────────────────────────────
    # Warm up every one of the 7 call paths once, so first-call model-loading/
    # connection latency doesn't pollute trial 0.
    for _, cmd in norm[:max(0, warmup)]:
        try:
            fch = _FakeChannel()
            agents.handle(cmd, fch.write, fch.read)
        except Exception:
            pass
        for agent_type in AGENT_TYPES:
            try:
                agents.direct_pure(agent_type, cmd)
            except Exception:
                pass
            try:
                fch = _FakeChannel()
                _hydrapot_handle(agent_type)(cmd, fch.write, fch.read,
                                             force_agent=agent_type)
            except Exception:
                pass

    # ── measured trials ───────────────────────────────────────────────────────
    for fi_band, cmd in norm:
        base = cmd.strip().split()[0] if cmd.strip() else ""
        if base in exclude:
            continue

        for t in range(trials):
            # ── PURE arms: cowrie/on_device/cloud, zero HydraPoT involvement —
            #    no proxy, no router, no PromptManager, no SYSTEM_STATE ──────
            for agent_type in AGENT_TYPES:
                if f"standalone_{_LABEL[agent_type]}" not in _sel:
                    continue
                try:
                    (out, fields_p) = _apply_measures(
                        agents.direct_pure, (agent_type, cmd), measures
                    )
                    ok_p = True
                except Exception:
                    out, fields_p, ok_p = None, {}, False

                cost_info = getattr(agents, "last_usage", None) if agent_type == "cloud" else None

                rec = {"arm": f"standalone_{_LABEL[agent_type]}", "agent": agent_type, "fi_band": fi_band,
                    "command": cmd, "trial": t + trial_offset, "ok": ok_p,
                    "response": _clip(out), **fields_p}
                if cost_info is not None:
                    rec["cost_info"] = cost_info
                _clean_cloud_latency(rec, agents, agent_type == "cloud")
                _emit(rec)

            # ── HYDRAPOT arms: same agent, forced through main.py's real
            #    handle() — real PromptManager, real SYSTEM_STATE, real FI
            #    scoring. Each agent type has its OWN isolated closure ──────
            for agent_type in AGENT_TYPES:
                if f"{_LABEL[agent_type]}_hydrapot" not in _sel:
                    continue
                handle_fn = _hydrapot_handle(agent_type)
                fch = _FakeChannel()
                _call = lambda hf=handle_fn, c=cmd, ch=fch, a=agent_type: (
                    hf(c, ch.write, ch.read, force_agent=a)
                )
                try:
                    (ret, fields_h) = _apply_measures(_call, (), measures)
                    ok_h = True
                except Exception:
                    ret, fields_h, ok_h = None, {}, False

                streamed_text = fch.text()
                output_only   = _unwrap(ret)
                real_response = output_only if output_only else streamed_text
                cost_info = getattr(handle_fn, "last_usage", None) if agent_type == "cloud" else None

                rec = {"arm": f"{_LABEL[agent_type]}_hydrapot", "agent": agent_type,
                       "fi_band": fi_band, "command": cmd, "trial": t + trial_offset, "ok": ok_h,
                       "response": _clip(real_response),
                       "state_size": getattr(handle_fn, "state_size", None),
                       **fields_h}
                if cost_info is not None:
                    rec["cost_info"] = cost_info
                _clean_cloud_latency(rec, agents, agent_type == "cloud")
                _emit(rec)

            if "honeyrouter" not in _sel:
                continue
            # ── HONEYROUTER arm: full pipeline, 100% real HoneyRouter — main.py's
            #    actual make_command_handler(), natural routing via classify() ──
            fch = _FakeChannel()
            try:
                (ret, fields_r) = _apply_measures(
                    agents.handle, (cmd, fch.write, fch.read), measures
                )
                ok_r = True
            except Exception:
                ret, fields_r, ok_r = None, {}, False

            agent = getattr(agents.handle, "last_agent", "unknown")
            streamed_text = fch.text()
            # handle() returns ("", "") on streamed paths and (output, "") on
            # non-streamed paths. Unwrap the tuple FIRST, then fall back to
            # streamed_text if the unwrapped output is empty — otherwise the
            # raw (output, "") tuple gets str()-ified into the logged response.
            output_only = _unwrap(ret)
            real_response = output_only if output_only else streamed_text
            cost_info = getattr(agents.handle, "last_usage", None) if agent == "cloud" else None

            rec = {"arm": "honeyrouter", "agent": agent, "fi_band": fi_band,
                   "command": cmd, "trial": t + trial_offset, "ok": ok_r,
                   "response": _clip(real_response),
                   "state_size": getattr(agents.handle, "state_size", None),
                   **fields_r}
            if cost_info is not None:
                rec["cost_info"] = cost_info
            _clean_cloud_latency(rec, agents, agent == "cloud")
            _emit(rec)

    return records