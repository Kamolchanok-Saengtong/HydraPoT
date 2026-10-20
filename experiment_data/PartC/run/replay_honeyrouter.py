"""
experiment_data/PartC/replay_honeyrouter.py — build the HoneyRouter arm by REPLAY, not re-run.
─────────────────────────────────────────────────────────────────────────────────
We already collected cowrie / on_device / cloud responses for every command
(the three forced arms). Re-running the live agents is unnecessary (and cloud
is currently unavailable). Instead we replay all sessions through the REAL
HydraPoT pipeline (main.handle) — full production logic: classify() routing,
_needs_llm overrides, deterministic handlers, cd/state tracking, impactful
(FI) processing — but the three agents are replaced by LOOKUP STUBS that
return the response that agent already produced for that exact (session_id,
position). The pipeline runs exactly as in production; only the source of each
agent's text is a lookup instead of a live call.

Result: honeyrouter.jsonl whose `routed_to` is the real routing decision and
whose `response` is the real production output (deterministic-handler canned
replies included), assembled with zero live agent calls — no GPU, no Cowrie
connection, no cloud API.

Arm sources (edit if you re-collect an arm):
    cowrie    -> results/fidelity_full109_final/cowrie.jsonl      (real container)
    on_device -> results/fidelity_20260723_135641/on_device.jsonl (Qwen3.5-9B)
    cloud     -> results/fidelity_cloud_new_20260728_131019/cloud.jsonl  (deepseek-v4-flash)

Usage:
    python experiment_data/PartC/replay_honeyrouter.py
    python experiment_data/PartC/replay_honeyrouter.py --limit 3     # smoke test: first 3 sessions
─────────────────────────────────────────────────────────────────────────────────
"""

import os
import sys
import json
import types
import argparse
from datetime import datetime

# PartC/, not this sub-folder: every path below is relative to the part.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NSC  = os.path.abspath(os.path.join(_HERE, ".."))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for p in (_ROOT, _NSC, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)
sys.path.insert(0, os.path.join(_NSC, "PartA"))

# config_loader reads config.yaml by relative path -> must run from project root
if os.path.abspath(os.getcwd()) != _ROOT:
    os.chdir(_ROOT)

from overhead import _FakeChannel          # noqa: E402
from core.config_loader import load_config       # noqa: E402
import main as hp                           # noqa: E402

# Route each arm's log to its own Part folder (see _paths.py).
from _paths import session_dir_for



RESULTS_DIR = os.path.join(_HERE, "..", "results", "partC")
DEFAULT_SESSIONS = os.path.join(_ROOT, "dataset", "partC_stateful_sessions.json")

# ── arm sources (the three forced-arm runs we already have) ───────────────────
ARM_FILES = {
    "cowrie":    os.path.join(RESULTS_DIR, "fidelity_full109_final",   "cowrie.jsonl"),
    "on_device": os.path.join(RESULTS_DIR, "fidelity_20260723_135641", "on_device.jsonl"),
    "cloud":     os.path.join(RESULTS_DIR, "fidelity_cloud_new_20260728_131019", "cloud.jsonl"),  # deepseek-v4-flash
}


# ── lookup tables: (session_id, position_in_session) -> record ────────────────
def _build_lut(path):
    lut = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            lut[(r["session_id"], r["position_in_session"])] = r
    return lut


def _usage_from(rec):
    if rec is None:
        return None
    keys = ("prompt_tokens", "completion_tokens", "total_tokens",
            "cost", "cache_hit_tokens", "cache_miss_tokens")
    u = {k: rec.get(k) for k in keys}
    return u if any(v is not None for v in u.values()) else None


# ── replay stubs: same interface as the real agents, but text comes from LUT ──
class _CowrieStub:
    """Matches CowrieAgent surface used by main.handle():
       .send(cmd) -> (output, _); plus no-op .shell.send / ._collect_until_prompt
       / ._connect / .disconnect for sync_history() housekeeping."""
    def __init__(self, lut, ctx):
        self.lut = lut
        self.ctx = ctx
        self.shell = types.SimpleNamespace(send=lambda *a, **k: None)

    def _connect(self):                     return None
    def _collect_until_prompt(self, *a, **k): return ""
    def disconnect(self):                   return None

    def send(self, cmd):
        rec = self.lut.get((self.ctx["sid"], self.ctx["pos"]))
        return ((rec["response"] if rec else ""), None)


class _LLMStub:
    """Matches on_device/cloud surface: .send(sys,usr)->str and
       .send_with_usage(sys,usr)->(text, usage)."""
    def __init__(self, lut, ctx, name):
        self.lut = lut
        self.ctx = ctx
        self.name = name
        self._miss = 0

    def _rec(self):
        rec = self.lut.get((self.ctx["sid"], self.ctx["pos"]))
        if rec is None:
            self._miss += 1
        return rec

    def send(self, system_prompt, user_prompt):
        rec = self._rec()
        return rec["response"] if rec else ""

    def send_with_usage(self, system_prompt, user_prompt):
        rec = self._rec()
        return (rec["response"] if rec else ""), _usage_from(rec)


def load_sessions(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data["sessions"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", default=DEFAULT_SESSIONS)
    ap.add_argument("--limit", type=int, default=None,
                    help="only replay the first N sessions (smoke test)")
    ap.add_argument("--out", default=None, help="output dir (default: auto timestamp)")
    args = ap.parse_args()

    # ── load luts ─────────────────────────────────────────────────────────────
    for arm, path in ARM_FILES.items():
        if not os.path.exists(path):
            print(f"[replay] MISSING arm source for {arm}: {path}")
            sys.exit(1)
    luts = {arm: _build_lut(path) for arm, path in ARM_FILES.items()}
    print(f"[replay] loaded luts: " +
          ", ".join(f"{a}={len(l)}" for a, l in luts.items()))

    # ── wire main's globals to config + stubs (no live agents) ─────────────────
    ctx = {"sid": None, "pos": None, "cmd": None}
    hp.config   = load_config()
    hp.ondevice = _LLMStub(luts["on_device"], ctx, "on_device")
    hp.cloud    = _LLMStub(luts["cloud"], ctx, "cloud")
    cowrie_stub = _CowrieStub(luts["cowrie"], ctx)

    sessions = load_sessions(args.sessions)
    if args.limit:
        sessions = sessions[:args.limit]
    total_cmds = sum(len(s["commands"]) for s in sessions)
    print(f"[replay] {len(sessions)} sessions, {total_cmds} commands")

    run_id  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.out or os.path.join(RESULTS_DIR, f"honeyrouter_replay_{run_id}")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "honeyrouter.jsonl")
    fout = open(out_path, "w", encoding="utf-8")

    from collections import Counter
    routed_counter = Counter()
    n = 0
    miss = 0

    for session in sessions:
        sid = session["session_id"]
        # fresh handle per session -> fresh SYSTEM_STATE (same as ground-truth
        # collection's reset-between-sessions behaviour)
        handle = hp.make_command_handler(
            cowrie_stub, src_ip=f"hrreplay_{sid}", public_ip=f"hrreplay_{sid}",
            plugins=None, capture_cost=True,
            store="json", store_dir=session_dir_for(f"hrreplay_{sid}", __file__),
        )
        for pos, c in enumerate(session["commands"]):
            if c.get("blocked"):
                continue
            cmd = c["cmd"]
            ctx["sid"], ctx["pos"], ctx["cmd"] = sid, pos, cmd

            ch = _FakeChannel()
            try:
                ret = handle(cmd, ch.write, ch.read)   # force_agent=None -> real routing
                ok = True
            except Exception as e:
                ret, ok = ("", ""), False
                print(f"[replay] handle error on {cmd!r}: {e}")

            output = ret[0] if isinstance(ret, tuple) else ret
            response = (output if output else ch.text()) or ""
            routed_to  = getattr(handle, "last_agent", "unknown")
            usage      = getattr(handle, "last_usage", None)
            state_size = getattr(handle, "state_size", None)

            # sanity: did the chosen agent actually have a collected response?
            if routed_to in luts and (sid, pos) not in luts[routed_to]:
                miss += 1

            routed_counter[routed_to] += 1
            rec = {
                "run_id": run_id, "trial": 0,
                "session_id": sid, "position_in_session": pos, "cmd": cmd,
                "source": session.get("source"), "fi_score": c.get("fi"),
                "ground_truth": c.get("ground_truth"),
                "arm": "honeyrouter", "routed_to": routed_to,
                "response": response.strip() if response else response,
                "ok": ok,
                "prompt_tokens":     usage.get("prompt_tokens")     if usage else None,
                "completion_tokens": usage.get("completion_tokens") if usage else None,
                "total_tokens":      usage.get("total_tokens")      if usage else None,
                "cost":              usage.get("cost")              if usage else None,
                "cache_hit_tokens":  usage.get("cache_hit_tokens")  if usage else None,
                "cache_miss_tokens": usage.get("cache_miss_tokens") if usage else None,
                "state_size": state_size,
            }
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1

    fout.close()
    print(f"\n[replay] wrote {n} records -> {out_path}")
    print(f"[replay] routing distribution: {dict(routed_counter)}")
    if miss:
        print(f"[replay] WARNING: {miss} commands routed to an agent with no "
              f"collected response for that (session,pos) — check arm coverage")


if __name__ == "__main__":
    main()
