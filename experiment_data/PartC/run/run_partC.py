"""
experiment_data/PartC/run_partC.py — Part C: raw data collection (fidelity scoring deferred)
─────────────────────────────────────────────────────────────────
Replays the dataset named by --sessions — real, stateful ml4net
sessions (1658 commands total, real Docker-collected ground truth) —
through 4 agent arms: cowrie/on_device/cloud (forced) + honeyrouter
(natural routing).

Session structure is preserved: commands within a session run through
ONE shared handle, IN ORDER, so state accumulates exactly as it did when
ground truth was collected. Each session gets a FRESH handle (fresh
SYSTEM_STATE) per arm — mirrors collect_ground_truth_sessions.py's
reset-between-sessions / accumulate-within-session behavior. `blocked`
commands are skipped entirely (never sent), same as quick_cloud_check.py.

Collects, per command per arm: response, latency, CPU/RAM/VRAM, token
usage (cloud + on_device), cloud $ cost, and per-arm state_size —
everything needed to later compute fidelity (BERTScore/cosine/exact-match)
and derived cost metrics, without deciding those formulas now. Fidelity
scoring itself is NOT computed here — a separate script scores
ground_truth vs response per record after this run finishes.

Usage:
    python experiment_data/PartC/run_partC.py --sessions dataset/dataset_groundtruth_<N>.json [--trials 1]
    python experiment_data/PartC/run_partC.py --arms on_device
─────────────────────────────────────────────────────────────────
"""

import os
import sys
import json
import time
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

# Experiment keys (API_KEY_*, PARTC_BASE_URL) live in experiment_data/.env,
# kept separate from the repo-root .env production uses.
from core.config_loader import load_dotenv
load_dotenv(os.path.join(_NSC, ".env"), override=True)

from overhead import latency, resources, _apply_measures, _FakeChannel

# Route each arm's log to its own Part folder (see _paths.py).
from _paths import session_dir_for



# No default dataset. This pointed at dataset/partC_stateful_sessions.json,
# a months-old selection whose ground truth was collected one docker exec
# per command, so `cd` never carried over and 73 of its 109 sessions are
# wrong. Reaching for it implicitly is how stale output kept reappearing;
# the dataset is now always named on the command line.


def load_sessions(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data["sessions"], data.get("breakdown", {})


RESULTS_DIR = os.path.join(_HERE, "..", "results", "partC")
ARMS = ("cowrie", "on_device", "cloud", "honeyrouter", "irt_router")


# ─── logger — mirrors every message to stdout AND a run.log file ───────────────

def _make_logger(log_path):
    fh = open(log_path, "a", encoding="utf-8")

    def log(msg):
        print(msg)
        fh.write(msg + "\n")
        fh.flush()   # so `tail -f run.log` shows progress live, not on buffer flush

    def close():
        fh.close()

    return log, close


# ─── writer ─────────────────────────────────────────────────────────────────────

def make_writers(out_dir, arms=ARMS):
    handles = {
        arm: open(os.path.join(out_dir, f"{arm}.jsonl"), "w", encoding="utf-8")
        for arm in arms
    }

    def write(arm, rec):
        handles[arm].write(json.dumps(rec, ensure_ascii=False) + "\n")
        handles[arm].flush()

    def close():
        for fh in handles.values():
            fh.close()
        return out_dir

    return write, close


# ─── one arm call ───────────────────────────────────────────────────────────────

def _run_arm(handle, cmd, force_agent, log=print):
    ch = _FakeChannel()

    def _call():
        if force_agent is not None:
            return handle(cmd, ch.write, ch.read, force_agent=force_agent)
        return handle(cmd, ch.write, ch.read)

    try:
        ret, fields = _apply_measures(_call, (), [latency, resources])
        ok = True
    except Exception as e:
        ret, fields, ok = ("", ""), {}, False
        log(f"[partC] arm error on {cmd!r}: {e}")

    output_only = ret[0] if isinstance(ret, tuple) else ret
    response = output_only if output_only else ch.text()
    routed_to  = getattr(handle, "last_agent", "unknown")
    usage      = getattr(handle, "last_usage", None)
    state_size = getattr(handle, "state_size", None)
    state_snapshot = getattr(handle, "state_snapshot", None)
    return (response.strip() if response else response,
            fields, routed_to, usage, state_size, state_snapshot, ok)


# ─── one session, one arm ────────────────────────────────────────────────────────

def _expected_route(config, fi):
    """Config-defined correct tier for an FI band (fi_routing table)."""
    try:
        table = {int(k): v for k, v in dict(config.routing.fi_routing).items()}
        return table.get(fi, config.routing.fallback)
    except Exception:
        return None


def _run_session_for_arm(base, session, arm, trial, run_id, write, arm_stats, log,
                         irt_router=None):
    """
    Fresh handle for this (session, arm) pair — fresh SYSTEM_STATE, same as
    ground truth collection's reset-between-sessions behavior. Commands
    within the session run through this ONE handle, in order, so state
    accumulates exactly like the real Docker collection did.
    """
    import main as hydrapot_main
    session_id  = session["session_id"]
    # honeyrouter: force nothing, core.router.classify() (regex + FI) decides.
    # irt_router:  the TRAINED neural policy names the agent per command and
    #              it is forced, so the pick is the network's, not the regex's.
    # anything else: that single agent, forced.
    force_agent = None if arm in ("honeyrouter", "irt_router") else arm

    handle = hydrapot_main.make_command_handler(
        base.cowrie,
        src_ip=f"partc_{arm}_{session_id}", public_ip=f"partc_{arm}_{session_id}",
        plugins=None,
        capture_cost=True,
        store="json", store_dir=session_dir_for(f"partc_{arm}_{session_id}", __file__),
    )

    cloud_cost = 0.0
    for pos, c in enumerate(session["commands"]):
        if c.get("blocked"):
            continue

        cmd          = c["cmd"]
        ground_truth = c.get("ground_truth")
        fi_score     = c.get("fi")

        per_cmd_force = force_agent
        if arm == "irt_router":
            per_cmd_force = irt_router.pick(cmd)

        response, fields, routed_to, usage, state_size, state_snapshot, ok = _run_arm(
            handle, cmd, per_cmd_force, log=log
        )

        if usage and usage.get("cost") is not None:
            cloud_cost += usage["cost"]

        rec = {
            "run_id":             run_id,
            "trial":              trial,
            "session_id":         session_id,
            "position_in_session": pos,
            "cmd":                cmd,
            "source":             session.get("source"),
            "fi_score":           fi_score,
            "ground_truth":       ground_truth,
            "arm":                arm,
            "routed_to":          routed_to,
            "response":           response,
            "ok":                 ok,
            "inference_ms":       fields.get("latency_ms"),
            "cpu_pct":            fields.get("cpu_pct"),
            "ram_after_mb":       fields.get("ram_after_mb"),
            "ram_delta_mb":       fields.get("ram_delta_mb"),
            "vram_after_mb":      fields.get("vram_after_mb"),
            "vram_delta_mb":      fields.get("vram_delta_mb"),
            "prompt_tokens":      usage.get("prompt_tokens")     if usage else None,
            "completion_tokens":  usage.get("completion_tokens") if usage else None,
            "total_tokens":       usage.get("total_tokens")      if usage else None,
            "cost":               usage.get("cost")              if usage else None,
            "prompt_cost":        usage.get("prompt_cost")       if usage else None,
            "completion_cost":    usage.get("completion_cost")   if usage else None,
            "reasoning_tokens":   usage.get("reasoning_tokens")  if usage else None,
            "cache_hit_tokens":   usage.get("cache_hit_tokens")  if usage else None,
            "cache_miss_tokens":  usage.get("cache_miss_tokens") if usage else None,
            "gflops":             usage.get("gflops")            if usage else None,
            "state_size":         state_size,
            "state_snapshot":     state_snapshot,
            # config-defined correct tier for this FI — gold label for routing accuracy
            "expected_route":     _expected_route(base.config, fi_score),
        }
        write(arm, rec)

        s = arm_stats[arm]
        s["count"] += 1
        if ok:
            s["ok"] += 1
        if fields.get("latency_ms") is not None:
            s["latency_sum"] += fields["latency_ms"]
        if usage:
            s["prompt_tokens_sum"]     += usage.get("prompt_tokens") or 0
            s["completion_tokens_sum"] += usage.get("completion_tokens") or 0
            s["cost_sum"]              += usage.get("cost") or 0

    return cloud_cost


# ─── main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=str, required=True,
                    help="the dataset_groundtruth_<N>.json to replay")
    ap.add_argument("--trials",   type=int, default=1)
    ap.add_argument("--arms",     type=str, default=None,
                     help=f"comma-separated subset of arms to run, from {ARMS} "
                          f"(default: all 4). e.g. --arms on_device")
    ap.add_argument("--irt-config-dir", type=str, default=None,
                     help="for --arms irt_router: the "
                          "results/partC_ml_router/config_<hash>/ folder whose "
                          "trained policy picks the agent per command")
    ap.add_argument("--irt-policy", type=str, default="rl",
                     choices=["rl", "policy"],
                     help="rl = Stage 3 PPO, the final model (default); "
                          "policy = Stage 2 supervised, the warm start and the "
                          "fallback while Stage 3 is being fixed")
    ap.add_argument("--irt-omega", type=float, default=0.5,
                     help="preference weight on -cost the policy is "
                          "conditioned on at inference (default 0.5)")
    ap.add_argument("--tag",      type=str, default=None,
                     help="human-readable label for the output folder, e.g. "
                          "--tag cloud_new -> results/partC/fidelity_cloud_new/ "
                          "(default: results/partC/fidelity/, overwritten each run)")
    args = ap.parse_args()

    if args.arms:
        selected_arms = tuple(a.strip() for a in args.arms.split(","))
        unknown = [a for a in selected_arms if a not in ARMS]
        if unknown:
            print(f"[partC] unknown arm(s) {unknown} — must be from {ARMS}")
            sys.exit(1)
    else:
        selected_arms = ARMS

    run_id   = datetime.now().strftime("%Y%m%d_%H%M%S")
    # No timestamp — a rerun overwrites the same folder (run_id stays in records).
    dir_name = f"fidelity_{args.tag}" if args.tag else "fidelity"
    out_dir  = os.path.join(RESULTS_DIR, dir_name)
    os.makedirs(out_dir, exist_ok=True)
    log, close_log = _make_logger(os.path.join(out_dir, "run.log"))

    log(f"[partC] run_id={run_id}  sessions_file={args.sessions}  trials={args.trials}  arms={selected_arms}")

    sessions, breakdown = load_sessions(args.sessions)
    total_cmds = sum(len(s["commands"]) for s in sessions)
    log(f"[partC] workload: {len(sessions)} sessions, {total_cmds} commands  breakdown={breakdown}")

    from agents import build_agents
    # cowrie connection only needed if cowrie itself or honeyrouter (which may
    # naturally route to cowrie) is actually being run this time
    needs_cowrie    = "cowrie" in selected_arms or "honeyrouter" in selected_arms
    # on_device (GPU) only loads when an arm actually routes there: the forced
    # on_device arm, or honeyrouter (whose FI1/FI2 go to on_device). A cloud- or
    # cowrie-only run then needs no GPU and won't fail if the GPU is busy.
    needs_on_device = "on_device" in selected_arms or "honeyrouter" in selected_arms
    base = build_agents(connect_cowrie=needs_cowrie, load_on_device=needs_on_device)

    # Part C cloud arm: deepseek-v4.1-flash via PARTC_BASE_URL (pooled API_KEY_*
    # keys). On a clean 50-command sample at max_tokens=2048 this beat every
    # other tested model (0.734 avg similarity to ground truth, 3/50 blank) —
    # gpt-4o-mini hit a deterministic proxy-side null-content bug on certain
    # commands (see CloudAgent's retry-on-null-content handling). Scoped here
    # so config.yaml / live honeypot keep gpt-5.6-luna.
    cloud = getattr(base, "cloud", None)
    # Always, so honeyrouter's FI-4 cloud hops use the same model too.
    if cloud is not None:
        from openai import OpenAI
        partc_url = (os.environ.get("PARTC_BASE_URL") or "").rstrip("/") or cloud._base_url
        cloud.model     = "deepseek/deepseek-v4.1-flash"
        cloud._base_url = partc_url
        cloud._api_key  = cloud._pool.current()
        cloud.client    = OpenAI(api_key=cloud._api_key, base_url=partc_url)
        log(f"[partC] cloud arm -> {cloud.model} @ {partc_url}  "
            f"({len(cloud._pool)} key(s) pooled)")

    write, close = make_writers(out_dir, arms=selected_arms)

    # One router for the whole run: loading the predictor and policy is slow
    # and the embedding cache inside it pays off across repeated commands.
    # Stage 3 (rl) is the final model; Stage 2 (policy) is the warm start and
    # the fallback while Stage 3 is being fixed.
    irt_router = None
    if "irt_router" in selected_arms:
        if not args.irt_config_dir:
            raise SystemExit(
                "--arms irt_router needs --irt-config-dir: the trained "
                "config_<hash>/ folder whose policy should pick the agent")
        from irt_router_live import IrtRouter
        irt_router = IrtRouter(args.irt_config_dir, which=args.irt_policy,
                               omega=args.irt_omega)
        log(f"[partC] irt_router: {args.irt_policy} policy from "
            f"{args.irt_config_dir}, omega={args.irt_omega}")

    cloud_cost_total = 0.0
    t_run_start = time.time()
    arm_stats = {
        arm: {"count": 0, "ok": 0, "latency_sum": 0.0,
              "prompt_tokens_sum": 0, "completion_tokens_sum": 0, "cost_sum": 0.0}
        for arm in selected_arms
    }

    for trial in range(args.trials):
        for s_idx, session in enumerate(sessions):
            for arm in selected_arms:
                cloud_cost_total += _run_session_for_arm(
                    base, session, arm, trial, run_id, write, arm_stats, log,
                    irt_router=irt_router
                )

            if (s_idx + 1) % 10 == 0:
                elapsed = time.time() - t_run_start
                log(
                    f"[partC] {s_idx+1}/{len(sessions)} sessions (trial {trial})  "
                    f"elapsed={elapsed:.0f}s  cloud_cost_so_far=${cloud_cost_total:.4f}"
                )

    close()
    try:
        base.cowrie.disconnect()
    except Exception:
        pass

    log(f"\n{'='*72}")
    log(f"  Part C Summary — run_id: {run_id}")
    log(f"{'='*72}")
    log(f"  sessions: {len(sessions)}   commands: {total_cmds}   trials: {args.trials}")
    log("")
    log(f"  {'arm':<12} {'records':>8} {'ok':>6} {'avg_ms':>10} {'tokens':>12} {'cost':>10}")
    log(f"  {'-'*62}")
    for arm in selected_arms:
        s = arm_stats[arm]
        avg_ms     = s["latency_sum"] / s["count"] if s["count"] else 0.0
        tokens_sum = s["prompt_tokens_sum"] + s["completion_tokens_sum"]
        log(
            f"  {arm:<12} {s['count']:>8} {s['ok']:>6} {avg_ms:>9.1f}ms "
            f"{tokens_sum:>12,} ${s['cost_sum']:>9.4f}"
        )
    log(f"\n  total cloud cost: ${cloud_cost_total:.4f}")
    log(f"  results -> {out_dir}")
    log(f"{'='*72}\n")
    close_log()


if __name__ == "__main__":
    main()
