"""
honeyrouter/evaluate.py — does the RL router actually beat the alternatives?

Two things live here:

    compare()   replays the SAME recorded sessions through five routing
                policies and reports cost, time and fidelity for each
    evaluate()  the older single-policy view: mean episode reward and which
                agent the DQN picks

    policy  ->  picks an agent per command  ->  read THAT arm's recorded result

Nothing is simulated. Every session was already executed against all three
agents (experiment_data/PartC/results/fidelity_full109_final), so a policy's
score is a lookup of measurements that actually happened. The policies differ
only in WHICH recorded outcome they selected, which is what makes the
comparison fair.

    Pure Cowrie      always the traditional emulator
    Pure On-device   always the local LLM
    Pure Cloud       always the cloud LLM
    Rule-based       HydraPoT's shipped router -- its RECORDED decisions
    RL HoneyRouter   the trained DQN, deterministic

THREE THINGS THIS FILE IS CAREFUL ABOUT
---------------------------------------
1. LATENCY IS TOTAL SESSION TIME, not a per-command mean. Sessions run from 1
   to 132 commands, so a mean tracks how long the sessions were rather than
   how good the policy was. What an operator waits through is the whole
   session; what a study should report is the sum.

2. EVERY POLICY SEES THE SAME SESSIONS IN THE SAME ORDER. compare() walks them
   sorted by id. evaluate() below draws RANDOM episodes, which is fine for
   inspecting one model but cannot compare two policies -- they would never
   face the same input.

3. THE RULE-BASED BASELINE IS A RECORDING, NOT A RE-RUN. It reads the routing
   decisions the shipped router actually wrote during the experiment, because
   router.classify() has changed since. And there are TWO such recordings that
   route 8x differently to cloud -- which one you read decides whether the
   baseline costs $0.32 or $0.57. sessions.ROUTER_FILE picks the one that pairs
   with the cloud arm; see rule_based() and the comment there.
"""
import argparse
import os
import statistics
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stable_baselines3 import DQN                     # noqa: E402

from honeyrouter.action import AGENTS                 # noqa: E402
from honeyrouter.environment import HoneyRouterEnv    # noqa: E402
from honeyrouter.sessions import load_sessions        # noqa: E402

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "out", "dqn_honeyrouter")

# $ per 1,000,000 tokens, used to price token counts on ONE scale.
#
# The recorded `cost` field in the Part C records implies ~$0.066/M, but a
# recorded price is whatever that provider charged on that day, for that mix of
# input/output/cached tokens. Pricing every policy at a single published input
# rate makes the comparison reproducible and provider-independent -- and
# assuming ALL tokens bill at the input rate is the LOWEST plausible estimate,
# since completions cost more everywhere. Both numbers are reported; they
# answer different questions.
TOKEN_RATE_USD_PER_M = 0.14


# ── policies ────────────────────────────────────────────────────────────────
# Each is (command, history) -> agent name. `history` is what has already been
# routed in this session; the rule-based router takes it, so every policy does.

def pure(agent: str):
    """Always route to one agent -- the three single-agent baselines."""
    def policy(command, history):
        return agent
    policy.__name__ = f"pure_{agent}"
    return policy


def rule_based(path=None):
    """HydraPoT's production router — its RECORDED decisions, not a replay of
    the rule.

    honeyrouter.jsonl is a fourth arm: the shipped router was executed over the
    same 2,179 commands and every routing decision written down. Reading those
    decisions is strictly better than calling router.classify() again, because
    the rule has MOVED since the experiment ran. Re-running it today gives:

        recorded 07-28   cowrie 68.8%   on_device  7.0%   cloud 24.1%
        classify()       cowrie 63.5%   on_device 36.5%   cloud  0.0%

    A baseline that does not match the run it claims to represent is not a
    baseline. The recorded file is what the router actually did.

    WHICH recorded file matters as much as which arm files -- there are two
    runs, and they route 8x differently to cloud. sessions.ROUTER_FILE picks
    the one that pairs with the cloud arm; see the comment there.

    Scored by arm lookup like every other policy, NOT from honeyrouter.jsonl's
    own inference_ms/cost/tokens. Its timings include routing overhead the
    other policies never pay, and its own judge file was scored by a different
    judge model than cowrie's arm (4.02 there vs 3.77 by arm lookup), so taking
    it would compare this policy on a scale no other policy is measured on.
    What is compared here is the DECISIONS, every policy priced identically.
    """
    import json
    from honeyrouter.sessions import ROUTER_FILE
    path = path or ROUTER_FILE
    decisions = {}
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        decisions[(r["session_id"], r["position_in_session"])] = r["routed_to"]

    def policy(command, history):
        target = decisions.get((command["session_id"], command["position"]))
        # One command in 2,179 recorded routed_to="unknown" (the router failed
        # to classify it). Falling back to the configured default is what the
        # live system does, and dropping the command would silently shrink this
        # policy's workload relative to the others.
        return target if target in AGENTS else "cowrie"

    policy.__name__ = "rule_based"
    return policy


def rl_policy(model_path: str = MODEL_PATH):
    """The trained DQN, deterministic -- no exploration.

    Builds the observation with the environment's own builder rather than a
    copy, so a change to the state layout cannot silently feed the model
    something different from what it was trained on.
    """
    from honeyrouter.environment import (_agent_costs, _agent_latencies,
                                         _agent_judge_scores)
    from honeyrouter.state import build_observation

    model = DQN.load(model_path)

    def policy(command, history):
        obs = build_observation(
            fi_score=command["fi_score"],
            agent_costs=_agent_costs(command),
            agent_latencies=_agent_latencies(command),
            agent_judge_scores=_agent_judge_scores(command),
        )
        action, _ = model.predict(obs, deterministic=True)
        return AGENTS[int(action)]

    policy.__name__ = "rl_honeyrouter"
    return policy


# ── replay ──────────────────────────────────────────────────────────────────

def run_policy(policy, sessions) -> dict:
    """Walk every session, let the policy choose, read the chosen arm's real
    measurements.

    Keeps the per-session latency list rather than a running total: "total
    time" is a per-session quantity, and the spread across sessions says as
    much as the sum.
    """
    total_cost = 0.0
    judge_scores = []
    session_latencies = []
    picks = Counter()
    # Split because only cloud tokens are billable. on-device tokens are real
    # compute on your own hardware -- free to the API bill, not free to the
    # machine -- so folding them together would overstate what a policy costs.
    cloud_tokens = local_tokens = 0

    for sid in sorted(sessions):                 # deterministic order
        history, session_latency = [], 0.0
        for command in sessions[sid]:
            command = {**command, "session_id": sid}
            agent = policy(command, history)
            arm = command["agents"][agent]
            total_cost += arm["cost_usd"]
            session_latency += arm["latency_s"]
            if agent == "cloud":
                cloud_tokens += arm["total_tokens"]
            elif agent == "on_device":
                local_tokens += arm["total_tokens"]
            judge_scores.append(arm["judge_score"])
            picks[agent] += 1
            history.append({"cmd": command["cmd"], "agent": agent})
        session_latencies.append(session_latency)

    return {
        "cost_usd": total_cost,
        "cloud_tokens": cloud_tokens,
        "local_tokens": local_tokens,
        "token_cost_usd": cloud_tokens / 1e6 * TOKEN_RATE_USD_PER_M,
        # What the on-device tokens WOULD cost at the same rate. Not a bill --
        # nobody charges you for your own GPU -- but it is the only way to see
        # the size of the compute a policy pushed onto local hardware. A policy
        # that looks free because it routes everything on-device is not free,
        # it has moved the cost somewhere the invoice does not show.
        "local_token_cost_usd": local_tokens / 1e6 * TOKEN_RATE_USD_PER_M,
        "latency_total_s": sum(session_latencies),
        "latency_per_session_s": statistics.mean(session_latencies),
        "latency_median_s": statistics.median(session_latencies),
        "latency_max_s": max(session_latencies),
        "judge_mean": statistics.mean(judge_scores) if judge_scores else 0.0,
        "commands": len(judge_scores),
        "sessions": len(session_latencies),
        "picks": dict(picks),
    }


def compare(model_path: str = MODEL_PATH) -> dict:
    """Every policy over identical input. -> {policy name: metrics}"""
    sessions = load_sessions()
    policies = [
        ("Pure Cowrie", pure("cowrie")),
        ("Pure On-device", pure("on_device")),
        ("Pure Cloud", pure("cloud")),
        ("Rule-based", rule_based()),
    ]
    if os.path.exists(model_path + ".zip") or os.path.exists(model_path):
        policies.append(("RL HoneyRouter", rl_policy(model_path)))
    else:
        print(f"[eval] no trained model at {model_path} — skipping the RL row")

    results = {}
    for name, policy in policies:
        results[name] = run_policy(policy, sessions)
        if hasattr(policy, "_restore"):
            policy._restore()

    # Computed here, while `sessions` is already in hand, rather than in
    # report() -- it needs the same arm records and reloading them costs ~50MB
    # of JSON to print four lines.
    if "Rule-based" in results:
        results["Rule-based"]["measured_ref"] = _measured_reference(sessions)
    return results


def _measured_reference(sessions) -> dict | None:
    """The one rule-based run that was measured end to end, next to what this
    file's method WOULD have charged those same decisions.

    A different run from the baseline policy (different routing mix), so it
    cannot validate that row -- only quantify how far derived timing drifts
    from reality for a router of this kind. See _latency_caveat.
    """
    import json
    from honeyrouter.sessions import ROUTER_MEASURED_FILE as path
    if not os.path.exists(path):
        return None
    rows = [json.loads(l) for l in open(path, encoding="utf-8")]
    measured = sum((r.get("inference_ms") or 0) for r in rows) / 1000.0
    if not measured:
        return None

    decisions = {(r["session_id"], r["position_in_session"]): r["routed_to"]
                 for r in rows}
    derived = 0.0
    for sid in sessions:
        for command in sessions[sid]:
            agent = decisions.get((sid, command["position"]))
            agent = agent if agent in AGENTS else "cowrie"
            derived += command["agents"][agent]["latency_s"]

    mix = Counter(r.get("routed_to") for r in rows)
    n = sum(mix.values())
    return {
        "measured_s": measured,
        "derived_s": derived,
        "mix": "  ".join(f"{a[:3]} {100 * mix.get(a, 0) / n:.0f}%"
                         for a in AGENTS if mix.get(a)),
        "path": os.path.basename(os.path.dirname(path)),
    }


def _times(value, baseline) -> str:
    """Multiple of the baseline, not a percent change.

    "-100%" and "+269%" are arithmetically right and unreadable: the first
    means ZERO and the second means 3.7 TIMES. A multiple says both directly,
    and zero gets a word rather than a number.
    """
    if not baseline:
        return "—"
    if value == 0:
        return "free" if baseline > 0 else "0x"
    ratio = value / baseline
    mark = "✓" if ratio < 1 else ("✗" if ratio > 1 else " ")
    return f"{ratio:.2f}x{mark}"


def _points(value, baseline) -> str:
    """Absolute difference, for a bounded scale.

    The judge score is 0-5. A percentage on a bounded scale exaggerates: 5% of
    3.77 is 0.19 points, which reads as a bigger move than it is.
    """
    if baseline is None:
        return "—"
    diff = value - baseline
    if abs(diff) < 0.005:
        return "  same"
    return f"{diff:+.2f}{'✓' if diff > 0 else '✗'}"


def _delta(value, baseline, lower_is_better=True) -> str:
    """TRUE percent change, with a marker for whether it is an improvement.

    An earlier version flipped the sign so that negative always meant better.
    It was consistent and it was unreadable: "Judge -21.2%" for a score that
    ROSE from 3.48 to 4.22 is the opposite of what anyone reads. The number now
    says what actually happened and the marker says whether that is good, which
    needs no legend.
    """
    if not baseline:
        return "—"
    pct = 100.0 * (value - baseline) / baseline
    better = (pct < 0) if lower_is_better else (pct > 0)
    mark = " " if abs(pct) < 0.05 else ("✓" if better else "✗")
    return f"{pct:+.1f}% {mark}"


def report(results: dict, baseline: str = "Rule-based"):
    first = next(iter(results.values()))
    print(f"\nReplay of {first['sessions']} recorded attack sessions "
          f"({first['commands']} commands) — every policy on identical input.\n")

    # Cost is TOKENS x a single published rate, not the `cost` field recorded
    # per row. A recorded price is whatever that provider charged that day for
    # that mix of input/output/cached tokens; pricing every policy from its own
    # token count on one rate is reproducible and provider-independent. The
    # recorded figure is kept alongside so the two can be compared.
    head = (f"{'Policy':<17}{'Cost $ ↓':>11}{'(recorded)':>12}{'Total time ↓':>14}"
            f"{'Per session':>13}{'Judge ↑':>10}   routing mix")
    print(head)
    print("─" * len(head))
    for name, r in results.items():
        mix = "  ".join(f"{a[:3]} {100 * r['picks'].get(a, 0) / r['commands']:.0f}%"
                        for a in AGENTS if r["picks"].get(a))
        print(f"{name:<17}{r['token_cost_usd']:>11.4f}{r['cost_usd']:>12.4f}"
              f"{r['latency_total_s']:>13.1f}s"
              f"{r['latency_per_session_s']:>12.1f}s{r['judge_mean']:>10.2f}   {mix}")

    if baseline in results:
        base = results[baseline]
        print(f"\nVersus {baseline}   ✓ better · ✗ worse\n")
        head = (f"{'Policy':<17}{'Cost $':>9}{'x base':>9}"
                f"{'Time s':>9}{'x base':>9}{'Judge':>8}{'vs base':>9}")
        print(head)
        print("─" * len(head))
        for name, r in results.items():
            marker = "  (baseline)" if name == baseline else ""
            print(f"{name:<17}"
                  f"{r['token_cost_usd']:>9.4f}"
                  f"{_times(r['token_cost_usd'], base['token_cost_usd']):>9}"
                  f"{r['latency_total_s']:>9.0f}"
                  f"{_times(r['latency_total_s'], base['latency_total_s']):>9}"
                  f"{r['judge_mean']:>8.2f}"
                  f"{_points(r['judge_mean'], base['judge_mean']):>9}"
                  f"{marker}")
        print("\n  x base   multiple of the baseline. 0.5x = half. 2x = double.")
        print("           'free' = exactly zero, which no percentage says clearly.")
        print("  Judge    absolute points on the 0-5 scale, not a percentage:")
        print("           a 5% change on a 3.77 mean is 0.19 points, and reading")
        print("           it as a percentage makes small moves look large.")

    _token_table(results)
    _latency_caveat(results, baseline)
    print("\nLatency is TOTAL SESSION TIME summed over all sessions, not a "
          "per-command mean:\nsessions run 1–132 commands, so a mean would "
          "track session length rather than policy.")
    print(f"Cost is cloud tokens x ${TOKEN_RATE_USD_PER_M:.2f} per 1M — all "
          f"tokens at the input rate,\nthe lowest plausible estimate since "
          f"completions bill higher everywhere.")
    print("Judge is the mean LLM-as-judge fidelity score (0–5) over every "
          "command.\n")


def _token_table(results, cloud_baseline="Pure Cloud"):
    """Billable tokens, priced on one published rate.

    Token saving is measured against PURE CLOUD, not against the rule-based
    router: the question a token budget answers is "how much of the cloud bill
    did routing avoid", and the only policy that pays the full bill is the one
    that sends everything there. Measuring against the rule-based baseline
    would compare two partial savings and hide the headline.

        saving = (baseline cloud tokens - policy cloud tokens)
                 / baseline cloud tokens x 100
    """
    if cloud_baseline not in results:
        return
    base_tok = results[cloud_baseline]["cloud_tokens"]
    print(f"\nToken accounting — every token priced at the input rate "
          f"(${TOKEN_RATE_USD_PER_M:.2f} / 1M), the lowest plausible estimate:\n")
    head = (f"{'Policy':<17}{'Cloud tokens':>14}{'YOUR BILL $':>13}"
            f"{'Local tokens':>14}{'local compute $':>17}"
            f"{'  Token saving vs ' + cloud_baseline:>30}")
    print(head)
    print("─" * len(head))
    for name, r in results.items():
        saving = (100.0 * (base_tok - r["cloud_tokens"]) / base_tok
                  if base_tok else 0.0)
        print(f"{name:<17}{r['cloud_tokens']:>14,}{r['token_cost_usd']:>13.4f}"
              f"{r['local_tokens']:>14,}{r['local_token_cost_usd']:>17.4f}"
              f"{saving:>29.1f}%")
    print("\n  YOUR BILL $      what a provider actually charges. Cloud tokens only.")
    print("  local compute $  NOT A BILL, and never added to the one above. It is"
          "\n                   on-device tokens priced at the same rate, purely to"
          "\n                   show how much work was pushed onto your own GPU --"
          "\n                   something an API invoice can never reveal. Nobody"
          "\n                   sends you this. A policy that looks free because it"
          "\n                   runs everything locally is not free, it moved the"
          "\n                   cost somewhere the invoice does not look.")
    print("  Saving       cloud tokens only, per the definition: "
          "(baseline - policy) / baseline.")
    print("\n  Cowrie reports no tokens at all -- it is a rule-based emulator, "
          "not a model,\n  so tokens were never measured for it. Null there "
          "means 'not applicable',\n  while null on an LLM arm means a SILENT "
          "response: the command produced no\n  output, so no generation was "
          "needed and none was billed.")


def _latency_caveat(results, baseline="Rule-based"):
    """Every policy's latency in the table above is DERIVED -- the arm it
    picked, charged at that arm's Part C timing. Nobody has ever run these
    policies end to end except a rule-based router, once.

    That one measured run is the 07-14 router, and the baseline above is the
    07-28 one. They are DIFFERENT ROUTING MIXES (79/18/3 vs 69/7/24), so this
    is NOT a same-decisions cross-check and is not printed as one. It is the
    only evidence on hand for one narrow question: how far derived timing sits
    from a real end-to-end run of the same kind of system. For the 07-14 mix
    the answer was ~12% high, because cowrie answered faster inside the router
    process than in the standalone cowrie arm.

    Printed rather than buried, because that bias applies to every row in the
    table -- including the RL router's -- and quoting derived gaps without it
    overstates whatever the RL agent appears to win on time.
    """
    ref = results.get(baseline, {}).get("measured_ref")
    if not ref:
        return
    drift = 100 * (ref["derived_s"] - ref["measured_s"]) / ref["measured_s"]
    print(f"\nLatency caveat — derived timing runs high.\n"
          f"  The only rule-based router ever run end to end is {ref['path']} "
          f"({ref['mix']}),\n  which is NOT the {baseline} row above "
          f"({results[baseline]['latency_total_s']:.0f}s, a different routing "
          f"mix). Read the pair below\n  as evidence of the bias, never as "
          f"this policy's real time:")
    print(f"  that run, charged the way this table charges : "
          f"{ref['derived_s']:8.1f}s")
    print(f"  that run, actually measured                  : "
          f"{ref['measured_s']:8.1f}s   ({drift:+.1f}%)")
    print(f"  So derived overstates a real run by ~{abs(drift):.0f}% — mostly "
          f"because cowrie answers\n  faster inside the router process than in "
          f"the standalone cowrie arm. That bias\n  applies to EVERY row above, "
          f"the RL router's included; no RL router has been run\n  end to end, "
          f"so its real latency is unknown too. The table stays DERIVED so all "
          f"five\n  policies sit on one scale.")


# ── weight sweep ────────────────────────────────────────────────────────────

def sweep(grid=None, timesteps=10_000, out_dir=None):
    """Retrain at several reward weightings and table the trade-off.

    Only W_COST moves. W_JUDGE stays fixed because the RATIO is what matters
    -- scaling both changes nothing. The reward has two terms now (FI and
    latency were dropped, see reward.py), so this is a single axis: how much
    is a convincing answer worth in dollars.

    Each config trains a FRESH model to its own path, so the sweep never
    overwrites the model in out/. compute_reward() reads its weights as module
    globals at call time, so setting them before training is enough; there is
    no need to edit reward.py between runs.
    """
    import tempfile
    from stable_baselines3 import DQN as _DQN
    from honeyrouter import reward as R
    from honeyrouter.environment import HoneyRouterEnv

    grid = grid or [0.10, 0.25, 0.45, 0.70, 1.00]
    out_dir = out_dir or tempfile.mkdtemp(prefix="hr_sweep_")
    sessions = load_sessions()

    # Baselines never change -- compute once rather than per config.
    base = run_policy(rule_based(), sessions)
    original = R.W_COST

    rows = []
    for w_cost in grid:
        R.W_COST = w_cost
        path = os.path.join(out_dir, f"dqn_c{w_cost}")
        model = _DQN("MlpPolicy", HoneyRouterEnv(), verbose=0)
        model.learn(total_timesteps=timesteps)
        model.save(path)
        r = run_policy(rl_policy(path), sessions)
        rows.append((w_cost, r))
        print(f"  trained W_COST={w_cost} (W_JUDGE={R.W_JUDGE}) -> "
              f"${r['token_cost_usd']:.4f}  {r['latency_total_s']:.0f}s  "
              f"judge {r['judge_mean']:.2f}")

    R.W_COST = original
    return rows, base


def report_sweep(rows, base):
    print(f"\nReward-weight sweep — RL HoneyRouter vs Rule-based baseline "
          f"(${base['token_cost_usd']:.4f}, {base['latency_total_s']:.0f}s, "
          f"judge {base['judge_mean']:.2f})\n")
    head = (f"{'W_COST':>7}{'Cost $':>10}{'x base':>9}{'Time s':>9}"
            f"{'Judge':>7}{'vs base':>9}   routing mix")
    print(head)
    print("─" * len(head))
    for w_cost, r in rows:
        mix = " ".join(f"{a[:3]}{100 * r['picks'].get(a, 0) / r['commands']:.0f}"
                       for a in AGENTS)
        print(f"{w_cost:>7}{r['token_cost_usd']:>10.4f}"
              f"{_times(r['token_cost_usd'], base['token_cost_usd']):>9}"
              f"{r['latency_total_s']:>9.0f}{r['judge_mean']:>7.2f}"
              f"{_points(r['judge_mean'], base['judge_mean']):>9}   {mix}")
    print("\n  W_COST is what one dollar of cloud spend is worth against one")
    print("  point of fidelity. W_JUDGE is fixed -- only the RATIO matters.")
    print("  routing mix = cow/on_/clo as % of commands.")
    print("  There is no single best row. A config is interesting when it beats")
    print("  the baseline on one axis without collapsing the other.")


def evaluate(model_path: str = MODEL_PATH, n_episodes: int = 20):
    """Mean episode reward and the DQN's action distribution.

    RANDOM episodes, so this inspects one model rather than comparing two --
    use compare() for that.
    """
    env = HoneyRouterEnv()
    model = DQN.load(model_path, env=env)

    episode_rewards = []
    action_counts = Counter()

    for _ in range(n_episodes):
        obs, _ = env.reset()
        terminated = False
        ep_reward = 0.0
        while not terminated:
            action, _ = model.predict(obs, deterministic=True)
            action = int(action)
            action_counts[AGENTS[action]] += 1
            obs, reward, terminated, _truncated, _info = env.step(action)
            ep_reward += reward
        episode_rewards.append(ep_reward)

    total_actions = sum(action_counts.values())
    print(f"[eval] {n_episodes} episodes, model={model_path}")
    print(f"[eval] mean episode reward: {sum(episode_rewards) / len(episode_rewards):.3f}")
    print(f"[eval] min/max episode reward: {min(episode_rewards):.3f} / {max(episode_rewards):.3f}")
    print(f"[eval] action distribution ({total_actions} commands):")
    for agent in AGENTS:
        n = action_counts[agent]
        pct = 100 * n / total_actions if total_actions else 0
        print(f"  {agent:<10} {n:>5}  ({pct:5.1f}%)")

    return episode_rewards, action_counts


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Compare routing policies, or "
                                             "inspect one trained model.")
    ap.add_argument("--model", default=MODEL_PATH)
    ap.add_argument("--baseline", default="Rule-based",
                    help="policy the delta table compares against")
    ap.add_argument("--sweep", action="store_true",
                    help="retrain across reward weightings and table the "
                         "cost/latency/fidelity trade-off")
    ap.add_argument("--timesteps", type=int, default=10_000,
                    help="training steps per sweep config")
    ap.add_argument("--reward", action="store_true",
                    help="instead of comparing, show mean episode reward and "
                         "action mix for the trained model")
    ap.add_argument("--episodes", type=int, default=20,
                    help="episodes for --reward")
    args = ap.parse_args()

    if args.sweep:
        report_sweep(*sweep(timesteps=args.timesteps))
    elif args.reward:
        evaluate(args.model, args.episodes)
    else:
        report(compare(args.model), args.baseline)
