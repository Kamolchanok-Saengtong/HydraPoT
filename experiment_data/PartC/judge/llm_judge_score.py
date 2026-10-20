"""
experiment_data/PartC/llm_judge_score.py — LLM-as-a-Judge fidelity scoring (Part C)
─────────────────────────────────────────────────────────────────
Uses a real OpenAI model (default: gpt-5) as an independent judge of
honeypot response realism, separate from the BERTScore/cosine/etc.
metrics in evaluation/fidelity.py — a second, semantic-level opinion.

Two modes, same underlying judge call:

  reliability  — sanity-checks the judge itself. Feeds each command's
                  GROUND TRUTH as if it were the response being judged.
                  Since ground truth is real Docker-collected output from
                  an actual Linux system, a trustworthy judge should score
                  it ~5/5 almost every time. If it doesn't, don't trust
                  its scores in `score` mode either.

  score        — judges each arm's actual response (cowrie/on_device/
                  cloud/honeyrouter) against ground truth, 1-5, with a
                  one-sentence reason. This is the real comparison.

Both write one <output>.jsonl line per judged record, incrementally
(safe to Ctrl+C and resume — already-judged (session_id, position_in_session)
keys are skipped on restart) and run requests concurrently via a thread
pool (I/O-bound network calls, not CPU-bound, so threads are fine).

reliability mode reads cmd/ground_truth straight from the Part C reference
dataset (dataset/partC_stateful_sessions.json by default) — never from an
arm's result .jsonl, which pairs ground_truth with a `response` field. This
keeps the sanity check completely isolated from any arm's actual output.

Setup:
    export OPENAI_API_KEY=sk-...

Usage:
    # 1. Sanity-check the judge itself first (cheap: run on a sample)
    python experiment_data/PartC/llm_judge_score.py reliability \
        --results-dir experiment_data/PartC/results/fidelity_20260714_190136 \
        --sample 50

    # 2. Score real arm responses (repeat --arms for each arm you have)
    python experiment_data/PartC/llm_judge_score.py score \
        --results-dir experiment_data/PartC/results/fidelity_20260714_190136 \
        --arms on_device,cowrie,cloud,honeyrouter
─────────────────────────────────────────────────────────────────
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))     # experiment_data/
from _common import load_jsonl

import sys
import json
import time
import random
import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core.key_rotation import KeyPool, is_quota_error
from prompt.prompt_manager import _looks_binary

ARMS = ("cowrie", "on_device", "cloud", "honeyrouter")
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
DEFAULT_DATASET = os.path.join(_ROOT, "dataset", "partC_stateful_sessions.json")

# Experiment keys live in experiment_data/.env, separate from the repo-root .env.
from core.config_loader import load_dotenv
load_dotenv(os.path.join(_ROOT, "experiment_data", ".env"), override=True)


def _load_host_profile():
    """Static persona the honeypot emulates — given to the judge as context."""
    try:
        from core.config_loader import load_config
        hp = load_config(os.path.join(_ROOT, "config.yaml")).honeypot
        return f"hostname={hp.hostname}, os={hp.os}, kernel={hp.kernel}, arch={hp.arch}"
    except Exception:
        return None


HOST_PROFILE = _load_host_profile()

JUDGE_SYSTEM_PROMPT = """\
You are an expert cybersecurity researcher evaluating a Linux SSH honeypot.
Your job: given an attacker's command and a candidate response the honeypot
produced, score how convincingly the candidate response would fool a real
attacker into believing they are on a genuine Linux system, based on your own
knowledge of what that command actually does on a real Linux system.

Score 1-5:
  5 = Indistinguishable from the real system. Content and formatting both
      correct, or a trivially harmless variation (e.g. different but
      plausible hostname/timestamp/PID) that a real system could also show.
  4 = Very realistic, only a minor formatting/detail slip an attacker would
      likely not notice or care about.
  3 = Recognizable as roughly correct, but with a noticeable error a
      careful attacker might catch (wrong error text, missing fields).
  2 = Mostly wrong — some superficial resemblance but the core content or
      behavior is incorrect.
  1 = Would immediately reveal the system as fake (nonsensical output,
      wrong command entirely, obvious hallucination, or empty when the
      real system clearly would have produced output, or vice versa).

Judge CONTENT and BEHAVIOR realism, not exact string match — a differently
formatted but equally plausible real-world output can still be a 5.

You may also be given the HOST PROFILE and the SYSTEM STATE (cwd, files and
their contents, installed packages, tool versions) as it stands at this point
in the session. That state was established by the attacker's OWN PRIOR commands
and is context for judging STATE-DEPENDENT correctness — e.g. whether `cat f`
matches what an earlier command wrote to `f`, or whether a listing matches the
files that exist. It is NOT the expected output of the command being judged;
judge the response against real Linux behaviour given that state.

Respond with ONLY a JSON object, no other text:
{"score": <integer 1-5>, "reason": "<one short sentence>"}
"""

# Hard cap on cmd/response length sent to the judge. Some ground-truth-style
# responses (e.g. `cat /bin/busybox` echoing an entire binary) can run into
# the millions of characters — sending that whole thing (now removed) or an
# equally huge honeypot response would burn enormous token/cost for no judging
# benefit, since the judge only needs enough text to recognize the pattern.
_MAX_JUDGE_CHARS = 2000
_MAX_STATE_CHARS = 6000   # the state block holds many files; allow more room

def _clip_for_judge(text: str) -> str:
    if text is None:
        return text
    if len(text) <= _MAX_JUDGE_CHARS:
        return text
    return text[:_MAX_JUDGE_CHARS] + f"...[truncated, {len(text)} chars total]"


def _client(api_key_env: str, base_url: str | None):
    """Returns (api_key, base_url) for direct-HTTP calls. We deliberately do
    NOT use the OpenAI SDK object: PSU's ai.psu.blue proxy mishandles the SDK
    (it can return raw SSE text as a string -> 'str' object has no attribute
    'choices'). CloudAgent.send_with_usage already proved that a plain
    requests.post with stream=False returns a proper single JSON object here,
    so the judge uses that same direct-HTTP path."""
    # Keys rotate on quota: --api-key-env JUDGE_API_KEY picks up JUDGE_API_KEY_1,
    # _2, … (and bare JUDGE_API_KEY / OPENAI_API_KEY) from .env.
    pool = KeyPool(api_key_env, fallback_env="OPENAI_API_KEY")
    if not pool.current():
        print(f"[llm_judge] ERROR: no keys for '{api_key_env}' "
              f"(set {api_key_env}_1 / {api_key_env} / OPENAI_API_KEY).")
        sys.exit(1)
    base = (base_url or "https://api.openai.com/v1").rstrip("/")
    print(f"[llm_judge] {len(pool)} key(s) for {api_key_env}")
    return {"pool": pool, "base_url": base}


def _render_state(state) -> str:
    """Compact text for the judge. Accepts the recorded snapshot dict (or str)."""
    if not state:
        return ""
    txt = state if isinstance(state, str) else json.dumps(state, ensure_ascii=False, indent=2)
    return txt if len(txt) <= _MAX_STATE_CHARS else txt[:_MAX_STATE_CHARS] + "…[clipped]"


def _judge_one(client: dict, model: str, cmd: str, response: str,
               state=None, host_profile: str = None, max_retries: int = 5) -> dict:
    """One judge call via direct HTTP POST (stream=False). Returns
    {"score": int|None, "reason": str}.

    Ground truth is deliberately NOT sent — some captured ground-truth values
    (e.g. `cat /bin/busybox` echoing an entire binary) run into millions of
    characters, which burned enormous token cost for no judging benefit. The
    judge instead scores plausibility from its own knowledge of real Linux
    behavior. This is a real methodology change (comparison-to-reference ->
    plausibility-from-knowledge) — cheaper, but reliability-mode's "does the
    judge score real ground truth ~5/5" check now tests whether the judge
    recognizes genuine output as realistic, not whether it correctly compares
    against a supplied reference.
    """
    blocks = []
    if host_profile:
        blocks.append(f"Host profile (the system being emulated):\n{host_profile}")
    state_txt = _render_state(state)
    if state_txt:
        blocks.append("System state at this point (from the attacker's prior "
                      "commands — NOT the expected output of the command below):\n"
                      + state_txt)
    blocks.append(f"Command run by the attacker:\n{_clip_for_judge(cmd)}")
    blocks.append("Candidate response to judge (from the honeypot):\n"
                  + (_clip_for_judge(response) if response else "(empty)"))
    user_prompt = "\n\n".join(blocks)
    pool = client["pool"]
    url = f"{client['base_url']}/chat/completions"
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        # Deliberate, not left to the proxy's default — a judge benefits from
        # more careful reasoning before scoring, and its output is a tiny
        # fixed-shape JSON object, so a high reasoning budget never risks the
        # reasoning-exhaustion blank responses seen on the honeypot-answer path.
        "reasoning": {"effort": "high"},
    }
    # gpt-5 (a reasoning model) rejects any temperature != 1 ("Unsupported
    # value: 'temperature' does not support 0 with this model") — every call
    # was failing with HTTP 400 until this was made conditional. Other models
    # (deepseek, glm, etc.) still get temperature=0 for deterministic judging.
    if not model.startswith("gpt-5"):
        payload["temperature"] = 0
    delay = 1.0
    for attempt in range(max_retries):
        key = pool.current()
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=60)
            if r.status_code == 200:
                data = r.json()
                text = data["choices"][0]["message"]["content"] or ""
                obj = _extract_json_obj(text)
                if obj is None:
                    return {"score": None, "reason": f"no JSON in response: {text[:120]!r}"}
                score = obj.get("score")
                reason = obj.get("reason", "")
                if isinstance(score, (int, float)) and 1 <= score <= 5:
                    return {"score": int(score), "reason": reason}
                return {"score": None, "reason": f"unparseable score: {text[:120]!r}"}
            # Quota exhausted on this key → switch to the next and retry now.
            if is_quota_error(r.status_code, r.text) and pool.rotate(key):
                continue
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:150]}")
        except Exception as e:
            if attempt == max_retries - 1:
                return {"score": None, "reason": f"judge call failed: {e}"}
            time.sleep(delay)
            delay = min(delay * 2, 30)
    return {"score": None, "reason": "exhausted retries"}


def _extract_json_obj(text: str):
    """Best-effort parse of a single JSON object from a model reply — tolerates
    ```json fences, leading prose, or a bare object embedded in text."""
    import re
    text = text.strip()
    # try direct
    try:
        return json.loads(text)
    except Exception:
        pass
    # strip code fences
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except Exception:
            pass
    # first {...} balanced-ish span
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


def _safe_model(model: str) -> str:
    """Model ids like 'z-ai/glm-5' contain '/', which would be read as a path
    separator in output filenames. Flatten to a filename-safe token."""
    return model.replace("/", "_").replace(":", "_")


def already_done_keys(out_path: str) -> set:
    """(session_id, position_in_session) SUCCESSFULLY judged in out_path.

    Only records with a real judge_score count as done. A failed call (rate
    limit / 429 daily credit cap / 502 / unparseable) is written with
    judge_score=None, and MUST be retried on the next run — counting those as
    "done" would silently strand them forever (this bit us: a daily-credit-cap
    run left 2,144 records unscored). We also purge those null rows from the
    file here, so retries append cleanly instead of duplicating keys.
    """
    done = set()
    if not os.path.exists(out_path):
        return done

    records = load_jsonl(out_path)
    keep = [r for r in records if r.get("judge_score") is not None]
    if len(keep) != len(records):
        # rewrite without the failed rows so they can be re-judged cleanly
        with open(out_path, "w", encoding="utf-8") as f:
            for r in keep:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[llm_judge] {os.path.basename(out_path)}: dropped "
              f"{len(records) - len(keep)} failed record(s) — they will be retried")

    for r in keep:
        done.add((r["session_id"], r["position_in_session"]))
    return done


def _select(records: list, limit: int | None, sample: int | None) -> list:
    records = [r for r in records if r.get("ground_truth") is not None]
    if sample is not None and sample < len(records):
        records = random.sample(records, sample)
    if limit is not None:
        records = records[:limit]
    return records


def load_source_dataset(path: str) -> list:
    """
    Loads (session_id, position_in_session, cmd, ground_truth, fi_score) straight
    from the actual Part C reference dataset (e.g. dataset/partC_stateful_sessions.json)
    — NOT from any arm's result .jsonl. Those files pair ground_truth with a
    `response` field from a specific arm; reading from the pure source dataset
    instead means there is zero chance of ever touching an arm's response here.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    records = []
    for session in data["sessions"]:
        sid = session["session_id"]
        for pos, c in enumerate(session["commands"]):
            if c.get("blocked"):
                continue
            records.append({
                "session_id": sid, "position_in_session": pos,
                "cmd": c["cmd"], "ground_truth": c.get("ground_truth"),
                "fi_score": c.get("fi"),
            })
    return records


def run_reliability(args):
    client = _client(args.api_key_env, args.base_url)
    records = load_source_dataset(args.dataset)
    if not records:
        print(f"[llm_judge] no records found in {args.dataset}")
        sys.exit(1)

    records = _select(records, args.limit, args.sample)
    out_dir = os.path.join(args.results_dir, "judge")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"judge_reliability_{_safe_model(args.model)}.jsonl")
    done = already_done_keys(out_path)
    todo = [r for r in records if (r["session_id"], r["position_in_session"]) not in done]
    print(f"[llm_judge] reliability check: {len(todo)} to judge "
          f"({len(records) - len(todo)} already done, resuming into {out_path})")

    scores = []
    with open(out_path, "a", encoding="utf-8") as out_f, \
         ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {
            pool.submit(_judge_one, client, args.model, r["cmd"], r["ground_truth"]): r
            for r in todo
        }
        n_done = 0
        for fut in as_completed(futures):
            r = futures[fut]
            result = fut.result()
            rec = {
                "session_id": r["session_id"], "position_in_session": r["position_in_session"],
                "cmd": r["cmd"], "ground_truth": r["ground_truth"],
                "judge_score": result["score"], "judge_reason": result["reason"],
            }
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out_f.flush()
            if result["score"] is not None:
                scores.append(result["score"])
            n_done += 1
            if n_done % 20 == 0:
                print(f"[llm_judge] {n_done}/{len(todo)} judged", flush=True)

    all_scores = scores + [r["judge_score"] for r in load_jsonl(out_path)
                            if r["judge_score"] is not None and
                            (r["session_id"], r["position_in_session"]) in done]
    if all_scores:
        dist = defaultdict(int)
        for s in all_scores:
            dist[s] += 1
        print(f"\n[llm_judge] RELIABILITY CHECK — judge: {args.model}, n={len(all_scores)}")
        print(f"  mean score: {sum(all_scores)/len(all_scores):.2f} / 5")
        for s in range(1, 6):
            print(f"  {s}: {'#' * dist[s]} ({dist[s]})")
        print(f"  -> if mean is well below ~4.5, treat this judge's `score` mode results with caution.")


def run_score(args):
    client = _client(args.api_key_env, args.base_url)
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]

    for arm in arms:
        src_path = os.path.join(args.results_dir, f"{arm}.jsonl")
        records = load_jsonl(src_path)
        if not records:
            print(f"[llm_judge] {arm}: no records found in {src_path}, skipping")
            continue

        records = [r for r in records if r.get("ok") and r.get("response") is not None]
        # Same exclusion Part B uses: raw binary content isn't something an LLM
        # judge can meaningfully assess ("is this garbage realistic?"), and it
        # burns tokens on literal \x00-\xFF byte escapes for no scoring signal.
        records = [r for r in records if not _looks_binary(r.get("response") or "")
                   and not _looks_binary(r.get("ground_truth") or "")]
        records = _select(records, args.limit, args.sample)
        out_dir = os.path.join(args.results_dir, "judge", arm)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"judge_scored_{_safe_model(args.model)}.jsonl")
        done = already_done_keys(out_path)
        todo = [r for r in records if (r["session_id"], r["position_in_session"]) not in done]
        print(f"[llm_judge] {arm}: {len(todo)} to judge "
              f"({len(records) - len(todo)} already done, resuming into {out_path})")

        with open(out_path, "a", encoding="utf-8") as out_f, \
             ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {
                pool.submit(_judge_one, client, args.model, r["cmd"], r["response"],
                            state=r.get("state_snapshot"), host_profile=HOST_PROFILE): r
                for r in todo
            }
            n_done = 0
            for fut in as_completed(futures):
                r = futures[fut]
                result = fut.result()
                rec = {
                    "session_id": r["session_id"], "position_in_session": r["position_in_session"],
                    "cmd": r["cmd"], "fi_score": r.get("fi_score"), "arm": arm,
                    "routed_to": r.get("routed_to"), "expected_route": r.get("expected_route"),
                    "ground_truth": r["ground_truth"], "response": r["response"],
                    "judge_score": result["score"], "judge_reason": result["reason"],
                }
                out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                out_f.flush()
                n_done += 1
                if n_done % 20 == 0:
                    print(f"[llm_judge] {arm}: {n_done}/{len(todo)} judged", flush=True)

        all_recs = load_jsonl(out_path)
        scores = [r["judge_score"] for r in all_recs if r["judge_score"] is not None]
        if scores:
            print(f"[llm_judge] {arm}: n={len(scores)}  mean judge score={sum(scores)/len(scores):.2f}/5\n")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--results-dir", required=True, help="a fidelity_<run_id> folder from run_partC.py")
    common.add_argument("--model", default="openai/gpt-6-luna", help="judge model")
    common.add_argument("--api-key-env", default="API_KEY",
                        help="env PREFIX for the shared rotating pool: API_KEY → API_KEY_1,_2,…")
    common.add_argument("--base-url",
                        default=os.environ.get("JUDGE_BASE_URL") or os.environ.get("CLOUD_AGENT_BASE_URL"),
                        help="judge API base URL (defaults to JUDGE_BASE_URL / CLOUD_AGENT_BASE_URL)")
    common.add_argument("--concurrency", type=int, default=5)
    common.add_argument("--limit", type=int, default=None, help="cap number of records judged (after sampling)")
    common.add_argument("--sample", type=int, default=None, help="randomly sample N records instead of judging all")

    p_rel = sub.add_parser("reliability", parents=[common])
    p_rel.add_argument("--dataset", default=DEFAULT_DATASET,
                        help="Part C reference dataset to read cmd+ground_truth from "
                             "(NOT an arm's result file — no response field exists here at all)")

    p_score = sub.add_parser("score", parents=[common])
    p_score.add_argument("--arms", default=",".join(ARMS), help="comma-separated arms to judge")

    args = ap.parse_args()
    if args.mode == "reliability":
        run_reliability(args)
    else:
        run_score(args)


if __name__ == "__main__":
    main()
