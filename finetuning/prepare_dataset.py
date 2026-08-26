"""
finetuning/prepare_dataset.py — build the LoRA training set.

Turns zyw-286/shell-attack-evolution-dataset (config `request_response`, split
`curated`) into chat examples in HydraPoT's OWN prompt format, so the adapter
drops straight into the on_device agent slot.

State comes from PRODUCTION, not a reimplementation
───────────────────────────────────────────────────
Each row is one turn of a session. Production never sees a bare command — the
PromptManager wraps it with SYSTEM_STATE (SRi), and SRi at turn N is the result
of turns 0..N-1: `mkdir` adds a directory, `apt install` adds a package, `cd`
moves cwd, `rm` removes a file. If every training prompt carried the same fresh
state, the model would never see the state block change and would learn to
ignore it — which is the one thing this prompt format exists to teach.

So we replay each session through main.make_command_handler() — the real
pipeline: classify() routing, _needs_llm overrides, deterministic handlers, cd
and state tracking, FI scoring. The three agents are replaced by LOOKUP STUBS
returning the dataset's recorded response, so there are no live agent calls
(no GPU, no Cowrie, no cloud API). Same technique as
NSC/PartC/replay_honeyrouter.py, which does this for the HoneyRouter arm.

The prompt is captured BEFORE the command runs (what the model would see at
inference) and the command is then executed so SRi advances for the next turn.

NOTE: H_i has been removed from HydraPoT entirely — SYSTEM_STATE is the single
source of session memory, and the prompt has no Interaction History section.
Training data therefore contains SRi only, matching inference exactly.

Split is BY SESSION, not by row: turns of one session share state, so a random
row split would put turn 3 in train and turn 5 in test — leakage that inflates
the score.

    python finetuning/prepare_dataset.py
    python finetuning/prepare_dataset.py --test-size 0.2 --seed 42 --limit 20

Outputs -> finetuning/data/{train,test}.jsonl   ({"messages":[...]} per line)
"""
import os
import sys
import json
import types
import random
import argparse
from collections import defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from datasets import load_dataset

DATASET = "zyw-286/shell-attack-evolution-dataset"
CONFIG, SPLIT = "request_response", "curated"
OUT_DIR = os.path.join(_HERE, "data")


class _Stub:
    """Stands in for cowrie / on_device / cloud. Returns the dataset's recorded
    response for the turn currently being replayed, so the real pipeline runs
    end-to-end with no live agent. Surface matches what main.handle() calls."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.shell = types.SimpleNamespace(send=lambda *a, **k: None)

    # CowrieAgent surface
    def _connect(self):                       return None
    def _collect_until_prompt(self, *a, **k): return ""
    def disconnect(self):                     return None
    def send(self, *args):
        # cowrie: send(cmd) -> (output, _);  llm: send(system, user) -> str
        resp = self.ctx.get("response", "")
        return (resp, None) if len(args) == 1 else resp

    def send_with_usage(self, system_prompt, user_prompt):
        return self.ctx.get("response", ""), None


class _FakeChannel:
    """Collects anything the pipeline streams to the attacker's terminal."""

    def __init__(self):
        self.buf = []

    def write(self, s):
        self.buf.append(s)

    def read(self, *a, **k):
        return ""

    def text(self):
        return "".join(self.buf)


def build_examples(rows, limit=0):
    """Replay sessions through the production pipeline, capturing each prompt."""
    import main as hp
    from config_loader import load_config

    by_session = defaultdict(list)
    for r in rows:
        by_session[r["session_id"]].append(r)

    # Silence production writes. handle() -> _finish() -> log() inserts into
    # the live sessions table, and FILogManager(store="sqlite") inserts into
    # impactful. Replaying 1,489 turns would inject that much junk into the
    # dashboard's data under a fake src_ip. (This is exactly how the existing
    # `hrreplay_*` rows ended up in the production DB.) Prep is read-only.
    import storage as _st
    _st.insert_command = lambda *a, **k: None
    _st.insert_impactful = lambda *a, **k: None

    ctx = {"response": ""}
    hp.config = load_config()
    hp.ondevice = _Stub(ctx)
    hp.cloud = _Stub(ctx)
    cowrie_stub = _Stub(ctx)

    sids = sorted(by_session)
    if limit:
        sids = sids[:limit]

    out, errors = defaultdict(list), 0
    for sid in sids:
        turns = sorted(by_session[sid], key=lambda r: int(r.get("turn_index") or 0))
        # fresh handle per session -> fresh SYSTEM_STATE, like a new SSH connection
        handle = hp.make_command_handler(
            cowrie_stub, src_ip=f"ft_{sid}", public_ip=f"ft_{sid}", plugins=None)

        for r in turns:
            cmd, resp = r.get("command"), r.get("response")
            if not cmd or not resp:
                continue
            ctx["response"] = resp

            # capture the prompt as it stands BEFORE this command mutates state
            system_prompt, user_prompt = handle.prompt_manager.build_prompt(cmd)
            out[sid].append({"messages": [
                {"role": "system",    "content": system_prompt},
                {"role": "user",      "content": user_prompt},
                {"role": "assistant", "content": resp},
            ]})

            # run it so SRi advances for the next turn (deterministic handlers,
            # cd tracking, installed/files/services updates)
            try:
                ch = _FakeChannel()
                handle(cmd, ch.write, ch.read)
            except Exception as e:
                errors += 1
                if errors <= 5:
                    print(f"[prep] handle error on {cmd!r}: {type(e).__name__}: {e}")

    if errors:
        print(f"[prep] {errors} turns raised during replay (prompt still captured)")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--limit", type=int, default=0, help="first N sessions (smoke test)")
    args = ap.parse_args()

    print(f"[prep] loading {DATASET} :: {CONFIG} / {SPLIT}")
    ds = load_dataset(DATASET, CONFIG, split=SPLIT)
    print(f"[prep] {len(ds):,} rows")

    per_session = build_examples(list(ds), limit=args.limit)

    # Split by session (no turn leakage) but balance on TURN count, not session
    # count: sessions range from 1 to dozens of turns, so taking 20% of the
    # session list gave a 66/34 turn split. Walk the shuffled sessions and fill
    # the test side until it holds test_size of all turns.
    sids = sorted(per_session)
    random.Random(args.seed).shuffle(sids)
    total_turns = sum(len(per_session[s]) for s in sids)
    target = total_turns * args.test_size
    # Largest-first, and only take a session if it still FITS the test quota.
    # Session sizes are extremely skewed here — the biggest single session is
    # 352 of 1,489 turns (24%), median 2 — so a naive "first N sessions" or
    # "add until over target" split lands at 66/34 whenever that one session
    # falls on the test side.
    test_ids, running = set(), 0
    for sid in sorted(sids, key=lambda x: -len(per_session[x])):
        n_turns = len(per_session[sid])
        if running + n_turns <= target:
            test_ids.add(sid)
            running += n_turns
    train_ids = set(sids) - test_ids

    os.makedirs(OUT_DIR, exist_ok=True)
    counts = {}
    for name, ids in (("train", train_ids), ("test", test_ids)):
        path = os.path.join(OUT_DIR, f"{name}.jsonl")
        n = 0
        with open(path, "w", encoding="utf-8") as f:
            for sid in ids:
                for ex in per_session[sid]:
                    f.write(json.dumps(ex, ensure_ascii=False) + "\n")
                    n += 1
        counts[name] = n
        print(f"[prep] {name:<5} {len(ids):>4} sessions  {n:>5} turns  -> {path}")

    tot = sum(counts.values()) or 1
    print(f"[prep] split by SESSION (no turn leakage) — "
          f"{counts['train']/tot*100:.0f}/{counts['test']/tot*100:.0f} by turn")


if __name__ == "__main__":
    main()
