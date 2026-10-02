"""
honeyrouter/cli.py — train and review the HoneyRouter from a terminal.

Same three phases as gui.py, without a browser. One policy serves every omega,
so omega is picked in review rather than before training.

State: out/router_state.json. Approval is recorded there and nothing else —
the honeypot still routes with routing.fi_routing.

    python honeyrouter/cli.py              interactive
    python honeyrouter/cli.py --status
    python honeyrouter/cli.py --train
    python honeyrouter/cli.py --review
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
sys.path.insert(0, _ROOT)

OUT_DIR = os.path.join(_HERE, "out")
STATE_PATH = os.path.join(OUT_DIR, "router_state.json")
EXTRA_PATH = os.path.join(OUT_DIR, "extra_models.json")
PY = sys.executable

ARTIFACTS = {
    "predictor": "predictor.pt",
    "policy":    "routing_policy.pt",
    "rl":        "routing_policy_rl.pt",
}

DEFAULTS = {"p1_epochs": 300, "p2_steps": 4000, "p2_batch": 256,
            "p3_steps": 3000, "run_rl": True, "mixup": True}


# ── state ───────────────────────────────────────────────────────────────────

def _read_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _write_state(state: dict) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def data_fingerprint() -> dict:
    # Compared against what training saw, so `stale` means new data, not an old file.
    """Size of the replay right now."""
    from honeyrouter.sessions import load_sessions
    sess = load_sessions()
    return {"sessions": len(sess),
            "commands": sum(len(v) for v in sess.values())}


def status() -> dict:
    """State: not_trained, partial, trained, approved or stale."""
    state = _read_state()
    have = {k: os.path.exists(os.path.join(OUT_DIR, f))
            for k, f in ARTIFACTS.items()}
    try:
        current = data_fingerprint()
    except Exception:
        current = None

    missing = [k for k, ok in have.items() if not ok]
    if not have["predictor"] and not have["policy"]:
        label = "not_trained"
    elif missing:
        label = "partial"
    elif (current and state.get("trained_on")
          and state["trained_on"] != current):
        label = "stale"
    elif state.get("approved"):
        label = "approved"
    else:
        label = "trained"

    return {"state": label, "stages": state.get("stages", {}),
            "trained_on": state.get("trained_on"), "current": current,
            "approved": state.get("approved"), "missing": missing,
            "have": have}


EXPLAIN = {
    "not_trained": "The router has never been trained.",
    "partial":     "Training stopped part-way; some phases are missing.",
    "trained":     "Trained, not reviewed yet.",
    "approved":    "Trained and approved.",
    "stale":       "Trained, but the replay has changed since.",
}


# ── training ────────────────────────────────────────────────────────────────

def _phases(cfg: dict) -> list:
    out = [
        ("Phase 1 · IRT predictor", cfg["p1_epochs"], "ep",
         [PY, "-u", os.path.join(_HERE, "predictor.py"),
          "--epochs", str(cfg["p1_epochs"])]),
        ("Phase 2 · policy pretraining", cfg["p2_steps"], "step",
         [PY, "-u", os.path.join(_HERE, "routing_policy.py"),
          "--steps", str(cfg["p2_steps"]), "--batch", str(cfg["p2_batch"])]),
    ]
    if cfg["run_rl"]:
        rl = [PY, "-u", os.path.join(_HERE, "reinforcement.py"),
              "--steps", str(cfg["p3_steps"])]
        if not cfg["mixup"]:
            rl.append("--no-mixup")
        out.append(("Phase 3 · RL (multi-objective PPO)", cfg["p3_steps"],
                    "step", rl))
    return out


def train(cfg: dict = None, quiet: bool = False) -> bool:
    """Run every phase with a bar each. True if all finished."""
    cfg = {**DEFAULTS, **(cfg or {})}
    phases = _phases(cfg)
    os.makedirs(OUT_DIR, exist_ok=True)

    try:
        from rich.console import Console
        from rich.progress import (Progress, BarColumn, TextColumn,
                                   TimeElapsedColumn, MofNCompleteColumn,
                                   TaskProgressColumn)
        console = Console()
    except ImportError:
        console = None

    state = _read_state()
    state.setdefault("stages", {})
    started = time.time()

    def run(name, cmd, total, kind, advance):
        """advance(done_units), or None when there is no bar."""
        # "ep 12" / "step 400" is the only progress signal each phase emits
        pat = re.compile(rf"\b{kind}\s+(\d+)")
        proc = subprocess.Popen(cmd, cwd=_ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1,
                                env={**os.environ, "PYTHONUNBUFFERED": "1"})
        last = 0
        tail = []
        for line in proc.stdout:
            tail = (tail + [line.rstrip()])[-8:]
            if "it/s]" in line or "Loading weights" in line:
                continue
            m = pat.search(line)
            if m and advance:
                now = min(total, int(m.group(1)))
                if now > last:
                    advance(now - last)
                    last = now
        proc.wait()
        if proc.returncode != 0:
            if console:
                console.print(f"[red]{name} failed (exit {proc.returncode})[/red]")
                for t in tail:
                    console.print(f"    {t}", style="dim")
            else:
                print(f"{name} failed (exit {proc.returncode})")
                for t in tail:
                    print("   ", t)
            return False
        if advance and last < total:
            advance(total - last)
        return True

    ok = True
    if console and not quiet:
        with Progress(TextColumn("[bold]{task.description}"), BarColumn(),
                      TaskProgressColumn(), MofNCompleteColumn(),
                      TimeElapsedColumn(), console=console) as bar:
            # Each phase reports its own units, so an overall bar needs one
            # shared scale: every phase is worth the same slice of 100.
            slice_pct = 100.0 / len(phases)
            overall = bar.add_task("[cyan]Overall", total=100.0)
            for i, (name, total, kind, cmd) in enumerate(phases):
                task = bar.add_task(name, total=total)

                # Counted here, not read back from bar.tasks: removing a
                # finished task shifts that list and the lookup goes stale.
                done = [0]

                def advance(n, t=task, tot=total, d=done):
                    d[0] += n
                    bar.advance(t, n)
                    bar.update(overall, completed=min(
                        100.0, i * slice_pct + d[0] / tot * slice_pct))

                started = time.time()
                if not run(name, cmd, total, kind, advance):
                    ok = False
                    break
                # Collapse the finished phase to one line so only the running
                # one has a live bar.
                bar.remove_task(task)
                bar.console.print(f"  [green]✓[/green] {name}  "
                                  f"[dim]{total} {kind} in "
                                  f"{time.time() - started:.0f}s[/dim]")
                bar.update(overall, completed=(i + 1) * slice_pct)
                key = ("predictor" if "predictor" in cmd[2] else
                       "policy" if "routing_policy" in cmd[2] else "rl")
                state["stages"][key] = {"at": time.strftime("%Y-%m-%d %H:%M:%S"),
                                        "units": total}
    else:
        for name, total, kind, cmd in phases:
            print(f"===== {name} =====")
            if not run(name, cmd, total, kind, None):
                ok = False
                break
            key = ("predictor" if "predictor" in cmd[2] else
                   "policy" if "routing_policy" in cmd[2] else "rl")
            state["stages"][key] = {"at": time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "units": total}

    if ok:
        state["trained_on"] = data_fingerprint()
        state["config"] = cfg
        state["took_sec"] = round(time.time() - started, 1)
        # An approval belonged to the old weights
        state.pop("approved", None)
    _write_state(state)
    return ok


# ── review ──────────────────────────────────────────────────────────────────

_DATA = {}


def _load_data():
    if _DATA:
        return _DATA
    import numpy as np
    import torch
    from honeyrouter import predictor as P
    from honeyrouter import routing_policy as RP
    if not os.path.exists(os.path.join(OUT_DIR, ARTIFACTS["predictor"])):
        return None
    model, _ = P.load()
    E, score, cost, _sids, _pairs = RP.build_pairwise_dataset()
    I = model.mu.detach()
    with torch.no_grad():
        p_hat = torch.sigmoid(model.logits(torch.tensor(E), I)).numpy()
    cn = cost / np.maximum(cost.max(1, keepdims=True), 1e-8)
    _DATA.update(dict(E=E, score=score, cost=cost, cost_norm=cn,
                      I=I.numpy(), p_hat=p_hat, np=np, torch=torch))
    return _DATA


def _policy(which: str):
    from honeyrouter import routing_policy as RP
    if which == "rl":
        from honeyrouter import reinforcement as RL
        if not os.path.exists(os.path.join(OUT_DIR, ARTIFACTS["rl"])):
            return None
        pol, _, _ = RL.load_rl_policy()
        return pol
    if not os.path.exists(os.path.join(OUT_DIR, ARTIFACTS["policy"])):
        return None
    pol, _ = RP.load_policy()
    return pol


def _picks(pol, omega: float):
    from honeyrouter.action import AGENTS
    d = _load_data()
    torch = d["torch"]
    n = d["E"].shape[0]
    I = torch.tensor(d["I"])
    e = torch.tensor(d["E"])
    I_ctx = I.unsqueeze(0).expand(n, len(AGENTS), I.shape[1])
    c_ctx = torch.tensor(d["cost_norm"]).unsqueeze(-1)
    p_ctx = torch.tensor(d["p_hat"]).unsqueeze(-1)
    w = torch.tensor([[1.0, float(omega)]]).expand(n, 2)
    with torch.no_grad():
        return pol.logits(e, I_ctx, c_ctx, p_ctx, w).argmax(1).numpy()


def sweep(which: str = "rl", points: int = 9, w_max: float = 2.0) -> list:
    """What each w buys, measured on the replay. w weights -cost, so higher
    is cheaper. Range matches reinforcement.py training: w ~ U(0, 2)."""
    from honeyrouter.action import AGENTS
    d = _load_data()
    if d is None:
        return []
    pol = _policy(which)
    if pol is None:
        return []
    np = d["np"]
    rows = []
    idx = np.arange(d["E"].shape[0])
    for omega in [round(i * w_max / (points - 1), 2) for i in range(points)]:
        pick = _picks(pol, omega)
        rows.append({
            "omega": omega,
            "judge": float(d["score"][idx, pick].mean()),
            "cost":  float(d["cost"][idx, pick].sum()),
            "mix": {a: int((pick == k).sum()) for k, a in enumerate(AGENTS)},
        })
    return rows


def baselines() -> list:
    """Single-arm rows, to compare the sweep against."""
    from honeyrouter.action import AGENTS
    d = _load_data()
    if d is None:
        return []
    return [{"name": f"always {a}",
             "judge": float(d["score"][:, k].mean()),
             "cost": float(d["cost"][:, k].sum())}
            for k, a in enumerate(AGENTS)]


def print_review(which: str = "rl") -> list:
    from honeyrouter.action import AGENTS
    rows = sweep(which)
    if not rows:
        print("Nothing to review — train first.")
        return []
    try:
        from rich.console import Console
        from rich.table import Table
        t = Table(title=f"w sweep · {which} policy · {len(_DATA['E'])} commands")
        t.add_column("w", justify="right")
        t.add_column("fidelity", justify="right")
        t.add_column("cost $", justify="right")
        for a in AGENTS:
            t.add_column(a, justify="right")
        for r in rows:
            t.add_row(f"{r['omega']:.1f}", f"{r['judge']:.3f}",
                      f"{r['cost']:.4f}",
                      *[str(r["mix"][a]) for a in AGENTS])
        c = Console()
        c.print(t)
        b = Table(title="for comparison")
        b.add_column("policy"); b.add_column("fidelity", justify="right")
        b.add_column("cost $", justify="right")
        for r in baselines():
            b.add_row(r["name"], f"{r['judge']:.3f}", f"{r['cost']:.4f}")
        c.print(b)
    except ImportError:
        hdr = f"{'w':>6} {'fidelity':>9} {'cost $':>10}  " + \
              " ".join(f"{a:>10}" for a in AGENTS)
        print(hdr)
        for r in rows:
            print(f"{r['omega']:>6.1f} {r['judge']:>9.3f} {r['cost']:>10.4f}  " +
                  " ".join(f"{r['mix'][a]:>10}" for a in AGENTS))
    return rows


def approve(which: str, omega: float) -> str:
    """Record the choice. Writes a file, changes nothing else."""
    state = _read_state()
    state["approved"] = {"at": time.strftime("%Y-%m-%d %H:%M:%S"),
                         "policy": which, "omega": float(omega)}
    state.setdefault("trained_on", data_fingerprint())
    _write_state(state)
    return STATE_PATH


# ── terminal ────────────────────────────────────────────────────────────────

def print_status() -> dict:
    s = status()
    try:
        from rich.console import Console
        c = Console()
        colour = {"approved": "green", "trained": "yellow", "stale": "yellow",
                  "partial": "red", "not_trained": "red"}[s["state"]]
        c.print(f"\n  HoneyRouter: [{colour}]{s['state']}[/{colour}] "
                f"— {EXPLAIN[s['state']]}")
    except ImportError:
        print(f"\n  HoneyRouter: {s['state']} — {EXPLAIN[s['state']]}")

    for key, fname in ARTIFACTS.items():
        mark = "✓" if s["have"][key] else "·"
        done = s["stages"].get(key, {}).get("at", "")
        print(f"    {mark} {key:10} {fname:24} {done}")

    if s["trained_on"]:
        t, cur = s["trained_on"], s["current"]
        print(f"    trained on {t['commands']} commands / {t['sessions']} sessions")
        if cur and cur != t:
            print(f"    replay now {cur['commands']} commands / "
                  f"{cur['sessions']} sessions  ← retrain to use them")
    if s["approved"]:
        a = s["approved"]
        print(f"    approved   {a['policy']} @ omega={a['omega']} on {a['at']}")
    print("\n    Approval is recorded only. The honeypot routes with "
          "routing.fi_routing\n    from config.yaml until the router is wired in.\n")
    return s


def _interactive():
    import questionary
    s = print_status()

    action = questionary.select(
        "What now?",
        choices=["Train (all phases)", "Review a trained policy",
                 "Show status only", "Quit"]).ask()
    if action is None or action.startswith("Quit"):
        return
    if action.startswith("Show"):
        return

    if action.startswith("Train"):
        if s["state"] in ("trained", "approved", "stale"):
            if not questionary.confirm(
                    "Already trained — retrain from scratch?", default=False).ask():
                return
        cfg = dict(DEFAULTS)
        if questionary.confirm("Change the defaults?", default=False).ask():
            cfg["p1_epochs"] = int(questionary.text(
                "Phase 1 epochs", default=str(cfg["p1_epochs"])).ask())
            cfg["p2_steps"] = int(questionary.text(
                "Phase 2 steps", default=str(cfg["p2_steps"])).ask())
            cfg["run_rl"] = questionary.confirm(
                "Run Phase 3 (RL)?", default=True).ask()
            if cfg["run_rl"]:
                cfg["p3_steps"] = int(questionary.text(
                    "Phase 3 steps", default=str(cfg["p3_steps"])).ask())
        if not train(cfg):
            print("\n  Training did not finish. Nothing was approved.\n")
            return
        print("\n  Training done.\n")

    which = "rl" if os.path.exists(os.path.join(OUT_DIR, ARTIFACTS["rl"])) else "policy"
    rows = print_review(which)
    if not rows:
        return

    print("  w weights cost: w=0 ignores price, higher w gets cheaper.\n")
    choice = questionary.select(
        "Approve which omega?",
        choices=[f"w {r['omega']:.2f}  fidelity {r['judge']:.3f}  "
                 f"cost ${r['cost']:.4f}" for r in rows] + ["Approve none"]).ask()
    if choice is None or choice == "Approve none":
        print("\n  Nothing approved.\n")
        return
    omega = float(choice.split()[1])
    if questionary.confirm(f"Record approval of {which} @ omega={omega}?",
                           default=True).ask():
        path = approve(which, omega)
        print(f"\n  Approved. Written to {os.path.relpath(path, _ROOT)}")
        print("  Nothing else changed — the honeypot still uses "
              "routing.fi_routing.\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--status", action="store_true", help="print state and exit")
    ap.add_argument("--train", action="store_true", help="train with defaults")
    ap.add_argument("--review", action="store_true", help="sweep omega and print")
    ap.add_argument("--policy", default="rl", choices=["rl", "policy"],
                    help="which policy to review (default: rl)")
    ap.add_argument("--approve-omega", type=float, default=None,
                    help="record approval of this omega, no prompts")
    a = ap.parse_args()

    if a.status:
        print_status()
    elif a.train:
        ok = train()
        print_status()
        raise SystemExit(0 if ok else 1)
    elif a.review:
        print_review(a.policy)
    elif a.approve_omega is not None:
        print(f"Approved -> {approve(a.policy, a.approve_omega)}")
    else:
        _interactive()


if __name__ == "__main__":
    main()
