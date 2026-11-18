"""
experiment_data/PartC/oscar/probe.py — create-then-revisit probe (OSCAR Table I/XIV).

A session creates files and directories, runs L filler commands, then revisits
everything it created. The transcript goes to the import-isolated oracle.

    # through a HydraPoT checkout, every model-served command on the cloud LLM
    python probe.py --repo <repo root> --fillers 5 20 --runs 3 --out res.json
    # calibrate the oracle on a real shell (must give 0 contradictions)
    python probe.py --real --fillers 5 --out real.json
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from oracle import count       # noqa: E402

# Establishes state for all twelve oracle signatures (paper Table II)
CREATE = [
    "mkdir loot",
    "cd loot",
    "echo AKIAIOSFODNN7EXAMPLE > key.pem",
    "echo 'db_pass=Winter2026' > creds.txt",
    "ls",
    "cat key.pem",
    "ls -l key.pem",
    "stat key.pem",
    "wc -c key.pem",
    "chmod 600 key.pem",
    "ln -s key.pem link.pem",
    "readlink link.pem",
    "export HP_TOKEN=s3cr3t",
    "sleep 1234 &",
    "pwd",
    "mkdir sub",
    "echo note > sub/n.txt",
    "cat creds.txt",
    "rm creds.txt",
]
FILLERS = ["uname -a", "id", "cat /etc/os-release", "df -h", "free -m",
           "uptime", "whoami", "ls /etc", "hostname", "w"]
# Reads every one of them back
REVISIT = [
    "cat key.pem",
    "ls",
    "ls -l key.pem",
    "stat key.pem",
    "wc -c key.pem",
    "du -b key.pem",
    "du -sb /root/loot",
    "readlink link.pem",
    "cat link.pem",
    "printenv HP_TOKEN",
    "echo $HP_TOKEN",
    "ps aux",
    "cat creds.txt",
    "cat sub/n.txt",
    "pwd",
    "cd /tmp",
    "cat /root/loot/key.pem",
    "ls /root/loot",
]


def session(fillers: int):
    return CREATE + [FILLERS[i % len(FILLERS)] for i in range(fillers)] + REVISIT


def run_real(cmds):
    """Each command in one real bash inside a fresh Ubuntu container."""
    marker = "__HP_PROBE_END__"
    # The base image has no `ps`; a real Ubuntu server does
    setup = "apt-get -qq update >/dev/null 2>&1; apt-get -qq install -y procps >/dev/null 2>&1\n"
    script = setup + "cd /root\n" + "".join(f"{c} 2>&1\necho {marker}\n" for c in cmds)
    out = subprocess.run(["docker", "run", "--rm", "-i", "ubuntu:20.04", "bash"],
                         input=script, capture_output=True, text=True, timeout=300).stdout
    parts = out.split(marker + "\n")
    return list(zip(cmds, [p.rstrip("\n") for p in parts[:len(cmds)]]))


def make_handler(repo):
    """A HydraPoT session from `repo`, all model-served commands on the cloud LLM."""
    sys.path[:0] = [repo, os.path.join(repo, "experiment_data"),
                    os.path.join(repo, "experiment_data", "PartA")]
    from agents import build_agents
    import main
    from openai import OpenAI

    base = build_agents(connect_cowrie=True, load_on_device=False)
    cloud = base.cloud
    # Same cloud arm as Part C (run_partC.py)
    url = (os.environ.get("PARTC_BASE_URL") or "").rstrip("/") or cloud._base_url
    cloud.model, cloud._base_url = "deepseek/deepseek-v4.1-flash", url
    cloud._api_key = cloud._pool.current()
    cloud.client = OpenAI(api_key=cloud._api_key, base_url=url)
    # On-device GPU is busy: the cloud model answers its share too
    main.ondevice = cloud
    main.cloud = cloud
    return lambda: main.make_command_handler(
        base.cowrie, src_ip="probe", public_ip="probe", plugins=None,
        capture_cost=True, store="json", store_dir=tempfile.mkdtemp(prefix="probe_"))


def run_hydrapot(new_handler, cmds):
    h = new_handler()
    transcript = []
    for cmd in cmds:
        buf = []
        out, _ = h(cmd, write_fn=buf.append, read_fn=lambda: "")
        transcript.append((cmd, (out or "".join(buf)).replace("\r\n", "\n").strip("\n")))
    gate = getattr(h, "gate", None)
    return transcript, (gate.metrics() if gate else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", help="HydraPoT checkout to probe")
    ap.add_argument("--real", action="store_true", help="probe a real Ubuntu shell")
    ap.add_argument("--fillers", type=int, nargs="+", default=[5])
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    new_handler = None if args.real else make_handler(os.path.abspath(args.repo))
    results = []
    for fillers in args.fillers:
        for run in range(args.runs):
            cmds = session(fillers)
            t0 = time.time()
            if args.real:
                transcript, gate = run_real(cmds), None
            else:
                transcript, gate = run_hydrapot(new_handler, cmds)
            found = count(transcript)
            results.append({"fillers": fillers, "run": run, "contradictions": found,
                            "gate": gate, "transcript": transcript,
                            "seconds": round(time.time() - t0, 1)})
            print(f"L={fillers} run={run}: {len(found)} contradiction(s)"
                  + (f"  gate={gate}" if gate else ""), flush=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
