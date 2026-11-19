"""
experiment_data/PartC/oscar/paper_suite.py -- the rest of OSCAR's evaluation
(Gil et al., TDSC 2026), on HydraPoT.

    heldout   Sec. VI-E  commands the rule core has no handler for, interleaved
                         with the create-revisit probe (Table V)
    attack    Sec. VI-D  ten ATT&CK tactic scenarios (Table III)
    wild      Sec. VI-I  replay of real captured Cowrie sessions: sessions of
                         5-50 commands, duplicates removed, top 100 by distinct
                         commands, per dataset

Every session is also run in a real Ubuntu 20.04 container (no network), so
"failed" means we failed where the real shell did not:

    CRR    fraction of commands answered
    FSRR   fraction of sessions in which every command was answered
    depth  commands sustained before the first failure or contradiction
    MSL%   depth as a fraction of the session length
    contradictions from the import-isolated oracle (oracle.py)

    python paper_suite.py --mode heldout --repo <repo> --runs 30 --out r.json
"""
import argparse
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import probe                    # noqa: E402
from oracle import count        # noqa: E402

_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "experiment_data"))
IMAGE = "hp-real:20.04"
# Output no shell prints: a stub, an unparsed model reply, or a missing tool
FAIL = re.compile(r"command not found|applet not found|<cowrie>|<ondevice>"
                  r"|head: invalid option -- '\d+'|tail: invalid option -- '\d+'", re.I)
# Fetching tools reach the network; the replay is simulation only
BLOCKED = re.compile(r"\b(wget|curl|tftp|ftpget|ftp|nc|ncat|telnet|dd|mkfs\S*|shutdown|"
                     r"reboot|halt|poweroff|nohup|sleep\s+\d{3,})\b|:\(\)\s*\{")

HELDOUT = [
    "basename /root/loot/key.pem", "dirname /root/loot/key.pem", "file key.pem",
    "which ls", "sort key.pem", "cut -c1-4 key.pem", "awk '{print length($0)}' key.pem",
    "sed 's/AKIA/XXXX/' key.pem", "base64 key.pem", "tac sub/n.txt", "rev sub/n.txt",
    "nl sub/n.txt", "diff key.pem sub/n.txt", "cmp key.pem key.pem",
    "find . -name '*.txt'", "test -f key.pem && echo yes", "date +%Y", "expr 6 \\* 7",
    "seq 1 3", "printf '%s\\n' a b", "id -u", "stat -c %s key.pem", "head -c 4 key.pem",
    "tail -n 1 sub/n.txt", "grep -c AKIA key.pem", "uniq key.pem", "tr a-z A-Z < key.pem",
    "od -c key.pem | head -2", "echo $((6*7))", "whoami",
]

TACTICS = {
    "execution": ["id", "whoami", "echo '#!/bin/sh' > run.sh", "echo 'echo executed' >> run.sh",
                  "chmod +x run.sh", "./run.sh", "bash run.sh", "sh -c 'echo hi'",
                  "python3 -c 'print(1+1)'", "cat run.sh", "ls -l run.sh"],
    "persistence": ["mkdir -p ~/.ssh", "echo 'ssh-rsa AAAA test' >> ~/.ssh/authorized_keys",
                    "chmod 600 ~/.ssh/authorized_keys", "cat ~/.ssh/authorized_keys",
                    "crontab -l", "echo '* * * * * /tmp/x' > /tmp/cron.txt", "cat /tmp/cron.txt",
                    "ls -la ~/.ssh", "ls /etc/cron.d", "cat /etc/crontab"],
    "privilege_escalation": ["id", "sudo -l", "find / -perm -4000 -type f 2>/dev/null",
                             "cat /etc/sudoers", "ls -l /etc/shadow", "uname -r",
                             "cat /etc/passwd", "ls -ld /root", "getent passwd root", "groups"],
    "defense_evasion": ["history -c", "unset HISTFILE", "export HISTSIZE=0",
                        "touch -r /etc/passwd /tmp/f", "echo x > /tmp/.hidden", "ls -la /tmp",
                        "chmod 000 /tmp/.hidden", "rm /tmp/.hidden", "ls -la /tmp",
                        "tail -n 2 /var/log/auth.log"],
    "credential_access": ["cat /etc/passwd", "cat /etc/shadow", "ls -la ~/.ssh",
                          "find / -name id_rsa 2>/dev/null", "cat ~/.bash_history",
                          "printenv HOME", "cat /proc/version", "grep root /etc/passwd",
                          "ls -l /etc/shadow", "id"],
    "discovery": ["uname -a", "hostname", "whoami", "id", "ps aux", "ip a", "ss -tlnp",
                  "df -h", "free -m", "cat /etc/os-release", "ls /home", "w", "last"],
    "lateral_movement": ["cat ~/.ssh/known_hosts", "ls ~/.ssh", "ssh -V", "cat /etc/hosts",
                         "ip route", "cat /etc/resolv.conf", "hostname -I", "ls /etc/ssh",
                         "echo done"],
    "collection": ["mkdir /tmp/loot", "cp /etc/passwd /tmp/loot/", "cp /etc/hostname /tmp/loot/",
                   "tar czf /tmp/loot.tgz /tmp/loot", "ls -l /tmp/loot.tgz",
                   "find /home -name '*.txt' 2>/dev/null", "head -n 2 /tmp/loot/passwd",
                   "wc -l /tmp/loot/passwd", "du -sh /tmp/loot", "ls /tmp/loot"],
    "exfiltration": ["tar czf /tmp/d.tgz /etc/hostname", "ls -l /tmp/d.tgz", "md5sum /tmp/d.tgz",
                     "wc -c /tmp/d.tgz", "split -b 10 /tmp/d.tgz /tmp/p_", "ls /tmp",
                     "rm /tmp/d.tgz", "ls /tmp", "echo exfil done"],
    "command_and_control": ["which curl wget nc", "echo '*/5 * * * * root true' > /tmp/c2cron",
                            "cat /tmp/c2cron", "sleep 300 &", "ps aux", "jobs", "kill %1",
                            "ps aux", "echo ok"],
}


def real_run(cmds):
    """Run the commands in one real bash in a throwaway, network-less container."""
    mark = "__HP_REAL_END__"
    # One bash for the whole session, so cwd and variables carry over
    script = "cd /root\n" + "".join(f"{c} 2>&1 </dev/null\necho {mark}\n" for c in cmds)
    out = subprocess.run(
        ["docker", "run", "--rm", "-i", "--network", "none", "--memory", "256m",
         "--pids-limit", "128", "--cpus", "1", IMAGE, "bash"],
        input=script, capture_output=True, text=True, timeout=120).stdout
    parts = out.split(mark + "\n")
    parts += [""] * (len(cmds) - len(parts))
    return [p.rstrip("\n") for p in parts[:len(cmds)]]


def failed(ours, real):
    ours, real = ours.strip(), real.strip()
    if FAIL.search(ours) and not FAIL.search(real):
        return True
    return not ours and bool(real)         # silent where the real shell prints


# Outputs that differ between two runs of the SAME real shell, or that depend on the
# persona (hostname psu, kernel 5.15.0-139) rather than on state. They still count
# as answered; they are left out of exact-match, where a Docker host is no reference.
NOISY = re.compile(r"^(ps|top|w|uptime|last|who|free|df|ip|ss|netstat|uname|hostname|lscpu|"
                   r"nproc|date|history|env|printenv\s*$)\b|sudo\s+-l|find\s+/\s|/proc/|"
                   r"os-release|(md5|sha\d+)sum\s+\S+\.(tgz|gz)|ls\s+-\w*\s+/(dev|run)", re.I)
_VOLATILE = re.compile(r"[A-Z][a-z]{2} [ \d]\d (\d\d:\d\d| \d{4})|\d\d:\d\d(:\d\d)?|\b\d{3,}\b")


def same(ours, real):
    """Equal once dates, clock times and long numbers (pids, inodes, sizes) are masked."""
    norm = lambda t: _VOLATILE.sub("#", t.strip())
    return norm(ours) == norm(real)


def score(cmds, transcript, real):
    flags = [failed(out, r) for (_, out), r in zip(transcript, real)]
    stable = [i for i, c in enumerate(cmds) if not NOISY.search(c.strip())]
    wrong = [cmds[i] for i in stable if not flags[i] and not same(transcript[i][1], real[i])]
    contra = count(transcript)
    first_bad = [i for i, f in enumerate(flags) if f] + [c["seq"] for c in contra]
    depth = min(first_bad) if first_bad else len(cmds)
    return {"commands": len(cmds), "failed": sum(flags), "answered": len(cmds) - sum(flags),
            "all_answered": not any(flags), "depth": depth,
            "stable": len(stable), "exact": len([i for i in stable if not flags[i]]) - len(wrong),
            "wrong_cmds": wrong[:12], "contradictions": contra,
            "failed_cmds": [cmds[i] for i, f in enumerate(flags) if f][:12]}


def heldout_session():
    # held-out commands go between create and revisit, as in the paper's probe
    return probe.CREATE + HELDOUT + probe.REVISIT


def wild_sessions(top=100, seed=0):
    """Paper Sec. VI-A: 5-50 commands, no duplicate sequences, top by distinct commands."""
    import workloads
    out = {}
    ml4net = json.load(open(workloads.ML4NET_FILE, encoding="utf-8"))
    pools = {"ml4net": [[c.strip() for c in e.get("commands", "").split(";") if c.strip()]
                        for e in ml4net]}
    lab = []
    for s in workloads.load_cyberlab_sessions():
        lab.append(s["commands"])
    pools["cyberlab"] = lab
    for name, sessions in pools.items():
        seen, kept = set(), []
        for cmds in sessions:
            cmds = [c for c in cmds if not BLOCKED.search(c) and len(c) < 400]
            key = tuple(cmds)
            if 5 <= len(cmds) <= 50 and key not in seen:
                seen.add(key)
                kept.append(cmds)
        kept.sort(key=lambda c: -len(set(c)))
        out[name] = kept[:top]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["heldout", "attack", "wild"])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--dataset", choices=["ml4net", "cyberlab"])
    ap.add_argument("--shard", default="0/1", help="i/n: this process's slice of the sessions")
    ap.add_argument("--no-gate", action="store_true")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    jobs = []                                  # (label, commands)
    if args.mode == "heldout":
        jobs = [("heldout", heldout_session()) for _ in range(args.runs)]
    elif args.mode == "attack":
        jobs = [(t, c) for t, c in TACTICS.items() for _ in range(args.runs)]
    else:
        jobs = [(f"{args.dataset}:{i}", c) for i, c in
                enumerate(wild_sessions()[args.dataset])]
    i, n = map(int, args.shard.split("/"))
    jobs = jobs[i::n]

    new_handler = probe.make_handler(os.path.abspath(args.repo), gate=not args.no_gate)
    results = []
    for label, cmds in jobs:
        t0 = time.time()
        try:
            for attempt in range(3):
                if not new_handler.cowrie.available:
                    new_handler.cowrie._connect()
                transcript, gate = probe.run_hydrapot(new_handler, cmds)
                # A session that lost Cowrie measured a different system: discard it
                if new_handler.cowrie.available:
                    break
                print(f"{label}: Cowrie dropped mid-session, retry {attempt + 1}", flush=True)
            else:
                raise RuntimeError("Cowrie kept dropping; session not scored")
            real = real_run(cmds)
        except Exception as exc:                      # one bad session must not end the run
            print(f"{label}: ERROR {exc}", flush=True)
            continue
        row = score(cmds, transcript, real)
        row.update({"label": label, "gate": gate, "transcript": transcript,
                    "real": real, "seconds": round(time.time() - t0, 1)})
        results.append(row)
        print(f"{label}: answered {row['answered']}/{row['commands']}  depth {row['depth']}"
              f"  contradictions {len(row['contradictions'])}", flush=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
