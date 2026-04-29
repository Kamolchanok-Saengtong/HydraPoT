"""
evaluation/normalizer.py
─────────────────────────────────────────────────────────────────
Normalizes dynamic values in Linux terminal output before scoring.
Inspired by Drain log parsing — replaces variable parts with tokens
so scoring measures structural correctness, not exact value matching.

Example:
    raw  : "inet 192.168.1.1 netmask 255.255.255.0 broadcast 192.168.1.255"
    norm : "inet [IP_ADDR] netmask [NETMASK] broadcast [IP_ADDR]"

Reusable — import in fidelity.py:
    from normalizer import normalize
─────────────────────────────────────────────────────────────────
"""

import re

# ─── Normalization Rules ──────────────────────────────────────────────────────
# Order matters — more specific patterns first to avoid partial matches
# e.g. netmask (255.x.x.x) must come before IP (x.x.x.x)

RULES = [

    # ── uuid — must come before PID/HEX rules ────────────────────────────────
    (r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', "[UUID]"),

    # ── network ───────────────────────────────────────────────────────────────

    # netmask — must come before IP (255.x.x.x is also an IP pattern)
    (r'\b255\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',                        "[NETMASK]"),

    # IPv6
    (r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',               "[IPV6_ADDR]"),

    # IPv4 with CIDR e.g. 192.168.1.0/24
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b',           "[IP_CIDR]"),

    # IPv4
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',                   "[IP_ADDR]"),

    # MAC address e.g. 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E
    (r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b',               "[MAC_ADDR]"),

    # port number after colon e.g. :8080 :22 :443
    (r'(?<=:)\d{1,5}\b',                                            "[PORT]"),

    # network interface e.g. eth0, wlan0, ens33, lo, enp3s0
    (r'\b(eth|wlan|ens|enp|em|bond|tun|tap|virbr|docker|veth)\w*\b', "[INTERFACE]"),

    # ── processes & system ────────────────────────────────────────────────────

    # PID — number after keyword pid/PID
    (r'(?i)(?<=pid\s)\d+',                                          "[PID]"),

    # standalone process id (large numbers likely PIDs e.g. in ps output)
    (r'\b\d{4,6}\b',                                                "[PID]"),

    # ── filesystem ────────────────────────────────────────────────────────────

    # block device e.g. /dev/sda1 /dev/nvme0n1p1
    (r'/dev/[a-zA-Z0-9]+',                                          "[DEVICE]"),

    # file size with unit e.g. 4.0K 1.2M 3G 512B
    (r'\b\d+(\.\d+)?\s*[KMGTP]?B?\b(?=\s)',                        "[SIZE]"),

    # inode number (large number in ls -i output)
    (r'\b\d{6,}\b',                                                 "[INODE]"),

    # ── time & date ───────────────────────────────────────────────────────────

    # full datetime e.g. 2024-01-15 14:22:01
    (r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',                     "[DATETIME]"),

    # date e.g. Jan 15 2024 or 2024-01-15
    (r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2,4}\b', "[DATE]"),
    (r'\b\d{4}-\d{2}-\d{2}\b',                                     "[DATE]"),

    # time e.g. 14:22:01 or 14:22
    (r'\b\d{2}:\d{2}(:\d{2})?\b',                                  "[TIME]"),

    # uptime e.g. 2 days, 3:14
    (r'\b\d+\s+days?,\s+\d+:\d+\b',                                "[UPTIME]"),

    # ── users & permissions ───────────────────────────────────────────────────

    # permissions string e.g. drwxr-xr-x or -rw-r--r--
    (r'[d\-lbcsp][rwx\-]{9}',                                      "[PERMISSIONS]"),

    # ── hashes & hex ──────────────────────────────────────────────────────────

    # MD5/SHA hash (long hex strings)
    (r'\b[0-9a-fA-F]{32,}\b',                                      "[HASH]"),

    # short hex values e.g. 0x1a2b
    (r'\b0x[0-9a-fA-F]+\b',                                        "[HEX]"),

    # ── versions ──────────────────────────────────────────────────────────────

    # version numbers e.g. 3.2.0 1.21.4 2.6.32-754
    (r'\b\d+\.\d+[\.\d\-]*\b',                                     "[VERSION]"),

]

# ─── Normalize ────────────────────────────────────────────────────────────────

def normalize(text: str) -> str:
    """
    Normalize dynamic values in Linux terminal output.
    Replaces variable parts (IPs, MACs, PIDs etc) with fixed tokens.

    Args:
        text : raw terminal output string

    Returns:
        normalized string with dynamic values replaced by tokens

    Example:
        normalize("inet 192.168.1.1 netmask 255.255.255.0")
        → "inet [IP_ADDR] netmask [NETMASK]"
    """
    if not text:
        return text

    for pattern, token in RULES:
        text = re.sub(pattern, token, text)

    # collapse multiple spaces/newlines left by replacements
    text = re.sub(r' +', ' ', text)
    text = text.strip()

    return text

# ─── Normalize Pair ───────────────────────────────────────────────────────────

def normalize_pair(predicted: str, ground_truth: str) -> tuple[str, str]:
    """
    Normalize both predicted and ground truth together.
    Convenience wrapper — use this in fidelity.py before scoring.

    Usage:
        from normalizer import normalize_pair
        pred_norm, gt_norm = normalize_pair(predicted, ground_truth)
        score = cosine_score_response(pred_norm, gt_norm)
    """
    return normalize(predicted), normalize(ground_truth)

# ─── Preview ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # quick test — run directly to see normalization in action
    samples = [
        "inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255",
        "ether 00:1A:2B:3C:4D:5E  txqueuelen 1000  (Ethernet)",
        "tcp  0  0 0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd",
        "drwxr-xr-x  2 root root  4096 Jan 15 14:22 /etc",
        "-rw-r--r--  1 root root   512 2024-01-15 config.txt",
        "Python 3.10.12",
        "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    ]

    print("─" * 60)
    for s in samples:
        print(f"RAW  : {s}")
        print(f"NORM : {normalize(s)}")
        print()