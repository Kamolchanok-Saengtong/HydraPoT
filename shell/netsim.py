"""
shell/netsim.py -- ping, traceroute and nmap, printed the way Linux prints them, for THIS machine.

The old static handlers were written for no particular box: `ping` stopped after 4 packets
and printed macOS's "Request timeout", `ping localhost` answered from a random public
address, `nmap localhost` reported ports 21/80/443 open on a machine that listens only on
22, and traceroute's hops were named hop-N.isp.net. Nothing here touches the network:
a name resolves to a stable made-up public address, and the machine's own address, gateway
and listening ports come from the same config the rest of the honeypot reads.

Formats are iputils-ping 20190709, traceroute 2.1.0 and Nmap 7.80 (Ubuntu 20.04's).
"""
import hashlib
import ipaddress
import math
import random
import re
from datetime import datetime, timezone

_NO_SUCH_TLD = (".invalid", ".test", ".example")


def _rng(*parts) -> random.Random:
    return random.Random(hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest())


def resolve(name: str, hostname: str):
    """(ip, shown_name | None), or None when the name would not resolve.

    Never does a real lookup: an attacker-chosen name would otherwise make this machine
    query an attacker-chosen DNS server."""
    try:
        ipaddress.ip_address(name)
        return name, None
    except ValueError:
        pass
    n = name.lower().rstrip(".")
    if n in ("localhost", "ip6-localhost", "ip6-loopback") or n.endswith(".localhost"):
        return "127.0.0.1", "localhost"
    if n == hostname.lower():
        return "127.0.1.1", hostname
    if "." not in n or n.endswith(_NO_SUCH_TLD):
        return None
    return _public(_rng("host", n)), name


def _public(r: random.Random) -> str:
    while True:
        ip = ipaddress.IPv4Address(r.getrandbits(32))
        if ip.is_global and not ip.is_multicast and not ip.is_reserved and ip.packed[0] < 224:
            return str(ip)


def gateway(local_ip: str, prefix: int = 24) -> str:
    return str(ipaddress.ip_interface(f"{local_ip}/{prefix}").network.network_address + 1)


# ── ping ───────────────────────────────────────────────────────────────────

def _ms(t: float) -> str:
    """iputils' time= precision: whole ms from 100, 1 decimal from 10, 2 from 1, else 3."""
    return f"{t:.0f}" if t >= 100 else f"{t:.1f}" if t >= 10 else f"{t:.2f}" if t >= 1 else f"{t:.3f}"


class Ping:
    def __init__(self, ip, shown, size=56, ttl=None, numeric=False, quiet=False, seed=""):
        self.ip, self.shown, self.size, self.quiet = ip, (None if numeric else shown), size, quiet
        addr = ipaddress.ip_address(ip)
        self.rng = _rng("ping", ip, seed)
        if addr.is_loopback:
            self.base, self.ttl = 0.045, 64
        elif addr.is_private:
            self.base, self.ttl = 0.45 + self.rng.random() * 0.5, 64
        else:
            self.base = 8 + _rng("rtt", ip).random() * 38
            self.ttl = _rng("ttl", ip).choice((117, 118, 54, 56, 52, 58, 235))
        if ttl:
            self.ttl = ttl
        self.times, self.sent = [], 0

    def header(self) -> str:
        return f"PING {self.shown or self.ip} ({self.ip}) {self.size}({self.size + 28}) bytes of data."

    def reply(self, seq: int) -> str:
        self.sent += 1
        jitter = self.rng.gauss(0, self.base * 0.04)
        t = max(self.base + jitter + (self.base * 0.35 if seq == 1 else 0), 0.005)
        self.times.append(t)
        who = f"{self.shown} ({self.ip})" if self.shown else self.ip
        if self.quiet:
            return ""
        return f"{self.size + 8} bytes from {who}: icmp_seq={seq} ttl={self.ttl} time={_ms(t)} ms"

    def summary(self, elapsed_ms: int) -> str:
        n, got = self.sent, len(self.times)
        lines = ["", f"--- {self.shown or self.ip} ping statistics ---",
                 f"{n} packets transmitted, {got} received, {round(100 * (n - got) / n) if n else 0}% "
                 f"packet loss, time {elapsed_ms}ms"]
        if got:
            avg = sum(self.times) / got
            mdev = math.sqrt(sum((x - avg) ** 2 for x in self.times) / got)
            lines.append(f"rtt min/avg/max/mdev = {min(self.times):.3f}/{avg:.3f}/"
                         f"{max(self.times):.3f}/{mdev:.3f} ms")
        return "\n".join(lines)


def parse_ping(argv, hostname: str):
    """-> ({ping, count, interval} | None, error_text | None). None, None = not ours."""
    count = interval = None
    size, ttl, numeric, quiet, target = 56, None, False, False, None
    args, i = argv[1:], 0
    while i < len(args):
        a = args[i]
        if a in ("-c", "-i", "-s", "-t", "-W", "-w", "-I", "-m", "-p", "-Q", "-S"):
            if i + 1 >= len(args):
                return None, f"ping: option requires an argument -- '{a[1]}'"
            v = args[i + 1]
            i += 2
            try:
                if a == "-c": count = int(v)
                elif a == "-i": interval = float(v)
                elif a == "-s": size = int(v)
                elif a == "-t": ttl = int(v)
            except ValueError:
                return None, f"ping: invalid argument: '{v}'"
            continue
        if a.startswith("-") and len(a) > 1:
            if not set(a[1:]) <= set("nqAaDOvdUbf46R"):
                return None, None
            numeric |= "n" in a
            quiet |= "q" in a
        else:
            target = a
        i += 1
    if target is None:
        return None, "ping: usage error: Destination address required"
    res = resolve(target, hostname)
    if res is None:
        return None, f"ping: {target}: Name or service not known"
    ip, shown = res
    return {"ping": Ping(ip, shown or None, size, ttl, numeric, quiet, seed=target),
            "count": count, "interval": max(interval or 1.0, 0.2)}, None


# ── traceroute ─────────────────────────────────────────────────────────────

def traceroute_lines(argv, hostname: str, local_ip: str, prefix: int = 24):
    """(lines, error). Probes are not sent: the path is made up, stable per destination."""
    numeric, maxhops, target, i, args = False, 30, None, 0, argv[1:]
    while i < len(args):
        a = args[i]
        if a == "-m" and i + 1 < len(args):
            maxhops = int(args[i + 1]) if args[i + 1].isdigit() else 30
            i += 2
            continue
        if a in ("-q", "-w", "-s", "-p", "-f", "-g", "-i", "-t", "-z", "-N") and i + 1 < len(args):
            i += 2
            continue
        if a == "-n":
            numeric = True
        elif a.startswith("-"):
            pass
        else:
            target = a
        i += 1
    if target is None:
        return [], "Usage:\n  traceroute [ -46dFITnreAUDV ] [ -f first_ttl ] [ -g gate,... ] [ -i device ] [ -m max_ttl ]\n"\
                   "[ -N squeries ] [ -p port ] [ -t tos ] [ -l flow_label ] [ -w MAX,HERE,NEAR ] [ -q nqueries ]\n"\
                   "[ -s src_addr ] [ -z sendwait ] [ --fwmark=num ] host [ packetlen ]"
    res = resolve(target, hostname)
    if res is None:
        return [], f"{target}: Name or service not known\nCannot handle \"host\" cmdline arg `{target}' on position 1 (argc 1)"
    ip, shown = res
    addr = ipaddress.ip_address(ip)
    name = (shown or ip)
    rng = _rng("trace", ip)
    lines = [f"traceroute to {name} ({ip}), {maxhops} hops max, 60 byte packets"]

    def probes(base):
        return "  ".join(f"{max(base + rng.gauss(0, base * 0.06), 0.02):.3f} ms" for _ in range(3))
    if addr.is_loopback:
        return lines + [f" 1  {'localhost' if not numeric else ip} ({ip})  {probes(0.04)}"], None
    gw = gateway(local_ip, prefix)
    if addr.is_private:
        if ip == gw:
            return lines + [f" 1  _gateway ({gw})  {probes(0.5)}"], None
        return lines + [f" 1  _gateway ({gw})  {probes(0.5)}", f" 2  {ip} ({ip})  {probes(1.1)}"], None
    hops = rng.randint(6, 11)
    total = 8 + _rng("rtt", ip).random() * 38
    for h in range(1, hops):
        if h == 1:
            lines.append(f" 1  _gateway ({gw})  {probes(0.5)}" if not numeric else f" 1  {gw}  {probes(0.5)}")
            continue
        if rng.random() < 0.08:
            lines.append(f"{h:>2}  * * *")
            continue
        hop = _public(rng)
        lines.append(f"{h:>2}  {hop} ({hop})  {probes(0.8 + total * (h / hops) * 0.9)}" if not numeric
                     else f"{h:>2}  {hop}  {probes(0.8 + total * (h / hops) * 0.9)}")
    lines.append(f"{hops:>2}  {name} ({ip})  {probes(total)}" if not numeric else f"{hops:>2}  {ip}  {probes(total)}")
    return lines, None


# ── nmap ───────────────────────────────────────────────────────────────────

_SERVICES = {22: "ssh", 80: "http", 443: "https", 21: "ftp", 25: "smtp", 53: "domain", 110: "pop3",
             143: "imap", 3306: "mysql", 5432: "postgresql", 8080: "http-proxy", 3389: "ms-wbt-server",
             23: "telnet", 445: "microsoft-ds", 139: "netbios-ssn", 6379: "redis", 27017: "mongod"}
_VALUE_FLAGS = {"-p", "-oA", "-oN", "-oG", "-oX", "--top-ports", "-e", "--source-port", "-g", "-iL",
                "-S", "--max-retries", "--host-timeout", "-T", "--script", "-D"}
_OUIS = (("52:54:00", "QEMU virtual NIC"), ("00:50:56", "VMware"), ("B8:27:EB", "Raspberry Pi Foundation"),
         ("00:0C:29", "VMware"), ("DC:A6:32", "Raspberry Pi Trading"), ("3C:97:0E", "Intel Corporate"))


def _port_set(spec: str):
    ports = set()
    for part in spec.split(","):
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part.strip())
        if m:
            lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
            ports.update(range(lo, min(hi, 65535) + 1))
    return ports


def _ssh_banner(ssh_version: str) -> str:
    return re.sub(r"Ubuntu-", "Ubuntu ", (ssh_version or "OpenSSH_8.2p1").replace("_", " "))


def nmap_lines(argv, ctx: dict):
    """(lines, scan_seconds, error). ctx: hostname, local_ip, listeners [(port)], ssh_version, now."""
    flags, target, ports_spec, i, args = [], None, None, 0, argv[1:]
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            flags.append(a)
            if a == "-p" and i + 1 < len(args):
                ports_spec = args[i + 1]; i += 1
            elif a.startswith("-p") and len(a) > 2:
                ports_spec = a[2:]
            elif a in _VALUE_FLAGS:
                i += 1
        elif target is None:
            target = a
        i += 1
    if target is None:
        return [], 0, "Nmap 7.80 ( https://nmap.org )\nUsage: nmap [Scan Type(s)] [Options] {target specification}\nTARGET SPECIFICATION:\n  Can pass hostnames, IP addresses, networks, etc.\nSee the output of nmap -h for a summary of options."
    version_scan = "-sV" in flags or "-A" in flags
    ping_only = "-sn" in flags
    now = ctx["now"].strftime("%Y-%m-%d %H:%M %Z").strip()
    out = [f"Starting Nmap 7.80 ( https://nmap.org ) at {now}"]
    local = target.lower() in ("localhost", "127.0.0.1", ctx["hostname"].lower(), ctx["local_ip"], "::1")
    rng = _rng("nmap", target)

    if "/" in target:                                   # a network: which hosts answer
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return [], 0, f"Failed to resolve \"{target}\".\nWARNING: No targets were specified, so 0 hosts scanned.\nNmap done: 0 IP addresses (0 hosts up) scanned in 0.03 seconds"
        base = list(net.hosts())
        picks = sorted(rng.sample(range(len(base)), min(len(base), 2 + rng.randint(0, 3)))) if base else []
        for k in picks:
            h = base[k]
            oui, vendor = rng.choice(_OUIS)
            out += [f"Nmap scan report for {h}", f"Host is up ({rng.uniform(0.0004, 0.004):.4f}s latency).",
                    f"MAC Address: {oui}:{rng.randint(0, 255):02X}:{rng.randint(0, 255):02X}:{rng.randint(0, 255):02X} ({vendor})"]
        secs = round(rng.uniform(1.6, 3.4), 2)
        out += ["", f"Nmap done: {net.num_addresses} IP addresses ({len(picks)} hosts up) scanned in {secs} seconds"]
        return out, secs, None

    res = resolve(target, ctx["hostname"])
    if res is None:
        return [], 0, f"Failed to resolve \"{target}\".\nWARNING: No targets were specified, so 0 hosts scanned.\nNmap done: 0 IP addresses (0 hosts up) scanned in 0.05 seconds"
    ip, shown = res
    if ip == "127.0.0.1" and not shown:
        shown = "localhost"                          # nmap reverse-resolves loopback
    label = f"{shown} ({ip})" if shown else ip
    if local:
        open_ports = {p: _SERVICES.get(p, "unknown") for p in ctx["listeners"]}
        latency = f"{rng.uniform(0.00006, 0.00018):.6f}"
        secs = round(rng.uniform(5.8, 8.9) if version_scan else rng.uniform(0.04, 0.12), 2)
    else:
        pool = [22, 80, 443] + ([3306] if rng.random() < 0.15 else []) + ([8080] if rng.random() < 0.2 else [])
        open_ports = {p: _SERVICES[p] for p in rng.sample(pool, rng.randint(1, min(3, len(pool))))}
        latency = f"{rng.uniform(0.012, 0.06):.4f}"
        secs = round(rng.uniform(3.2, 9.5) + (4 if version_scan else 0), 2)
    out.append(f"Nmap scan report for {label}")
    out.append(f"Host is up ({latency}s latency).")
    if local and target.lower() == "localhost":
        out.append("Other addresses for localhost (not scanned): ::1")
    if not ping_only:
        scanned = (_port_set(ports_spec) if ports_spec and ports_spec != "-" else
                   set(range(1, 65536)) if ports_spec == "-" else set(range(1, 1001)))
        if not ports_spec:
            scanned |= set(open_ports)
        hits = {p: s for p, s in open_ports.items() if p in scanned}
        state = "closed" if local else "filtered"
        if not hits and len(scanned) <= 25 and ports_spec:
            out.append(f"All {len(scanned)} scanned ports on {label} are closed")
        elif not hits:
            out.append(f"All {len(scanned)} scanned ports on {label} are {state}")
        else:
            few = len(scanned) <= 25
            if not few:
                out.append(f"Not shown: {len(scanned) - len(hits)} {state} ports")
            rows = []
            for p in sorted(set(hits) | (scanned if few else set())):
                is_open = p in hits
                ver = ""
                if version_scan and is_open:
                    ver = (_ssh_banner(ctx["ssh_version"]) + " (Ubuntu Linux; protocol 2.0)" if p == 22 else
                           "nginx 1.18.0 (Ubuntu)" if p in (80, 443) else "")
                rows.append((f"{p}/tcp", "open" if is_open else state, _SERVICES.get(p, "unknown"), ver))
            pw, sw = max([len(r[0]) for r in rows] + [4]), max([len(r[1]) for r in rows] + [5])
            vw = max([len(r[2]) for r in rows] + [7])
            out.append(f"{'PORT':<{pw}} {'STATE':<{sw}} {'SERVICE':<{vw}}" + (" VERSION" if version_scan else ""))
            for port, st, svc, ver in rows:
                out.append((f"{port:<{pw}} {st:<{sw}} {svc:<{vw}}" + (f" {ver}" if version_scan else "")).rstrip())
        if version_scan and hits:
            out.append("Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel")
    if not local and ip.startswith(("10.", "192.168.", "172.")) and not ping_only:
        oui, vendor = rng.choice(_OUIS)
        out.append(f"MAC Address: {oui}:{rng.randint(0, 255):02X}:{rng.randint(0, 255):02X}:{rng.randint(0, 255):02X} ({vendor})")
    if version_scan and open_ports and not ping_only:
        out += ["", "Service detection performed. Please report any incorrect results at https://nmap.org/submit/ ."]
    else:
        out.append("")
    out.append(f"Nmap done: 1 IP address (1 host up) scanned in {secs:.2f} seconds")
    return out, secs, None
