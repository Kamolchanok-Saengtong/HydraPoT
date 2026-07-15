"""
static_handler.py — fully fake outputs for commands that would hang or
behave badly in Cowrie. Streams line-by-line via a write_fn callback
so the asyncssh frontend can deliver output to the attacker as it's
generated. Every function returns the full string for logging.

Currently handles:
  - nmap        finite scan, drips lines
  - ping        defaults to 4 pings, respects -c flag
  - traceroute  fake hop list, drips lines
  - top         one snapshot, exits (so it doesn't hang forever)
  - watch       runs the wrapped cmd ONCE then exits
  - tail -f     fakes a few log lines then exits
  - vim/nano    polite "not installed" error
  - less/more   passes through (or noop) — see is_static / dispatch_static
"""

import re
import time
import random
from typing import Callable, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Public registry — main.py uses this to decide if a command goes here.
# ─────────────────────────────────────────────────────────────────────────────
STATIC_CMDS = (
    "nmap", "ping", "traceroute", "tracepath",
    "top", "htop", "watch",
    "tail",          # only intercepted if `-f` flag present (see dispatch_static)
    "vim", "vi", "nano", "emacs",
    "less", "more",
)


def is_static(cmd: str) -> bool:
    """True if main.py should route this command to dispatch_static()."""
    parts = cmd.strip().split()
    if not parts:
        return False
    base = parts[0]
    if base not in STATIC_CMDS:
        return False
    # tail is only static when used with -f (follow), otherwise let cowrie do it
    if base == "tail" and "-f" not in parts:
        return False
    return True


def dispatch_static(cmd: str, write_fn: Callable[[str], None]) -> str:
    """
    Single entry point — main.py just calls this for any static cmd.
    Returns the full output string for logging.
    """
    parts = cmd.strip().split()
    base  = parts[0]

    if base == "nmap":                          return run_nmap(cmd, write_fn)
    if base == "ping":                          return run_ping(cmd, write_fn)
    if base in ("traceroute", "tracepath"):     return run_traceroute(cmd, write_fn)
    if base in ("top", "htop"):                 return run_top(cmd, write_fn)
    if base == "watch":                         return run_watch(cmd, write_fn)
    if base == "tail":                          return run_tail_follow(cmd, write_fn)
    if base in ("vim", "vi", "nano", "emacs"):  return run_editor(cmd, write_fn)
    if base in ("less", "more"):                return run_pager(cmd, write_fn)

    # shouldn't reach here, but be safe
    msg = f"bash: {base}: command not handled"
    write_fn(msg + "\r\n")
    return msg


def _extract_target(parts: list[str], value_flags: set[str], default: str) -> str:
    """
    First non-flag token that isn't itself the VALUE of a preceding flag.
    e.g. for ping/traceroute/nmap, "-c 3 8.8.8.8" must not pick "3" as the
    target just because it doesn't start with '-' — it's -c's argument.
    parts[0] (the binary name itself) is expected to already be excluded.
    """
    skip_next = False
    for p in parts:
        if skip_next:
            skip_next = False
            continue
        if p in value_flags:
            skip_next = True
            continue
        if p.startswith('-'):
            continue
        return p
    return default


# ─────────────────────────────────────────────────────────────────────────────
# nmap
# ─────────────────────────────────────────────────────────────────────────────
# Flags that take a separate following argument (not booleans like -sV/-sU)
_NMAP_VALUE_FLAGS = {'-p', '-oA', '-oN', '-oG', '-oX', '--top-ports', '-e', '--source-port', '-g'}


def parse_nmap_cmd(cmd: str) -> dict:
    parts  = cmd.split()
    flags  = [p for p in parts if p.startswith('-')]
    target = _extract_target(parts[1:], _NMAP_VALUE_FLAGS, "192.168.1.1")
    return {"flags": flags, "target": target}


def generate_nmap_output(cmd: str) -> list[str]:
    info   = parse_nmap_cmd(cmd)
    target = info["target"]
    flags  = info["flags"]

    if "-sV" in flags or "--version" in flags:
        ports = [
            "22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)",
            "80/tcp   open  http     Apache httpd 2.4.6",
            "443/tcp  open  https    OpenSSL/1.0.2k",
            "21/tcp   open  ftp      vsftpd 3.0.3",
            "3306/tcp open  mysql    MySQL 5.7.34",
        ]
    elif "-sU" in flags:
        ports = [
            "53/udp   open  domain",
            "123/udp  open  ntp",
            "161/udp  open  snmp",
        ]
    elif "-p" in flags:
        ports = ["22/tcp  open  ssh", "80/tcp  open  http"]
    else:
        ports = [
            "22/tcp  open  ssh",
            "80/tcp  open  http",
            "21/tcp  open  ftp",
            "443/tcp open  https",
        ]

    latency   = round(random.uniform(0.3, 2.5), 2)
    scan_time = round(random.uniform(2.0, 8.0), 2)
    mac = "DE:AD:BE:EF:{:02X}:{:02X}".format(
        random.randint(0, 255), random.randint(0, 255))

    lines = [
        "Starting Nmap 7.80 ( https://nmap.org )",
        f"Nmap scan report for {target}",
        f"Host is up ({latency}s latency).",
    ]
    if "-sV" in flags:
        lines.append("Not shown: 995 closed ports")
        lines.append("PORT     STATE SERVICE VERSION")
    else:
        lines.append("Not shown: 996 closed ports")
        lines.append("PORT    STATE SERVICE")
    lines.extend(ports)
    lines.append(f"MAC Address: {mac} (Unknown)")
    lines.append("")
    lines.append(f"Nmap done: 1 IP address (1 host up) scanned in {scan_time} seconds")
    return lines


def run_nmap(cmd: str, write_fn: Callable[[str], None] = print,
             delay: float = 0.4) -> str:
    lines = generate_nmap_output(cmd)
    full  = ""
    for line in lines:
        write_fn(line + "\r\n")
        full += line + "\n"
        time.sleep(delay)
    return full.strip()


# ─────────────────────────────────────────────────────────────────────────────
# ping
# ─────────────────────────────────────────────────────────────────────────────
def _fake_ip_for(target: str) -> str:
    """Deterministic-ish fake IP for hostnames so a target stays consistent."""
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        return target
    # cheap hash → IP in 8.x.x.x range
    h = abs(hash(target)) % (256 * 256 * 254 + 1)
    return f"8.{(h >> 16) & 0xff}.{(h >> 8) & 0xff}.{(h & 0xff) or 1}"


_PING_VALUE_FLAGS = {'-c', '-i', '-s', '-t', '-W', '-w', '-p', '-l'}


def run_ping(cmd: str, write_fn: Callable[[str], None] = print,
             count: int = 4, delay: float = 1.0) -> str:
    parts  = cmd.split()
    target = _extract_target(parts[1:], _PING_VALUE_FLAGS, "8.8.8.8")
    if '-c' in parts:
        try:    count = max(1, min(20, int(parts[parts.index('-c') + 1])))
        except (ValueError, IndexError): pass

    fake_ip = _fake_ip_for(target)
    full    = ""

    def emit(s):
        nonlocal full
        write_fn(s + "\r\n")
        full += s + "\n"

    emit(f"PING {target} ({fake_ip}) 56(84) bytes of data.")

    received, times = 0, []
    for seq in range(1, count + 1):
        time.sleep(delay)
        if random.random() < 0.95:
            t = round(random.uniform(8.0, 35.0), 1)
            emit(f"64 bytes from {fake_ip}: icmp_seq={seq} ttl=117 time={t} ms")
            times.append(t); received += 1
        else:
            emit(f"Request timeout for icmp_seq {seq}")

    loss = round((count - received) / count * 100, 1)
    emit("")
    emit(f"--- {target} ping statistics ---")
    emit(f"{count} packets transmitted, {received} received, {loss}% packet loss, time {count*1000}ms")
    if times:
        mn, mx, avg = min(times), max(times), sum(times)/len(times)
        mdev = round(random.uniform(0.5, 4.0), 3)
        emit(f"rtt min/avg/max/mdev = {mn}/{round(avg,1)}/{mx}/{mdev} ms")

    return full.strip()


# ─────────────────────────────────────────────────────────────────────────────
# traceroute
# ─────────────────────────────────────────────────────────────────────────────
_TRACEROUTE_VALUE_FLAGS = {'-m', '-w', '-q', '-p', '-s', '-i', '-f', '-g', '-z'}


def run_traceroute(cmd: str, write_fn: Callable[[str], None] = print,
                   max_hops: int = 12, delay: float = 0.4) -> str:
    parts  = cmd.split()
    target = _extract_target(parts[1:], _TRACEROUTE_VALUE_FLAGS, "8.8.8.8")
    fake_ip = _fake_ip_for(target)
    full = ""

    def emit(s):
        nonlocal full
        write_fn(s + "\r\n")
        full += s + "\n"

    emit(f"traceroute to {target} ({fake_ip}), 30 hops max, 60 byte packets")

    # generate a believable path
    hops = max(4, min(max_hops, random.randint(6, 11)))
    last_ip = "192.168.1.1"
    for i in range(1, hops + 1):
        time.sleep(delay)
        if i == hops:
            ip = fake_ip
            host = target
        else:
            ip = f"{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            host = f"hop-{i}.isp.net"
        t1 = round(random.uniform(1.0, 50.0), 3)
        t2 = round(t1 + random.uniform(-1, 1), 3)
        t3 = round(t1 + random.uniform(-1, 1), 3)
        # 5% chance of a starred hop
        if random.random() < 0.05:
            emit(f"{i:>2}  * * *")
        else:
            emit(f"{i:>2}  {host} ({ip})  {t1} ms  {t2} ms  {t3} ms")
        last_ip = ip

    return full.strip()


# ─────────────────────────────────────────────────────────────────────────────
# top / htop — one snapshot then exit
# ─────────────────────────────────────────────────────────────────────────────
_FAKE_PROCS = [
    ("root",    1,    0.0, 0.1, "/sbin/init"),
    ("root",    2,    0.0, 0.0, "[kthreadd]"),
    ("root",   12,    0.1, 0.0, "[ksoftirqd/0]"),
    ("root",  421,    0.0, 0.2, "/usr/sbin/sshd -D"),
    ("root",  503,    0.5, 1.2, "/usr/sbin/apache2 -k start"),
    ("www-data", 612, 0.2, 0.8, "/usr/sbin/apache2 -k start"),
    ("mysql", 718,    1.4, 8.6, "/usr/sbin/mysqld"),
    ("root",  892,    0.0, 0.3, "/usr/sbin/cron -f"),
    ("root", 1024,    0.1, 0.4, "-bash"),
    ("root", 1138,    0.0, 0.2, "top"),
]


# ─────────────────────────────────────────────────────────────────────────────
# top / htop — one realistic snapshot then exit
# ─────────────────────────────────────────────────────────────────────────────

# Modern Ubuntu 22.04 process set. Mix of kernel threads (RES=0),
# system daemons, user daemons, and the attacker's own session.
# Format: (user, base_pid_offset, cmd, is_kernel_thread)
_PROC_TEMPLATE = [
    # PID 1 always init/systemd
    ("root",      0,    "/sbin/init splash",                    False),
    # kernel threads (RES=0, in [brackets])
    ("root",      1,    "[kthreadd]",                           True),
    ("root",      2,    "[rcu_gp]",                             True),
    ("root",      3,    "[rcu_par_gp]",                         True),
    ("root",      4,    "[slub_flushwq]",                       True),
    ("root",      9,    "[ksoftirqd/0]",                        True),
    ("root",     11,    "[migration/0]",                        True),
    ("root",     12,    "[idle_inject/0]",                      True),
    ("root",     13,    "[cpuhp/0]",                            True),
    ("root",     14,    "[cpuhp/1]",                            True),
    # core systemd daemons
    ("root",    180,    "/lib/systemd/systemd-journald",        False),
    ("root",    210,    "/lib/systemd/systemd-udevd",           False),
    ("systemd-resolve", 256, "/lib/systemd/systemd-resolved",   False),
    ("systemd-network", 258, "/lib/systemd/systemd-networkd",   False),
    ("messagebus",      295, "@dbus-daemon --system --address=systemd:", False),
    ("root",    310,    "/usr/lib/snapd/snapd",                 False),
    ("root",    344,    "/usr/sbin/cron -f -P",                 False),
    ("root",    389,    "/usr/sbin/rsyslogd -n -iNONE",         False),
    ("root",    421,    "/usr/sbin/sshd -D -o AuthorizedKeysCommand=/usr/share/ec2-instance-connect/eic_run_authorized_keys %u %f", False),
    ("root",    458,    "/usr/sbin/atd -f",                     False),
    ("root",    503,    "/usr/sbin/apache2 -k start",           False),
    ("www-data",612,    "/usr/sbin/apache2 -k start",           False),
    ("www-data",614,    "/usr/sbin/apache2 -k start",           False),
    ("www-data",615,    "/usr/sbin/apache2 -k start",           False),
    ("mysql",   718,    "/usr/sbin/mysqld",                     False),
    ("root",    881,    "/usr/lib/postfix/sbin/master -w",      False),
    ("postfix", 884,    "qmgr -l -t unix -u",                   False),
    # the attacker's session
    ("root",    9821,   "sshd: root@pts/0",                     False),
    ("root",    9842,   "-bash",                                False),
    ("root",    9931,   "top",                                  False),
]


def _fmt_kib(n: int) -> str:
    """Format an integer KiB value the way top does (with optional g/m suffix)."""
    if n >= 10_000_000: return f"{n/1024/1024:.1f}g"
    if n >=  1_000_000: return f"{n/1024:.0f}m"
    return f"{n}"


def _gen_top_state(seed_offset: int = 0) -> dict:
    """Generate one consistent system state snapshot (load, mem, uptime)."""
    # uptime — cap years at 1 to look plausible
    days  = random.randint(7, 380)
    hh    = random.randint(0, 23)
    mm    = random.randint(0, 59)
    users = random.randint(1, 4)

    # load avg — spiky, not flat
    l1  = round(random.uniform(0.05, 2.5), 2)
    l5  = round(l1 * random.uniform(0.4, 1.4), 2)
    l15 = round(l5 * random.uniform(0.4, 1.4), 2)

    # CPU breakdown (must sum to ~100)
    us = round(random.uniform(0.5, 8.0), 1)
    sy = round(random.uniform(0.2, 3.0), 1)
    ni = 0.0
    wa = round(random.uniform(0.0, 0.8), 1)
    hi = round(random.uniform(0.0, 0.2), 1)
    si = round(random.uniform(0.0, 0.5), 1)
    st = 0.0
    id_ = round(max(0.0, 100 - us - sy - ni - wa - hi - si - st), 1)

    # memory (MiB) — total 8G machine
    total_mb     = 7976.0
    used_mb      = round(random.uniform(800.0, 3500.0), 1)
    buffcache_mb = round(random.uniform(800.0, 2500.0), 1)
    free_mb      = round(total_mb - used_mb - buffcache_mb, 1)
    avail_mb     = round(free_mb + buffcache_mb * 0.7, 1)

    return dict(
        days=days, hh=hh, mm=mm, users=users,
        l1=l1, l5=l5, l15=l15,
        us=us, sy=sy, ni=ni, id_=id_, wa=wa, hi=hi, si=si, st=st,
        total_mb=total_mb, used_mb=used_mb, free_mb=free_mb,
        buffcache_mb=buffcache_mb, avail_mb=avail_mb,
    )


def _gen_proc_row(user: str, pid: int, cmd: str, is_kernel: bool) -> str:
    """Render one process row with realistic memory/CPU figures."""
    if is_kernel:
        # kernel threads have no userspace memory
        virt, res, shr = 0, 0, 0
        cpu = round(random.uniform(0.0, 0.1), 1) if random.random() < 0.1 else 0.0
        mem = 0.0
        state = random.choice(("S", "I"))
        # cumulative CPU time for long-lived kernel thread
        time_h = random.randint(0, 8)
        time_m = random.randint(0, 59)
        time_s = random.randint(0, 59)
        time_cs = random.randint(0, 99)
        t_str = f"{time_h}:{time_m:02d}:{time_s:02d}.{time_cs:02d}" if time_h else f"{time_m}:{time_s:02d}.{time_cs:02d}"
    else:
        # realistic page-aligned-ish memory values in KiB
        virt = random.choice([
            random.randint(8_000,    50_000),       # tiny daemon
            random.randint(50_000,   300_000),      # medium daemon
            random.randint(300_000, 1_500_000),     # large daemon (mysql, apache)
        ])
        res = int(virt * random.uniform(0.05, 0.35))
        shr = int(res  * random.uniform(0.10, 0.55))
        cpu = round(random.uniform(0.0, 1.5), 1) if random.random() < 0.3 else 0.0
        mem = round(res / 1024 / 76.0, 1)            # rough %MEM on 8GB
        state = random.choice(("S", "S", "S", "S", "R"))   # mostly sleeping
        # daemon CPU time depends on uptime — pick something realistic
        time_h = random.choice([0, 0, 0, 0, 1, 2, 5, 12, 38])
        time_m = random.randint(0, 59)
        time_s = random.randint(0, 59)
        time_cs = random.randint(0, 99)
        if time_h:
            t_str = f"{time_h}:{time_m:02d}:{time_s:02d}"
        else:
            t_str = f"{time_m}:{time_s:02d}.{time_cs:02d}"

    pr  = "rt" if is_kernel and random.random() < 0.2 else "20"
    ni  = "0" if pr == "20" else "-"

    return (f"{pid:>7} {user:<10} {pr:>3} {ni:>3} "
            f"{_fmt_kib(virt):>8} {_fmt_kib(res):>7} {_fmt_kib(shr):>7} "
            f"{state} {cpu:>5.1f} {mem:>5.1f} {t_str:>9} {cmd}")


def run_top(cmd: str, write_fn: Callable[[str], None] = print,
            delay: float = 0.0) -> str:
    full = ""
    def emit(s):
        nonlocal full
        write_fn(s + "\r\n")
        full += s + "\n"

    s = _gen_top_state()
    cur = time.strftime("%H:%M:%S")

    # totals — make them feel real
    n_procs = 142 + random.randint(-20, 40)
    n_run   = random.randint(1, 4)
    n_zomb  = 0 if random.random() < 0.95 else random.randint(1, 2)
    n_stop  = 0
    n_sleep = n_procs - n_run - n_zomb - n_stop

    emit(f"top - {cur} up {s['days']} days, {s['hh']:>2}:{s['mm']:02d},  "
         f"{s['users']} users,  load average: {s['l1']}, {s['l5']}, {s['l15']}")
    emit(f"Tasks: {n_procs:>3} total,   {n_run} running, {n_sleep} sleeping,   "
         f"{n_stop} stopped,   {n_zomb} zombie")
    emit(f"%Cpu(s): {s['us']:>4.1f} us, {s['sy']:>4.1f} sy, {s['ni']:>4.1f} ni, "
         f"{s['id_']:>4.1f} id, {s['wa']:>4.1f} wa, {s['hi']:>4.1f} hi, "
         f"{s['si']:>4.1f} si, {s['st']:>4.1f} st")
    emit(f"MiB Mem :  {s['total_mb']:>7.1f} total,  {s['free_mb']:>7.1f} free,  "
         f"{s['used_mb']:>7.1f} used,  {s['buffcache_mb']:>7.1f} buff/cache")
    emit(f"MiB Swap:   2048.0 total,   2048.0 free,      0.0 used. "
         f"{s['avail_mb']:>7.1f} avail Mem")
    emit("")
    emit("    PID USER         PR  NI    VIRT     RES     SHR S  %CPU  %MEM     TIME+ COMMAND")

    # produce ~20 visible rows from the template, with PIDs jittered around the offsets
    pid_jitter = random.randint(0, 200)
    rows = []
    for user, base, command, is_kt in _PROC_TEMPLATE:
        # PID 1 is always 1 (init), kernel threads are early small PIDs,
        # everything else gets some realistic jitter
        if base == 0:
            pid = 1
        elif is_kt:
            pid = base + random.randint(0, 3)
        else:
            pid = base + pid_jitter + random.randint(0, 30)
        rows.append((user, pid, command, is_kt))

    # sort by CPU desc-ish (top default) — fake it by just shuffling daemon order slightly
    # but always keep init at top
    head = [rows[0]]
    tail = rows[1:]
    random.shuffle(tail)
    for user, pid, command, is_kt in head + tail[:21]:   # ~22 rows total like real top
        emit(_gen_proc_row(user, pid, command, is_kt))
        if delay: time.sleep(delay)

    return full.strip()


# ─────────────────────────────────────────────────────────────────────────────
# watch — run the wrapped command once and exit
# ─────────────────────────────────────────────────────────────────────────────
def run_watch(cmd: str, write_fn: Callable[[str], None] = print) -> str:
    # `watch -n 2 ls` → strip flags, dispatch the inner cmd once
    parts = cmd.split()
    # drop "watch" + any -n N / -d / -t flags
    inner = []
    skip_next = False
    for p in parts[1:]:
        if skip_next:
            skip_next = False; continue
        if p in ("-n", "--interval"):
            skip_next = True;  continue
        if p.startswith("-"):
            continue
        inner.append(p)

    if not inner:
        msg = "watch: missing command"
        write_fn(msg + "\r\n")
        return msg

    inner_cmd = " ".join(inner)
    header = f"Every 2.0s: {inner_cmd}\r\n\r\n"
    write_fn(header)

    # if inner is itself a static cmd, recurse; otherwise emit a fake "command not found"
    if is_static(inner_cmd):
        return header + dispatch_static(inner_cmd, write_fn)
    msg = f"sh: {inner[0]}: command not found"
    write_fn(msg + "\r\n")
    return header + msg


# ─────────────────────────────────────────────────────────────────────────────
# tail -f — fake a few log lines then "exit"
# ─────────────────────────────────────────────────────────────────────────────
_FAKE_LOG_LINES = [
    "{ts} svr04 sshd[{pid}]: Accepted password for root from 198.51.100.{ip} port {port} ssh2",
    "{ts} svr04 systemd[1]: Started Session {sid} of user root.",
    "{ts} svr04 cron[{pid}]: ({user}) CMD ({cmd})",
    "{ts} svr04 kernel: [{up}] usb 1-2: new high-speed USB device number 4 using xhci_hcd",
    "{ts} svr04 sudo: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND={cmd}",
    "{ts} svr04 systemd[1]: session-{sid}.scope: Succeeded.",
]


def run_tail_follow(cmd: str, write_fn: Callable[[str], None] = print,
                    lines: int = 8, delay: float = 0.6) -> str:
    parts  = cmd.split()
    path   = next((p for p in parts[1:] if not p.startswith('-')), "/var/log/syslog")
    full   = ""
    def emit(s):
        nonlocal full
        write_fn(s + "\r\n")
        full += s + "\n"

    emit(f"==> {path} <==")
    for _ in range(lines):
        time.sleep(delay)
        tmpl = random.choice(_FAKE_LOG_LINES)
        emit(tmpl.format(
            ts   = time.strftime("%b %d %H:%M:%S"),
            pid  = random.randint(1000, 9999),
            ip   = random.randint(2, 254),
            port = random.randint(40000, 60000),
            sid  = random.randint(10, 999),
            up   = round(random.uniform(1000, 99999), 6),
            user = random.choice(("root", "www-data", "nobody")),
            cmd  = random.choice(("/usr/bin/apt update", "/usr/sbin/logrotate /etc/logrotate.conf",
                                  "/usr/bin/find /tmp -mtime +7 -delete")),
        ))
    return full.strip()


# ─────────────────────────────────────────────────────────────────────────────
# editors — refuse politely, like a stripped-down server
# ─────────────────────────────────────────────────────────────────────────────
def run_editor(cmd: str, write_fn: Callable[[str], None] = print) -> str:
    base = cmd.strip().split()[0]
    msg  = f"-bash: {base}: command not found"
    write_fn(msg + "\r\n")
    return msg


# ─────────────────────────────────────────────────────────────────────────────
# less / more — print the file once with no paging
# ─────────────────────────────────────────────────────────────────────────────
def run_pager(cmd: str, write_fn: Callable[[str], None] = print) -> str:
    parts = cmd.strip().split()
    if len(parts) < 2:
        msg = f"{parts[0]}: missing filename"
        write_fn(msg + "\r\n")
        return msg
    # we don't have a filesystem to read from here — just say it doesn't exist.
    # main.py / cowrie can override this if you wire it differently later.
    path = parts[1]
    msg  = f"{parts[0]}: {path}: No such file or directory"
    write_fn(msg + "\r\n")
    return msg