"""
shell/network.py -- ifconfig, ip, hostname -I, netstat and ss from one description.

Cowrie answered each of these with a different invented network (a new MAC and
Docker address every session, 2014-era unix sockets, no PIDs), and a model
answered `ip a` differently again. Here the interface takes the address the
attacker connected to, and the listeners are the daemons in the process table.
"""
import ipaddress


def _eui64(mac: str) -> str:
    b = [int(x, 16) for x in mac.split(":")]
    b[0] ^= 2
    full = f"fe80::{b[0]:02x}{b[1]:02x}:{b[2]:02x}ff:fe{b[3]:02x}:{b[4]:02x}{b[5]:02x}"
    return str(ipaddress.ip_address(full))        # compressed, no leading zeros


def _net(ip: str, prefix: int):
    return ipaddress.ip_interface(f"{ip}/{prefix}")


def _bytes_human(n: int) -> str:
    for unit, div in (("GB", 10**9), ("MB", 10**6), ("KB", 10**3)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n} B"


def ifconfig(spec: dict, ip: str, counters: dict, argv) -> str:
    """net-tools 1.60 `ifconfig` / `ifconfig <iface>`; None for anything else."""
    names = [a for a in argv[1:] if not a.startswith("-")]
    if len(names) > 1 or any(a.startswith("-") and a != "-a" for a in argv[1:]):
        return None
    iface = spec["interface"]
    if names and names[0] not in (iface, "lo"):
        return f"{names[0]}: error fetching interface information: Device not found"
    nic = _net(ip, spec["prefix"])
    blocks = {}
    blocks[iface] = "\n".join([
        f"{iface}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500",
        f"        inet {ip}  netmask {nic.netmask}  broadcast {nic.network.broadcast_address}",
        f"        inet6 {_eui64(spec['mac'])}  prefixlen 64  scopeid 0x20<link>",
        f"        ether {spec['mac']}  txqueuelen 1000  (Ethernet)",
        f"        RX packets {counters['rx_packets']}  bytes {counters['rx_bytes']} "
        f"({_bytes_human(counters['rx_bytes'])})",
        "        RX errors 0  dropped 0  overruns 0  frame 0",
        f"        TX packets {counters['tx_packets']}  bytes {counters['tx_bytes']} "
        f"({_bytes_human(counters['tx_bytes'])})",
        "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0",
    ])
    lo = counters["lo"]
    blocks["lo"] = "\n".join([
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536",
        "        inet 127.0.0.1  netmask 255.0.0.0",
        "        inet6 ::1  prefixlen 128  scopeid 0x10<host>",
        "        loop  txqueuelen 1000  (Local Loopback)",
        f"        RX packets {lo}  bytes {lo * 96} ({_bytes_human(lo * 96)})",
        "        RX errors 0  dropped 0  overruns 0  frame 0",
        f"        TX packets {lo}  bytes {lo * 96} ({_bytes_human(lo * 96)})",
        "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0",
    ])
    if names:
        return blocks[names[0]]
    return blocks[iface] + "\n\n" + blocks["lo"]


def ip_command(spec: dict, ip: str, argv) -> str:
    """`ip a`, `ip addr`, `ip -4 a`, `ip link`, `ip route`, `ip r`; None otherwise."""
    args = [a for a in argv[1:]]
    only4 = "-4" in args
    args = [a for a in args if a not in ("-4", "-6", "-br", "-brief", "-c", "-color")]
    if "-6" in argv or "-br" in argv or "-brief" in argv or any(a.startswith("-") for a in args):
        return None
    iface, mac = spec["interface"], spec["mac"]
    nic = _net(ip, spec["prefix"])
    gateway = nic.network.network_address + 1
    verb = args[0] if args else ""
    if args[1:] and args[1] not in ("show", "ls", "list") and verb not in ("route", "r", "ro"):
        return None
    if verb in ("a", "addr", "address"):
        lo = ["1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000",
              "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
              "    inet 127.0.0.1/8 scope host lo",
              "       valid_lft forever preferred_lft forever"]
        if not only4:
            lo += ["    inet6 ::1/128 scope host ", "       valid_lft forever preferred_lft forever"]
        eth = [f"2: {iface}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000",
               f"    link/ether {mac} brd ff:ff:ff:ff:ff:ff",
               f"    inet {ip}/{spec['prefix']} brd {nic.network.broadcast_address} scope global dynamic {iface}",
               "       valid_lft 80921sec preferred_lft 80921sec"]
        if not only4:
            eth += [f"    inet6 {_eui64(mac)}/64 scope link ", "       valid_lft forever preferred_lft forever"]
        return "\n".join(lo + eth)
    if verb in ("l", "link"):
        return "\n".join([
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000",
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
            f"2: {iface}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000",
            f"    link/ether {mac} brd ff:ff:ff:ff:ff:ff"])
    if verb in ("r", "ro", "route") and len(args) <= 2 and (len(args) < 2 or args[1] in ("show", "ls", "list")):
        return "\n".join([
            f"default via {gateway} dev {iface} proto dhcp src {ip} metric 100 ",
            f"{nic.network} dev {iface} proto kernel scope link src {ip} ",
            f"{gateway} dev {iface} proto dhcp scope link src {ip} metric 100 "])
    return None


def hostname_command(name: str, ip: str, argv) -> str:
    args = argv[1:]
    if not args:
        return name
    if args == ["-I"]:
        return ip + " "
    if args == ["-i"]:
        return "127.0.1.1"
    if args in (["-s"], ["--short"]):
        return name.split(".")[0]
    if args in (["-f"], ["--fqdn"]):
        return name
    if args in (["-d"], ["--domain"]):
        return ""
    return None


def _socket_rows(spec: dict, ip: str, pids: dict, conn):
    """[(proto, local, port, state, comm, pid)] for every listener, then the live SSH link."""
    rows = []
    for l in spec["listeners"]:
        local = l["addr"].replace("{ip}", ip)
        pid = pids.get(l["process"])
        if pid is None:
            continue
        state = "UNCONN" if l["proto"].startswith("udp") else "LISTEN"
        rows.append((l["proto"], local, l["port"], state, l["comm"], pid, l.get("bound", "")))
    if conn:
        rows.append(("tcp", ip, 22, "ESTAB", "sshd", conn["pid"], "", conn["peer"]))
    return rows


def _flags(argv):
    flags = set()
    for a in argv[1:]:
        if a.startswith("--") or not a.startswith("-") or len(a) < 2:
            return None
        flags |= set(a[1:])
    return flags


def netstat(spec: dict, ip: str, pids: dict, conn, argv) -> str:
    flags = _flags(argv)
    if flags is None or flags - set("tulnpa4") or not flags & set("tu"):
        return None            # unix sockets and the rest are not modelled
    want = [p for p, f in (("tcp", "t"), ("udp", "u")) if f in flags]
    show_all = "a" in flags
    rows = [r for r in _socket_rows(spec, ip, pids, conn)
            if r[0].rstrip("6") in want
            and (show_all or (r[3] != "ESTAB" if "l" in flags else r[3] == "ESTAB"))]
    title = ("Active Internet connections (servers and established)" if show_all else
             "Active Internet connections (only servers)" if "l" in flags else
             "Active Internet connections (w/o servers)")
    head = "Proto Recv-Q Send-Q Local Address           Foreign Address         State       "
    head += "PID/Program name" if "p" in flags else ""
    out = [title, head.rstrip() if "p" not in flags else head]
    for r in rows:
        proto, local, port, state = r[0], r[1], r[2], r[3]
        loc = f"{local}:{port}" if ":" not in local else f":::{port}" if local == "::" else f"[{local}]:{port}"
        peer = r[7] if len(r) > 7 else ("0.0.0.0:*" if ":" not in local else ":::*")
        shown_state = "" if state == "UNCONN" else "ESTABLISHED" if state == "ESTAB" else state
        prog = (f"{r[5]}/{r[4]}" if state != "ESTAB" else f"{r[5]}/sshd: root@pts/0") if "p" in flags else ""
        out.append(f"{proto:<5} {0:>6} {0:>6} {loc:<23} {peer:<23} {shown_state:<11} {prog}".rstrip())
    return "\n".join(out)


def ss(spec: dict, ip: str, pids: dict, conn, argv) -> str:
    flags = _flags(argv)
    if flags is None or flags - set("tulnpa4") or not flags & set("tu"):
        return None
    want = [p for p, f in (("tcp", "t"), ("udp", "u")) if f in flags]
    show_all = "a" in flags
    rows = [r for r in _socket_rows(spec, ip, pids, conn) if r[0].rstrip("6") in want
            and (show_all or (r[3] != "ESTAB" if "l" in flags else r[3] == "ESTAB"))]
    both = len(want) == 2
    rows.sort(key=lambda r: (r[0].rstrip("6") != "udp", r[3] != "UNCONN"))   # udp first, as ss lists

    def local_cell(r):
        host = f"[{r[1]}]" if ":" in r[1] else r[1]
        host = "[::]" if r[1] == "::" else host
        if r[6]:
            host += f"%{r[6]}"
        return f"{host}:{r[2]}"

    def peer_cell(r):
        if len(r) > 7:
            return r[7]
        return "[::]:*" if r[1] == "::" else "0.0.0.0:*"

    cells = []
    for r in rows:
        send_q = 128 if r[4] == "sshd" else 4096 if r[3] == "LISTEN" else 0
        fd = 3 + (r[2] * 7 + r[5]) % 20          # differs per daemon, stable per socket
        proc = f'users:(("{r[4]}",pid={r[5]},fd={fd}))' if "p" in flags else ""
        cells.append(("udp" if r[0].startswith("udp") else "tcp", r[3], "0", str(send_q if r[3] == "LISTEN" else 0),
                      local_cell(r), peer_cell(r), proc))
    head = ("Netid", "State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port",
            "Process" if "p" in flags else "")
    table = [head] + cells
    if not both:
        table = [c[1:] for c in table]
    w = [max(len(c[i]) for c in table) for i in range(len(table[0]) - 1)]

    def fmt(c):
        n = len(c) - 3                                # columns before the two addresses
        left = "  ".join(f"{c[i]:<{w[i]}}" for i in range(n))
        return (f"{left}  {c[n]:>{w[n]}}  {c[n + 1]:>{w[n + 1]}}  {c[n + 2]}").rstrip()
    return "\n".join(fmt(c) for c in table)
