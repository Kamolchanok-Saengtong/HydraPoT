import re
import sys
import time
import random

def parse_nmap_cmd(cmd: str) -> dict:
    """Extract flags and target IP from nmap command."""
    parts = cmd.split()
    flags = [p for p in parts if p.startswith('-')]
    # find IP or hostname (not flags, not 'nmap')
    targets = [p for p in parts if not p.startswith('-') and p != 'nmap']
    target = targets[0] if targets else "192.168.1.1"
    return {"flags": flags, "target": target}

def generate_nmap_output(cmd: str) -> list[str]:
    """Generate realistic fake nmap output based on flags and target."""
    info = parse_nmap_cmd(cmd)
    target = info["target"]
    flags  = info["flags"]

    # fake open ports based on scan type
    if "-sV" in flags or "--version" in flags:
        ports = [
            f"22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)",
            f"80/tcp   open  http     Apache httpd 2.4.6",
            f"443/tcp  open  https    OpenSSL/1.0.2k",
            f"21/tcp   open  ftp      vsftpd 3.0.3",
            f"3306/tcp open  mysql    MySQL 5.7.34",
        ]
    elif "-sU" in flags:
        ports = [
            f"53/udp   open  domain",
            f"123/udp  open  ntp",
            f"161/udp  open  snmp",
        ]
    elif "-p" in flags:
        # specific port scan
        ports = [
            f"22/tcp  open  ssh",
            f"80/tcp  open  http",
        ]
    else:
        # default scan
        ports = [
            f"22/tcp  open  ssh",
            f"80/tcp  open  http",
            f"21/tcp  open  ftp",
            f"443/tcp open  https",
        ]

    # randomize latency to feel real
    latency = round(random.uniform(0.3, 2.5), 2)
    scan_time = round(random.uniform(2.0, 8.0), 2)
    mac = "DE:AD:BE:EF:{:02X}:{:02X}".format(random.randint(0,255), random.randint(0,255))

    lines = []
    lines.append(f"Starting Nmap 7.80 ( https://nmap.org )")
    lines.append(f"Nmap scan report for {target}")
    lines.append(f"Host is up ({latency}s latency).")

    if "-sV" in flags:
        lines.append(f"Not shown: 995 closed ports")
        lines.append(f"PORT     STATE SERVICE VERSION")
    else:
        lines.append(f"Not shown: 996 closed ports")
        lines.append(f"PORT    STATE SERVICE")

    lines.extend(ports)
    lines.append(f"MAC Address: {mac} (Unknown)")
    lines.append(f"")
    lines.append(f"Nmap done: 1 IP address (1 host up) scanned in {scan_time} seconds")

    return lines

def run_nmap(cmd: str, delay: float = 0.4) -> str:
    """Print nmap output line by line with delay. Returns full output."""
    lines = generate_nmap_output(cmd)
    full_output = ""

    for line in lines:
        print(line)
        sys.stdout.flush()
        full_output += line + "\n"
        time.sleep(delay)

    return full_output.strip()