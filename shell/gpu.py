"""
shell/gpu.py -- the GPUs this machine claims to have, as `nvidia-smi` prints them.

Declared in config.yaml (system_state.hardware.gpus), never read from the host. The numbers
move a little with time but stay the same for the same moment, and they follow the process
table: a training process on a GPU is listed there, and if the attacker kills it the card
goes idle, as it would on a real machine.
"""
import hashlib
import random
from datetime import datetime

_SEP = "+" + "-" * 87 + "+"


def _rng(seed: str, bucket: int, i: int) -> random.Random:
    return random.Random(hashlib.sha1(f"{seed}{bucket}{i}".encode()).digest())


def _state(g: dict, seed: str, now: float, i: int, busy: bool) -> dict:
    """What GPU i reads at this moment (a new reading every few seconds)."""
    r, cap = _rng(seed, int(now // 3), i), g["power_cap_w"]
    if not busy:
        return {"util": 0, "used": 4, "temp": 33 + r.randint(0, 3), "perf": "P0", "power": 70 + r.randint(0, 4)}
    base = _rng(seed, 0, i)
    return {"util": r.choice([100, 100, 99, 98, 97, 96, 100]), "used": g["memory_mib"] * 88 // 100 + base.randint(0, 2500) + r.randint(0, 6),
            "temp": 61 + base.randint(0, 9) + r.randint(0, 2), "perf": "P0", "power": int(cap * (0.55 + base.random() * 0.2) + r.randint(0, 25))}


def _uuid(seed: str, i: int) -> str:
    h = hashlib.sha1(f"{seed}gpu{i}".encode()).hexdigest()
    return f"GPU-{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _bus(i: int) -> str:
    return f"0000{(0x18, 0x2a, 0x3a, 0x4d, 0x9a, 0xab, 0xbb, 0xcb)[i % 8]:02X}:00.0".replace("0000", "0000", 1)


def _bus_full(i: int) -> str:
    return f"0000000{0}:{(0x18, 0x2a, 0x3a, 0x4d, 0x9a, 0xab, 0xbb, 0xcb)[i % 8]:02X}:00.0"[-16:]


def _cell(width: int, left: str, right: str = "") -> str:
    return left + right.rjust(width - len(left))


def _table(g, seed, now, trainers):
    when = datetime.fromtimestamp(now).strftime("%a %b %e %H:%M:%S %Y")
    out = [f"{when}       ", "+" + "-" * 87 + "+",
           "|" + f" NVIDIA-SMI {g['driver']}{' ' * 13}Driver Version: {g['driver']}   CUDA Version: {g['cuda']}".ljust(87) + "|",
           "|-----------------------------------------+----------------------+----------------------+",
           "| GPU  Name                 Persistence-M | Bus-Id        Disp.A | Volatile Uncorr. ECC |",
           "| Fan  Temp   Perf          Pwr:Usage/Cap |         Memory-Usage | GPU-Util  Compute M. |",
           "|                                         |                      |               MIG M. |",
           "|=========================================+======================+======================|"]
    for i in range(g["count"]):
        s = _state(g, seed, now, i, i in trainers)
        c1 = f" {i:>3}  {g['name']:<31}On  "[:41].ljust(41)
        c2 = f" {_bus_full(i)} Off "
        c3 = f"{0:>21} "
        r2a = _cell(41, f" N/A  {s['temp']:>3}C    {s['perf']}", f"{s['power']}W / {g['power_cap_w']}W ")
        r2b = f"{s['used']:>7}MiB / {g['memory_mib']}MiB "
        r2c = f"{s['util']:>7}%      Default "
        out += [f"|{c1}|{c2}|{c3}|", f"|{r2a}|{r2b}|{r2c}|", f"|{'':41}|{'':22}|{'Disabled':>21} |",
                "+-----------------------------------------+----------------------+----------------------+"]
    out[-1] = "+" + "-" * 87 + "+"
    out += ["", "+" + "-" * 87 + "+", "| Processes:".ljust(88) + "|",
            "|  GPU   GI   CI        PID   Type   Process name                            GPU Memory |",
            "|        ID   ID                                                             Usage      |",
            "|" + "=" * 87 + "|"]
    if not trainers:
        out.append("|  No running processes found".ljust(88) + "|")
    for i, pid in sorted(trainers.items()):
        s = _state(g, seed, now, i, True)
        left = f"{i:>5}   N/A  N/A{pid:>10}{'C':>7}   python3"
        right = f"{s['used'] - 12}MiB "
        out.append("|" + _cell(87, left, right) + "|")
    out.append("+" + "-" * 87 + "+")
    return "\n".join(out)


_FIELDS = {
    "index": lambda g, s, i, st: str(i), "name": lambda g, s, i, st: g["name"],
    "uuid": lambda g, s, i, st: _uuid(s, i), "driver_version": lambda g, s, i, st: g["driver"],
    "pci.bus_id": lambda g, s, i, st: _bus_full(i),
    "memory.total": lambda g, s, i, st: f"{g['memory_mib']} MiB",
    "memory.used": lambda g, s, i, st: f"{st['used']} MiB",
    "memory.free": lambda g, s, i, st: f"{g['memory_mib'] - st['used']} MiB",
    "utilization.gpu": lambda g, s, i, st: f"{st['util']} %",
    "utilization.memory": lambda g, s, i, st: f"{max(st['util'] - 38, 0)} %",
    "temperature.gpu": lambda g, s, i, st: str(st["temp"]),
    "power.draw": lambda g, s, i, st: f"{st['power']}.{(i * 7) % 100:02d} W",
    "power.limit": lambda g, s, i, st: f"{g['power_cap_w']}.00 W",
    "pstate": lambda g, s, i, st: st["perf"], "clocks.sm": lambda g, s, i, st: f"{1980 if st['util'] else 345} MHz",
    "compute_mode": lambda g, s, i, st: "Default", "persistence_mode": lambda g, s, i, st: "Enabled",
}


def _query(g, seed, now, trainers, argv):
    fields = fmt = None
    for a in argv:
        if a.startswith("--query-gpu="):
            fields = a.split("=", 1)[1].split(",")
        elif a.startswith("--format="):
            fmt = a.split("=", 1)[1].split(",")
    if not fields or not fmt or fmt[0] != "csv" or any(f not in _FIELDS for f in fields):
        return None
    units = "nounits" not in fmt
    lines = [] if "noheader" in fmt else [", ".join(_HEAD.get(f, f) + (_UNIT.get(f, "") if units else "") for f in fields)]
    for i in range(g["count"]):
        st = _state(g, seed, now, i, i in trainers)
        vals = [_FIELDS[f](g, seed, i, st) for f in fields]
        if not units:
            vals = [v.split(" ")[0] if f in _UNIT else v for f, v in zip(fields, vals)]
        lines.append(", ".join(vals))
    return "\n".join(lines)


_HEAD = {"memory.total": "memory.total", "utilization.gpu": "utilization.gpu"}
_UNIT = {"memory.total": " [MiB]", "memory.used": " [MiB]", "memory.free": " [MiB]", "utilization.gpu": " [%]",
         "utilization.memory": " [%]", "power.draw": " [W]", "power.limit": " [W]", "clocks.sm": " [MHz]"}


def smi(g: dict, seed: str, now: float, trainers: dict, argv) -> str:
    """-> the text, or None when the arguments are ones this does not model.

    trainers: {gpu index: pid} of the training processes the process table still has.
    """
    args = list(argv[1:])
    if not args:
        return _table(g, seed, now, trainers)
    if args in (["-L"], ["--list-gpus"]):
        return "\n".join(f"GPU {i}: {g['name']} (UUID: {_uuid(seed, i)})" for i in range(g["count"]))
    if any(a.startswith("--query-gpu=") for a in args):
        return _query(g, seed, now, trainers, args)
    return None
