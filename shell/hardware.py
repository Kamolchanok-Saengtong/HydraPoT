"""
shell/hardware.py -- one machine, described once, answered the same by every command.

`free -m` said 32 GB while /proc/meminfo said 4 GB, /proc/uptime printed nothing and
`df -h` was a model's guess that changed between calls. The numbers live in
config.yaml (system_state.hardware); free, df, nproc, /proc/meminfo, /proc/uptime,
/proc/loadavg and ps's %MEM all read them here.
"""
import math

# Fields /proc/meminfo carries that follow from the configured numbers
_KB = 1024


def meminfo(hw: dict) -> str:
    """/proc/meminfo for the configured memory, in the kernel's own layout."""
    m = hw["memory_kb"]
    total, free, avail = m["total"], m["free"], m["available"]
    buffers, cached, srecl = m["buffers"], m["cached"], m["sreclaimable"]
    shmem, swap, swap_free = m["shmem"], m["swap_total"], m["swap_free"]
    slab = srecl + m.get("sunreclaim", srecl // 3)
    anon = total - free - buffers - cached - slab
    active_file = (buffers + cached) * 2 // 5
    rows = [
        ("MemTotal", total), ("MemFree", free), ("MemAvailable", avail),
        ("Buffers", buffers), ("Cached", cached), ("SwapCached", swap - swap_free),
        ("Active", anon // 2 + active_file), ("Inactive", anon // 2 + (buffers + cached) - active_file),
        ("Active(anon)", anon // 4), ("Inactive(anon)", anon // 4 + shmem),
        ("Active(file)", active_file), ("Inactive(file)", buffers + cached - active_file),
        ("Unevictable", 18532), ("Mlocked", 18532),
        ("SwapTotal", swap), ("SwapFree", swap_free),
        ("Dirty", 84), ("Writeback", 0), ("AnonPages", anon), ("Mapped", anon // 3),
        ("Shmem", shmem), ("KReclaimable", srecl), ("Slab", slab),
        ("SReclaimable", srecl), ("SUnreclaim", slab - srecl),
        ("KernelStack", 4912), ("PageTables", anon // 90), ("NFS_Unstable", 0),
        ("Bounce", 0), ("WritebackTmp", 0), ("CommitLimit", total // 2 + swap),
        ("Committed_AS", anon * 4), ("VmallocTotal", 34359738367), ("VmallocUsed", 31208),
        ("VmallocChunk", 0), ("Percpu", 2624), ("HardwareCorrupted", 0),
        ("AnonHugePages", 0), ("ShmemHugePages", 0), ("ShmemPmdMapped", 0),
        ("FileHugePages", 0), ("FilePmdMapped", 0), ("CmaTotal", 0), ("CmaFree", 0),
        ("HugePages_Total", 0), ("HugePages_Free", 0), ("HugePages_Rsvd", 0),
        ("HugePages_Surp", 0),
    ]
    out = [f"{k + ':':<16}{v:>8} kB" if not k.startswith("HugePages_") else f"{k + ':':<16}{v:>8}"
           for k, v in rows]
    out.append(f"{'Hugepagesize:':<16}{2048:>8} kB")
    out.append(f"{'Hugetlb:':<16}{0:>8} kB")
    out.append(f"{'DirectMap4k:':<16}{total // 40:>8} kB")
    out.append(f"{'DirectMap2M:':<16}{total - total // 40:>8} kB")
    return "\n".join(out) + "\n"


def _scaled(kb: int, base: int = 1024):
    """('3.9', 'Gi') the way procps -h prints one value (bytes in, binary units)."""
    value = kb * 1024
    if value < base:
        return f"{value}", "B"
    for unit in ("Ki", "Mi", "Gi", "Ti"):
        value /= base
        if value < base or unit == "Ti":
            text = f"{value:.1f}" if value < 10 else f"{value:.0f}"
            return text, unit
    return f"{value:.0f}", "Ti"


def free(hw: dict, argv) -> str:
    """`free` with -k/-m/-g/-b/-h (procps 3.3.16 layout); None for anything else."""
    m = hw["memory_kb"]
    unit = "k"
    for a in argv[1:]:
        if a in ("-k", "-m", "-g", "-b", "-h", "--human"):
            unit = {"--human": "h"}.get(a, a[1])
        else:
            return None
    buff_cache = m["buffers"] + m["cached"] + m["sreclaimable"]
    used = m["total"] - m["free"] - buff_cache
    cols = [m["total"], used, m["free"], m["shmem"], buff_cache, m["available"]]
    swap = [m["swap_total"], m["swap_total"] - m["swap_free"], m["swap_free"]]

    def show(kb):
        if unit == "h":
            n, u = _scaled(kb)
            return n + u
        div = {"k": 1, "m": 1024, "g": 1024 * 1024}.get(unit)
        return str(kb * 1024) if unit == "b" else str(kb // div)

    head = " " * 7 + "".join(f"{h:>12}" for h in
                              ("total", "used", "free", "shared", "buff/cache", "available"))
    mem = f"{'Mem:':<7}" + "".join(f"{show(v):>12}" for v in cols)
    sw = f"{'Swap:':<7}" + "".join(f"{show(v):>12}" for v in swap)
    return "\n".join((head, mem, sw))


def loadavg(loads, procs: int, last_pid: int) -> str:
    return f"{loads[0]:.2f} {loads[1]:.2f} {loads[2]:.2f} 1/{procs} {last_pid}\n"


def uptime_file(up_seconds: float, cpus: int, idle_fraction: float) -> str:
    return f"{up_seconds:.2f} {up_seconds * cpus * idle_fraction:.2f}\n"


def _human_df(kb: int) -> str:
    """df -h: powers of 1024, rounded up, one decimal below 10."""
    value, unit = float(kb), "K"
    for nxt in ("M", "G", "T"):
        if value < 1024:
            break
        value, unit = value / 1024, nxt
    text = f"{math.ceil(value * 10) / 10:.1f}" if value < 10 else f"{math.ceil(value)}"
    return text + unit if kb else "0"


def df(disks, argv, mounted_on) -> str:
    """`df`, `df -h`, `df -k`, `df <path>` over the configured filesystems.

    `mounted_on(path)` -> the mount point holding that path, or None when unknown.
    Returns None for anything else (-T, -i, --output ...) so the old path answers.
    """
    human, paths = False, []
    for a in argv[1:]:
        if a == "-h":
            human = True
        elif a in ("-k", "-P"):
            continue
        elif a.startswith("-"):
            return None
        else:
            paths.append(a)
    chosen = disks
    if paths:
        chosen = []
        for p in paths:
            mount = mounted_on(p)
            fs = next((d for d in disks if d["mount"] == mount), None)
            if fs is None:
                return None
            chosen.append(fs)
    head = ("Filesystem      Size  Used Avail Use% Mounted on" if human else
            "Filesystem     1K-blocks    Used Available Use% Mounted on")
    rows = [head]
    for d in chosen:
        size, used, avail = d["size_kb"], d["used_kb"], d["avail_kb"]
        pct = f"{math.ceil(used * 100 / (used + avail))}%" if used + avail else "-"
        if human:
            rows.append(f"{d['device']:<14} {_human_df(size):>5} {_human_df(used):>5} "
                        f"{_human_df(avail):>5} {pct:>4} {d['mount']}")
        else:
            rows.append(f"{d['device']:<14} {size:>9} {used:>7} {avail:>9} {pct:>4} {d['mount']}")
    return "\n".join(rows)
