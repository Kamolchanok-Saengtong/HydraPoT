"""
shell/hardware.py -- one machine, described once, answered the same by every command.

`free -m` said 32 GB while /proc/meminfo said 4 GB, /proc/uptime printed nothing and
`df -h` was a model's guess that changed between calls. The numbers live in
system_state.hardware in config.yaml, which declares the machine; free, df,
nproc, /proc/uptime, /proc/loadavg and ps's %MEM all read them here.
"""
import math

def meminfo(hw: dict) -> str:
    """/proc/meminfo for the declared memory, in the kernel's own layout."""
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
    out += [f"{'Hugepagesize:':<16}{2048:>8} kB", f"{'Hugetlb:':<16}{0:>8} kB",
            f"{'DirectMap4k:':<16}{total // 40:>8} kB",
            f"{'DirectMap2M:':<16}{total - total // 40:>8} kB"]
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


def free(hw: dict, argv, drift: int = 0) -> str:
    """`free` with -k/-m/-g/-b/-h (procps 3.3.16 layout); None for anything else."""
    m = hw["memory_kb"]
    unit = "k"
    for a in argv[1:]:
        if a in ("-k", "-m", "-g", "-b", "-h", "--human"):
            unit = {"--human": "h"}.get(a, a[1])
        else:
            return None
    buff_cache = m["buffers"] + m["cached"] + m["sreclaimable"] - drift
    free_kb = m["free"] + drift
    used = m["total"] - free_kb - buff_cache
    cols = [m["total"], used, free_kb, m["shmem"], buff_cache, m["available"] + drift]
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


def _sized(d: dict, total_kb: int) -> dict:
    """tmpfs and devtmpfs are a share of RAM, so they follow it instead of a typed size."""
    if "ram_fraction" not in d:
        return d
    size = int(total_kb * d["ram_fraction"])
    used = d.get("used_kb", 0)
    return {**d, "size_kb": size, "used_kb": used, "avail_kb": size - used}


def df(disks, argv, mounted_on, total_kb: int = 0) -> str:
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
    disks = [_sized(d, total_kb) for d in disks]
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


_CGROUPS = ("cpu,cpuacct", "freezer", "pids", "rdma", "net_cls,net_prio", "cpuset", "memory",
            "blkio", "devices", "perf_event", "hugetlb")


def mount_lines(disks, total_kb: int, uid: int = 0) -> str:
    """`mount` the way Ubuntu 20.04 lists it: the kernel's pseudo-filesystems around the
    declared disks, with RAM-sized mounts following the machine's memory."""
    sized = {d["mount"]: _sized(d, total_kb) for d in disks}
    size = lambda mount: sized[mount]["size_kb"] if mount in sized else total_kb // 2
    out = ["sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)",
           "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)",
           f"udev on /dev type devtmpfs (rw,nosuid,relatime,size={size('/dev')}k,nr_inodes={size('/dev') // 4},mode=755)",
           "devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)",
           f"tmpfs on /run type tmpfs (rw,nosuid,noexec,relatime,size={size('/run')}k,mode=755)"]
    for d in disks:
        if d["device"].startswith("/dev/sd") or d["device"].startswith("/dev/vd") or d["device"].startswith("/dev/nvme"):
            if d["mount"] == "/":
                out.append(f"{d['device']} on / type ext4 (rw,relatime)")
    out += ["securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)",
            "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)",
            f"tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size={size('/run/lock')}k)",
            "tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)",
            "cgroup2 on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)",
            "cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)",
            "pstore on /sys/fs/pstore type pstore (rw,nosuid,nodev,noexec,relatime)",
            "none on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)"]
    out += [f"cgroup on /sys/fs/cgroup/{c} type cgroup (rw,nosuid,nodev,noexec,relatime,{c})" for c in _CGROUPS]
    out += ["systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=28,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=18226)",
            "hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,pagesize=2M)",
            "mqueue on /dev/mqueue type mqueue (rw,relatime)",
            "debugfs on /sys/kernel/debug type debugfs (rw,relatime)",
            "tracefs on /sys/kernel/tracing type tracefs (rw,relatime)",
            "configfs on /sys/kernel/config type configfs (rw,relatime)",
            "fusectl on /sys/fs/fuse/connections type fusectl (rw,relatime)"]
    for d in disks:
        if d["device"].startswith("/dev/loop"):
            out.append(f"{d['device']} on {d['mount']} type squashfs (ro,nodev,relatime)")
    for d in disks:
        if d["mount"] == "/boot/efi":
            out.append(f"{d['device']} on /boot/efi type vfat (rw,relatime,fmask=0077,dmask=0077,codepage=437,"
                       "iocharset=iso8859-1,shortname=mixed,errors=remount-ro)")
    owner = f",uid={uid},gid={uid}" if uid else ""
    out.append(f"tmpfs on /run/user/{uid} type tmpfs (rw,nosuid,nodev,relatime,size={size('/run') - 4}k,mode=700{owner})")
    return "\n".join(out)


# ── the processor, declared once ────────────────────────────────────────────

_FLAGS = ("fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx "
          "fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts "
          "rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx "
          "est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer "
          "aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb cat_l3 cat_l2 cdp_l3 invpcid_single "
          "intel_ppin cdp_l2 ssbd mba ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid "
          "ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a avx512f avx512dq rdseed adx "
          "smap avx512ifma clflushopt clwb intel_pt avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 "
          "xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local split_lock_detect avx_vnni avx512_bf16 "
          "wbnoinvd dtherm ida arat pln pts avx512vbmi umip pku ospke waitpkg avx512_vbmi2 gfni vaes vpclmulqdq "
          "avx512_vnni avx512_bitalg tme avx512_vpopcntdq la57 rdpid bus_lock_detect cldemote movdiri movdir64b "
          "enqcmd fsrm md_clear serialize tsxldtrk pconfig arch_lbr amx_bf16 avx512_fp16 amx_tile amx_int8 "
          "flush_l1d arch_capabilities")


def _cpu(hw: dict):
    c = hw.get("cpu")
    return c if c and hw.get("cpus") else None


def _topology(hw: dict, i: int):
    """(socket, core) of logical CPU i: socket-major, hyperthreads in the upper half, as Linux numbers them."""
    c = hw["cpu"]
    per_socket, cores = c["cores_per_socket"], c["cores_per_socket"] * c["sockets"]
    core = i % cores
    return core // per_socket, core


def cpuinfo(hw: dict) -> str:
    """/proc/cpuinfo for the declared processor, one block per logical CPU."""
    c = _cpu(hw)
    if not c:
        return ""
    blocks = []
    for i in range(hw["cpus"]):
        socket, core = _topology(hw, i)
        mhz = c["mhz"] + ((i * 37) % 200) / 10 - 5
        blocks.append("\n".join([
            f"processor\t: {i}", "vendor_id\t: GenuineIntel", f"cpu family\t: {c['family']}",
            f"model\t\t: {c['model']}", f"model name\t: {c['name']}", f"stepping\t: {c['stepping']}",
            f"microcode\t: {c['microcode']}", f"cpu MHz\t\t: {mhz:.3f}", f"cache size\t: {c['l3_kb']} KB",
            f"physical id\t: {socket}", f"siblings\t: {c['cores_per_socket'] * c['threads_per_core']}",
            f"core id\t\t: {core % c['cores_per_socket']}", f"cpu cores\t: {c['cores_per_socket']}",
            f"apicid\t\t: {core * 2 + (i // (hw['cpus'] // c['threads_per_core']))}",
            f"initial apicid\t: {core * 2 + (i // (hw['cpus'] // c['threads_per_core']))}",
            "fpu\t\t: yes", "fpu_exception\t: yes", "cpuid level\t: 27", "wp\t\t: yes", f"flags\t\t: {_FLAGS}",
            "vmx flags\t: vnmi preemption_timer posted_intr invvpid ept_x_only ept_ad ept_1gb flexpriority "
            "apicv tsc_offset vtpr mtf vapic ept vpid unrestricted_guest vapic_reg vid ple shadow_vmcs pml ept_mode_based_exec tsc_scaling",
            "bugs\t\t: spectre_v1 spectre_v2 spec_store_bypass swapgs eibrs_pbrsb",
            f"bogomips\t: {c['mhz'] * 2:.2f}", "clflush size\t: 64", "cache_alignment\t: 64",
            "address sizes\t: 46 bits physical, 57 bits virtual", "power management:", ""]))
    return "\n".join(blocks) + "\n"


def lscpu(hw: dict, argv=()) -> str:
    """util-linux 2.34 `lscpu` for the declared processor."""
    c = _cpu(hw)
    if not c or len(argv) > 1:
        return ""
    n, sockets = hw["cpus"], c["sockets"]
    per_node = n // sockets
    cores = c["cores_per_socket"] * sockets
    half = lambda k: f"{k * cores // sockets}-{(k + 1) * cores // sockets - 1},{n // 2 + k * cores // sockets}-{n // 2 + (k + 1) * cores // sockets - 1}"
    kib = lambda per, total: f"{per * total // 1024} MiB" if per * total >= 1048576 else f"{per * total} KiB"
    rows = [("Architecture:", "x86_64"), ("CPU op-mode(s):", "32-bit, 64-bit"), ("Byte Order:", "Little Endian"),
            ("Address sizes:", "46 bits physical, 57 bits virtual"), ("CPU(s):", str(n)),
            ("On-line CPU(s) list:", f"0-{n - 1}"), ("Thread(s) per core:", str(c["threads_per_core"])),
            ("Core(s) per socket:", str(c["cores_per_socket"])), ("Socket(s):", str(sockets)),
            ("NUMA node(s):", str(sockets)), ("Vendor ID:", "GenuineIntel"), ("CPU family:", str(c["family"])),
            ("Model:", str(c["model"])), ("Model name:", c["name"]), ("Stepping:", str(c["stepping"])),
            ("CPU MHz:", f"{c['mhz']:.3f}"), ("BogoMIPS:", f"{c['mhz'] * 2:.2f}"), ("Virtualization:", "VT-x"),
            ("L1d cache:", kib(48, cores)), ("L1i cache:", kib(32, cores)), ("L2 cache:", kib(2048, cores)),
            ("L3 cache:", f"{c['l3_kb'] * sockets // 1024} MiB")]
    rows += [(f"NUMA node{k} CPU(s):", half(k)) for k in range(sockets)]
    rows += [("Vulnerability Itlb multihit:", "Not affected"), ("Vulnerability L1tf:", "Not affected"),
             ("Vulnerability Mds:", "Not affected"), ("Vulnerability Meltdown:", "Not affected"),
             ("Vulnerability Spec store bypass:", "Mitigation; Speculative Store Bypass disabled via prctl and seccomp"),
             ("Vulnerability Spectre v1:", "Mitigation; usercopy/swapgs barriers and __user pointer sanitization"),
             ("Vulnerability Spectre v2:", "Mitigation; Enhanced IBRS, IBPB conditional, RSB filling"),
             ("Vulnerability Srbds:", "Not affected"), ("Vulnerability Tsx async abort:", "Not affected"),
             ("Flags:", _FLAGS)]
    return "\n".join(f"{k:<34}{v}" for k, v in rows)
