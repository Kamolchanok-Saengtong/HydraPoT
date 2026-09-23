"""
SIEM/bench.py — is this SIEM actually lightweight? Measure, don't claim.

Four things, because those are the four a reader can check against any other
SIEM's published minimums:

    footprint   what it costs to have it running at all
    idle        what it costs when nobody is using it
    ingest      how fast events can land
    scaling     how latency and disk move as the dataset grows

NEVER TOUCHES THE REAL DATABASE. Fixtures are built in a temp directory from
rows REPLAYED out of the real one (read-only), so command text, response size
and FI distribution are realistic rather than synthetic filler -- bytes/event
and pipeline cost both depend on that being true.

    python SIEM/bench.py                          # quick: 10k / 50k
    python SIEM/bench.py --sizes 10000,50000,200000 --idle 120 --csv bench.csv
"""
import argparse
import inspect
import os
import resource
import shutil
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import storage


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def point_storage_at(path: str):
    """Redirect every storage function at `path`.

    Rebinding storage.DB_PATH alone is not enough: each function captured the
    old value as a default argument when it was defined, so the defaults have
    to be rewritten too. Doing it by value rather than by position keeps it
    correct if a signature gains a parameter.
    """
    old = storage.DB_PATH
    storage.DB_PATH = path
    for fn in vars(storage).values():
        if inspect.isfunction(fn) and fn.__defaults__:
            fn.__defaults__ = tuple(path if d == old else d
                                    for d in fn.__defaults__)


# ── fixtures ────────────────────────────────────────────────────────────────

def real_rows(limit: int) -> list:
    """Sample rows out of the live database, read-only."""
    conn = sqlite3.connect(f"file:{storage.DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    # Spread across the whole table, not the first N: response length drives
    # bytes/event and the early rows are not representative of the mean.
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM sessions ORDER BY RANDOM() LIMIT ?", (limit,))]
    conn.close()
    return rows


def build(path: str, n: int, seed: list):
    """n rows, cycled from `seed`, each in its own session block of 20.

    Bulk-inserted on ONE connection. That is fixture building, not an ingest
    measurement -- ingest is timed separately through the real insert path.
    """
    storage.init_db(path)
    cols = [c for c in storage.COLUMNS]
    conn = sqlite3.connect(path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    batch = []
    for i in range(n):
        src = dict(seed[i % len(seed)])
        src["session_id"] = f"bench-{i // 20}"
        src["seq"] = i % 20
        src["instance"] = "default"
        batch.append(tuple(src.get(c) for c in cols))
    conn.executemany(
        f"INSERT OR IGNORE INTO sessions ({','.join(cols)}) "
        f"VALUES ({','.join('?' * len(cols))})", batch)
    conn.commit()
    conn.close()


# ── the four measurements ───────────────────────────────────────────────────

def footprint() -> dict:
    t = time.time()
    import api_server            # noqa: F401  Dash + FastAPI + the pipeline
    from api import services as svc     # noqa: F401
    return {"import_s": round(time.time() - t, 2), "rss_mb": round(rss_mb())}


def idle(seconds: int, port: int = 8050) -> dict:
    """RSS and CPU while serving nobody.

    Samples the running `hp dashboard` when there is one -- that is the number
    an operator cares about -- and this process otherwise.
    """
    import psutil
    me = psutil.Process()
    target, what = me, "this process (no server found)"
    # By LISTENING PORT, not by cmdline: the server is started through the `hp`
    # entry point, so its argv says "hp dashboard" and never "api_server".
    try:
        for c in psutil.net_connections(kind="tcp"):
            if (c.status == psutil.CONN_LISTEN and c.laddr
                    and c.laddr.port == port and c.pid and c.pid != me.pid):
                target = psutil.Process(c.pid)
                what = f"{' '.join(target.cmdline()[:3])}, pid {c.pid}"
                break
    except (psutil.AccessDenied, PermissionError):
        pass
    target.cpu_percent(None)                      # prime the counter
    rss, cpu = [], []
    for _ in range(max(1, seconds // 5)):
        time.sleep(5)
        rss.append(target.memory_info().rss / 1e6)
        cpu.append(target.cpu_percent(None))
    return {"who": what, "rss_mb": round(sum(rss) / len(rss)),
            "rss_max_mb": round(max(rss)), "cpu_pct": round(sum(cpu) / len(cpu), 2),
            "samples": len(rss)}


def ingest(seed: list, n: int) -> dict:
    """Events per second through the REAL write path, one commit each."""
    d = tempfile.mkdtemp()
    p = os.path.join(d, "ingest.db")
    storage.init_db(p)
    t = time.time()
    for i in range(n):
        row = dict(seed[i % len(seed)])
        row["session_id"] = f"ing-{i // 20}"
        storage.insert_command(row, path=p)
    dt = time.time() - t
    size = os.path.getsize(p)
    shutil.rmtree(d, ignore_errors=True)
    return {"events": n, "seconds": round(dt, 2), "events_per_s": round(n / dt),
            "ms_per_event": round(dt / n * 1000, 2),
            "bytes_per_event": round(size / n)}


def scaling(seed: list, sizes: list) -> list:
    out = []
    for n in sizes:
        d = tempfile.mkdtemp()
        p = os.path.join(d, f"bench_{n}.db")
        build(p, n, seed)
        point_storage_at(p)

        import SIEM.data as data
        from api import services as svc
        data.clear_caches()

        def ms(fn):
            t = time.time()
            try:
                fn()
            except Exception as e:
                return f"ERR {type(e).__name__}"
            return round((time.time() - t) * 1000)

        row = {
            "rows": n,
            "db_mb": round(os.path.getsize(p) / 1e6, 1),
            "bytes_row": round(os.path.getsize(p) / n),
            "query_recent": ms(lambda: storage.query_recent(30)),
            "load_all": ms(data.load_all),
            "overview": ms(lambda: svc.overview("all")),
            "detections": ms(lambda: svc.list_detections("all")),
            "iocs": ms(lambda: svc.list_iocs("all")),
            "rss_mb": round(rss_mb()),
        }
        out.append(row)
        print("   " + "  ".join(f"{k}={v}" for k, v in row.items()), flush=True)
        shutil.rmtree(d, ignore_errors=True)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sizes", default="10000,50000")
    ap.add_argument("--idle", type=int, default=0, help="seconds to sample")
    ap.add_argument("--port", type=int, default=8050,
                    help="the running dashboard, found by listening port")
    ap.add_argument("--ingest", type=int, default=3000, help="events to write")
    ap.add_argument("--csv", default="")
    a = ap.parse_args()

    real_db = storage.DB_PATH
    print(f"[bench] real database (read-only source): {real_db}")
    seed = real_rows(2000)
    print(f"[bench] seeded from {len(seed)} real rows\n")

    f = footprint()
    print(f"FOOTPRINT   import {f['import_s']}s   RSS {f['rss_mb']} MB   "
          f"external services 0")

    if a.idle:
        i = idle(a.idle, a.port)
        print(f"IDLE        {i['who']}: RSS {i['rss_mb']} MB "
              f"(max {i['rss_max_mb']}), CPU {i['cpu_pct']}% "
              f"over {i['samples']} samples")

    g = ingest(seed, a.ingest)
    print(f"INGEST      {g['events_per_s']} events/s  "
          f"({g['ms_per_event']} ms/event, {g['bytes_per_event']} bytes/event)")

    print("\nSCALING (ms, cold cache)")
    rows = scaling(seed, [int(s) for s in a.sizes.split(",")])

    if a.csv:
        import csv
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"\n[bench] wrote {a.csv}")


if __name__ == "__main__":
    main()
