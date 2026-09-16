"""
tools/prune_logs.py — apply the retention policy to hydrapot.db.

Nothing prunes this database on its own, so on a real deployment it grows
until the disk fills and the sensor stops recording without saying so.

DRY RUN BY DEFAULT. Deleting is opt-in via --apply, because this database
holds live capture, the CyberLab corpus and the experiment-sandbox runs in the
same tables — an age rule applied blindly removes the oldest real attacker
data first.

Usage
-----
    python tools/prune_logs.py                      # policy from config.yaml, dry run
    python tools/prune_logs.py --days 90            # override, dry run
    python tools/prune_logs.py --days 90 --apply    # actually delete
    python tools/prune_logs.py --days 90 --protect CyberLab --apply
    python tools/prune_logs.py --max-rows 500000 --apply
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

import storage                      # noqa: E402
from config_loader import load_config   # noqa: E402


def _mb(n):
    return f"{n / 1048576:.1f} MB"


def main():
    cfg = load_config().logging
    ap = argparse.ArgumentParser(description="Prune old rows from hydrapot.db")
    ap.add_argument("--days", type=int, default=cfg.retention_days,
                    help="delete rows older than N days (0 = off)")
    ap.add_argument("--max-rows", type=int, default=cfg.retention_max_rows,
                    help="per table, keep only the N newest rows (0 = off)")
    ap.add_argument("--protect", action="append",
                    default=list(cfg.retention_protect_instances),
                    help="instance name never to delete (repeatable)")
    ap.add_argument("--no-vacuum", action="store_true",
                    help="skip reclaiming disk after deleting")
    ap.add_argument("--apply", action="store_true",
                    help="actually delete; without this it is a dry run")
    a = ap.parse_args()

    if a.days <= 0 and a.max_rows <= 0:
        print("Retention is off (retention_days and retention_max_rows are both 0).")
        print("Set them in config.yaml under `logging:`, or pass --days / --max-rows.")
        return

    print(f"policy      : days={a.days or 'off'}  max_rows={a.max_rows or 'off'}")
    print(f"protected   : {', '.join(a.protect) if a.protect else '(nothing)'}")
    print(f"mode        : {'APPLY — rows will be deleted' if a.apply else 'DRY RUN'}\n")

    res = storage.prune(retention_days=a.days,
                        max_rows=a.max_rows,
                        protect_instances=a.protect,
                        vacuum=cfg.retention_vacuum and not a.no_vacuum,
                        dry_run=not a.apply)

    for table in storage.PRUNE_TABLES:
        r = res.get(table)
        if r:
            print(f"  {table:11} delete {r['deleted']:>9,}   keep {r['kept']:>9,}")
    print(f"\n  size {_mb(res['size_before'])} -> {_mb(res['size_after'])}"
          f"   vacuum={res.get('vacuum')}")
    if res.get("vacuum_skipped"):
        print(f"  vacuum skipped: {res['vacuum_skipped']}")
    if not a.apply:
        print("\n  Nothing was changed. Re-run with --apply to delete.")


if __name__ == "__main__":
    main()
