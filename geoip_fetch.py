"""
geoip_fetch.py — auto-download the DB-IP City Lite geolocation database.

The dashboard's world map needs an .mmdb geolocation DB. We use DB-IP's free
"IP to City Lite" file (db-ip.com) — CC BY 4.0, NO account/key required, and
freely redistributable (unlike MaxMind GeoLite2). This module fetches it on
demand so users don't have to download anything manually.

Attribution (required by CC BY 4.0):
    IP geolocation by DB-IP (https://db-ip.com) — City Lite, CC BY 4.0.

DB-IP publishes one file per month at a predictable URL and keeps only the
recent months live, so we try the current month and fall back a couple of
months if it's not published yet / has rolled off.
"""
import os
import gzip
import shutil
import tempfile
import urllib.request
import urllib.error
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))

# data/, not the repo root. This is a ~130 MB file fetched at runtime and
# gitignored -- runtime state, exactly like data/hp_run.log and the SSH host
# key that already live there. It is deliberately NOT shipped in the package:
# a 130 MB wheel for a file that is rebuilt monthly from an upstream URL would
# be absurd, and `pip install -e .` never copies it anywhere.
DATA_DIR = os.path.join(_HERE, "data")
DEFAULT_MMDB = os.path.join(DATA_DIR, "geoip.mmdb")

# Where it used to live. Kept only so an existing checkout does not re-download
# 90 MB after the move -- see _migrate_legacy().
_LEGACY_MMDB = os.path.join(_HERE, "geoip.mmdb")


def _migrate_legacy(path: str) -> bool:
    """Move a pre-existing root-level geoip.mmdb into data/ once.

    Same filesystem, so os.replace is atomic and instant -- the alternative is
    making every existing user re-download ~90 MB for a file they already have.
    Only fires for the default path: a caller that passed an explicit path
    means it.
    """
    if path != DEFAULT_MMDB or not os.path.exists(_LEGACY_MMDB):
        return False
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        os.replace(_LEGACY_MMDB, DEFAULT_MMDB)
        return True
    except OSError:
        return False
DBIP_URL = "https://download.db-ip.com/free/dbip-city-lite-{ym}.mmdb.gz"

ATTRIBUTION = "IP geolocation by DB-IP (https://db-ip.com) — City Lite, CC BY 4.0."

# DB-IP rejects the default Python-urllib user-agent with HTTP 403, so send a
# browser-like UA (the file itself is a free, no-auth public download).
_UA = "Mozilla/5.0 (X11; Linux x86_64) HydraPoT/geoip-fetch"


def _candidate_months(n: int = 3):
    """current month first, then the previous n-1 months (YYYY-MM strings)."""
    now = datetime.now(timezone.utc)
    y, m = now.year, now.month
    out = []
    for _ in range(n):
        out.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            m, y = 12, y - 1
    return out


def update_geoip(path: str = DEFAULT_MMDB, quiet: bool = False) -> bool:
    """(Re)download the latest DB-IP City Lite database to `path`. Returns True
    on success. Writes atomically (temp file + rename) so a failed/partial
    download never corrupts an existing good file."""
    # The target directory is data/ now, which a fresh checkout may not have --
    # and the temp files below are written next to `path`, so this must happen
    # before the first open(), not after.
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    def log(msg):
        if not quiet:
            print(msg, flush=True)

    for ym in _candidate_months():
        url = DBIP_URL.format(ym=ym)
        try:
            log(f"[geoip] downloading DB-IP City Lite {ym} (~90 MB)...")
            tmp_gz = path + f".{ym}.gz.tmp"
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=120) as resp, open(tmp_gz, "wb") as f:
                shutil.copyfileobj(resp, f)
            # gunzip -> temp, then atomic rename into place
            tmp_out = path + ".tmp"
            with gzip.open(tmp_gz, "rb") as fin, open(tmp_out, "wb") as fout:
                shutil.copyfileobj(fin, fout)
            os.replace(tmp_out, path)
            os.remove(tmp_gz)
            log(f"[geoip] ready -> {path}")
            log(f"[geoip] {ATTRIBUTION}")
            return True
        except urllib.error.HTTPError as e:
            # 404 for the current month early in the month is normal — try older
            if e.code == 404:
                continue
            log(f"[geoip] download error ({ym}): HTTP {e.code}")
        except Exception as e:
            log(f"[geoip] download failed ({ym}): {e}")
        finally:
            for f in (path + f".{ym}.gz.tmp", path + ".tmp"):
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except OSError:
                        pass

    log("[geoip] could not download DB-IP database (offline?). "
        "Dashboard still runs; the world map will be unavailable.")
    return False


def ensure_geoip(path: str = DEFAULT_MMDB, quiet: bool = False) -> bool:
    """Download the DB-IP database only if it's missing. Safe to call on every
    dashboard start — a no-op once the file exists. Never raises."""
    if os.path.exists(path):
        return True
    if _migrate_legacy(path):
        if not quiet:
            print(f"[geoip] moved existing database -> {path}", flush=True)
        return True
    try:
        return update_geoip(path, quiet=quiet)
    except Exception as e:
        if not quiet:
            print(f"[geoip] unexpected error: {e}", flush=True)
        return False


if __name__ == "__main__":
    update_geoip()
