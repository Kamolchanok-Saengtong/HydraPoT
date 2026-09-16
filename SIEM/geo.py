"""
SIEM/geo.py — GeoIP lookups + the sidebar's GeoIP status badge.
"""
import os

from dash import html, Input, Output

from SIEM.server import app

# Imported, never re-derived. This used to build its own path next to
# storage.py, so moving the database to data/ silently broke the map here while
# `hp geoip` kept reporting success -- two copies of one path is how that
# happens. geoip_fetch owns it; everyone else asks.
from geoip_fetch import DEFAULT_MMDB as MMDB_PATH

_geo_reader = None
_geo_reader_loaded = False
_geo_cache: dict = {}


def _load_geo_reader():
    global _geo_reader, _geo_reader_loaded
    if _geo_reader_loaded:
        return _geo_reader
    _geo_reader_loaded = True
    if not os.path.exists(MMDB_PATH):
        return None
    try:
        import geoip2.database
        _geo_reader = geoip2.database.Reader(MMDB_PATH)
    except Exception as e:
        print(f"[geo] failed: {e}")
        _geo_reader = None
    return _geo_reader

def geolocate(ip: str):
    if not ip or ip in ("?", "127.0.0.1", "::1", ""):
        return None
    if ip in _geo_cache:
        return _geo_cache[ip]
    reader = _load_geo_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
        if r.location.latitude is None:
            _geo_cache[ip] = None
            return None
        result = {
            "lat": r.location.latitude, "lon": r.location.longitude,
            "country": r.country.name or "Unknown", "city": r.city.name or "",
        }
        _geo_cache[ip] = result
        return result
    except Exception:
        _geo_cache[ip] = None
        return None


# ── GeoIP status badge ──────────────────────────────────────────────────────────

@app.callback(Output("geo-status", "children"), Input("page-store", "data"))
def update_geo_status(_page):
    if os.path.exists(MMDB_PATH):
        return html.Div("🌍 GeoIP ready", className="status-pill status-ok")
    return html.Div("⚠️ geoip.mmdb not found", className="status-pill status-warn")
