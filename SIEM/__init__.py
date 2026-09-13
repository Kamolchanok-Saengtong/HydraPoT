"""
SIEM/ — HydraPoT's Plotly Dash dashboard, split into one module per
concern/page (see each module's own docstring).

Import order matters: modules register @app.callback / app.clientside_callback
as a side effect of being imported, and layout.py needs every page module's
build_*_page() already importable before it can set app.layout. So: shared
infra first (data/theme/cost/geo/ioc), then clientside JS, then each page
module, then layout.py last.
"""
from SIEM.server import app

import SIEM.theme          # noqa: F401  (sets app.index_string, defines colors)
import SIEM.data           # noqa: F401  (TTL-cached data access)
import SIEM.cost           # noqa: F401  (estimate_savings)
import SIEM.geo            # noqa: F401  (registers update_geo_status)
import SIEM.ioc            # noqa: F401  (build_ioc_snapshot)

import SIEM.clientside     # noqa: F401  (registers 3 clientside callbacks)

import SIEM.pages.live_feed     # noqa: F401  (registers _refresh_live_feed)
import SIEM.pages.summary       # noqa: F401
import SIEM.pages.mitre         # noqa: F401  (registers several callbacks)
import SIEM.pages.investigate   # noqa: F401  (registers _select_detection)
import SIEM.pages.assistant     # noqa: F401  (registers the chat callbacks)
import SIEM.pages.database      # noqa: F401  (registers several callbacks)
import SIEM.pages.threat_intel  # noqa: F401  (registers several callbacks)

import SIEM.layout         # noqa: F401  (sets app.layout, registers nav callbacks)

__all__ = ["app"]
