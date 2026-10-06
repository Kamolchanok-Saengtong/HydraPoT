"""
console/ — HydraPoT's Plotly Dash dashboard, split into one module per
concern/page (see each module's own docstring).

Import order matters: modules register @app.callback / app.clientside_callback
as a side effect of being imported, and layout.py needs every page module's
build_*_page() already importable before it can set app.layout. So: shared
infra first (data/theme/cost/geo/ioc), then clientside JS, then each page
module, then layout.py last.
"""
from console.server import app

import console.theme          # noqa: F401  (sets app.index_string, defines colors)
import console.data           # noqa: F401  (TTL-cached data access)
import console.cost           # noqa: F401  (estimate_savings)
import console.geo            # noqa: F401  (registers update_geo_status)
import console.ioc            # noqa: F401  (build_ioc_snapshot)

import console.clientside     # noqa: F401  (registers 3 clientside callbacks)

import console.pages.live_feed     # noqa: F401  (registers _refresh_live_feed)
import console.pages.summary       # noqa: F401
import console.pages.mitre         # noqa: F401  (registers several callbacks)
import console.pages.investigate   # noqa: F401  (registers _select_detection)
import console.pages.assistant     # noqa: F401  (registers the chat callbacks)
import console.pages.database      # noqa: F401  (registers several callbacks)
import console.pages.threat_intel  # noqa: F401  (registers several callbacks)

import console.layout         # noqa: F401  (sets app.layout, registers nav callbacks)

__all__ = ["app"]
