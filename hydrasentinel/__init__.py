"""
hydrasentinel/ — HydraPoT's Plotly Dash dashboard, split into one module per
concern/page (see each module's own docstring).

Import order matters: modules register @app.callback / app.clientside_callback
as a side effect of being imported, and layout.py needs every page module's
build_*_page() already importable before it can set app.layout. So: shared
infra first (data/theme/cost/geo/ioc), then clientside JS, then each page
module, then layout.py last.
"""
from hydrasentinel.server import app

import hydrasentinel.theme          # noqa: F401  (sets app.index_string, defines colors)
import hydrasentinel.data           # noqa: F401  (TTL-cached data access)
import hydrasentinel.cost           # noqa: F401  (estimate_savings)
import hydrasentinel.geo            # noqa: F401  (registers update_geo_status)
import hydrasentinel.ioc            # noqa: F401  (build_ioc_snapshot)

import hydrasentinel.clientside     # noqa: F401  (registers 3 clientside callbacks)

import hydrasentinel.pages.live_feed     # noqa: F401  (registers _refresh_live_feed)
import hydrasentinel.pages.summary       # noqa: F401
import hydrasentinel.pages.mitre         # noqa: F401  (registers several callbacks)
import hydrasentinel.pages.investigate   # noqa: F401  (registers _select_detection)
import hydrasentinel.pages.assistant     # noqa: F401  (registers the chat callbacks)
import hydrasentinel.pages.database      # noqa: F401  (registers several callbacks)
import hydrasentinel.pages.threat_intel  # noqa: F401  (registers several callbacks)

import hydrasentinel.layout         # noqa: F401  (sets app.layout, registers nav callbacks)

__all__ = ["app"]
