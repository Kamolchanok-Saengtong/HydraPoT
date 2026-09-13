"""
SIEM/server.py — the Dash app object, and nothing else.

Every other SIEM/ module does `from SIEM.server import app` to register its
own callbacks. Keeping the bare app object in its own module (rather than in
layout.py or __init__.py) is what avoids circular imports: page modules need
`app` to exist before they can decorate a function with @app.callback, and
layout.py needs every page module's build_*_page() function already
importable — if `app` lived in either of those, importing it would require
importing the very modules that need to import it first.
"""
import os

from dash import Dash

# Dash resolves its default assets_folder relative to __name__'s module --
# that used to be fine when the Dash() call lived in root-level dashboard.py,
# but here __name__ is "SIEM.server", so the default would look for
# SIEM/assets/ instead of the real assets/ at the project root (favicon,
# hydrapot_logo.png). Point it there explicitly instead.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Dash(__name__, suppress_callback_exceptions=True,
           assets_folder=os.path.join(_ROOT, "assets"))
app.title = "HydraPoT"
