#!/usr/bin/env bash
# One image, several roles. docker-compose sets SERVICE to pick which one this
# container plays, so the honeypot and the dashboard share a single image
# instead of needing two.
#
# Note the --host 0.0.0.0: inside a container, 127.0.0.1 is only reachable from
# WITHIN the box. Binding 0.0.0.0 lets other containers and the host reach it.
set -euo pipefail

# A command given to the container wins over the role, so one-off tasks work:
#   docker-compose run --rm dashboard hp --dashboard-passwd
if [ "$#" -gt 0 ]; then
  exec "$@"
fi

case "${SERVICE:-honeypot}" in
  honeypot)
    # Fail with Docker-shaped advice, not the pip one the agent would print.
    python - <<'PY' || exit 1
import importlib.util, sys
from core.config_loader import load_config
o = load_config().agents.on_device
if o.enabled and o.mode == "local" and importlib.util.find_spec("llama_cpp") is None:
    print("\n[docker] agents.on_device is enabled (mode: local) but this image has no "
          "llama-cpp-python.\n  Pick one:\n"
          "    1. Build with it:   WITH_LOCAL_MODEL=1 docker-compose build\n"
          "       then fetch the model once:  docker-compose run --rm hydrapot hp --init\n"
          "    2. Run the model on a GPU host:  agents.on_device.mode: remote + base_url\n"
          "    3. Run without it:  agents.on_device.enabled: false\n", file=sys.stderr)
    sys.exit(1)
PY
    exec hp --run --host 0.0.0.0
    ;;
  dashboard)
    # Serves its internal port INSIDE the container so the proxy service in
    # front (compose's Caddy, or an org's own) can reach it over the Compose
    # network; hp only allows this inside the real dashboard container. TLS is
    # that proxy's job -- see proxy/README.md.
    exec hp --dashboard --foreground
    ;;
  *)
    # Any other value: run it as a raw command (handy for one-off tasks,
    # e.g. `docker compose run hydrapot bash`).
    exec "$@"
    ;;
esac
