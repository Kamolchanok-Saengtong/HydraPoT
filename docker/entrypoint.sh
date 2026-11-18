#!/usr/bin/env bash
# One image, several roles. docker-compose sets SERVICE to pick which one this
# container plays, so the honeypot and the dashboard share a single image
# instead of needing two.
#
# Note the --host 0.0.0.0: inside a container, 127.0.0.1 is only reachable from
# WITHIN the box. Binding 0.0.0.0 lets other containers and the host reach it.
set -euo pipefail

case "${SERVICE:-honeypot}" in
  honeypot)
    exec hp --run --host 0.0.0.0
    ;;
  dashboard)
    exec hp --dashboard --host 0.0.0.0
    ;;
  *)
    # Any other value: run it as a raw command (handy for one-off tasks,
    # e.g. `docker compose run hydrapot bash`).
    exec "$@"
    ;;
esac
