# ─────────────────────────────────────────────────────────────────────────────
# HydraPoT — CPU image (the "pull & run" default)
#
# Runs the Cowrie + Cloud arms out of the box. The on-device LLM arm is OFF by
# default (it needs a GPU) so this image runs on any laptop. For the on-device
# arm, build docker/Dockerfile.gpu instead (-> the hydrapot:gpu tag).
#
# This image is just your GitHub install wrapped in a sealed box: the same
# `pip install .` + the same `hp` command the native door uses. Nothing here
# changes the app — it only packages it.
#
#   docker build -f docker/Dockerfile -t hydrapot:latest .
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# OS-level build tools some wheels need. Removed in the same layer so they do
# not bloat the final image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the dependency manifest FIRST and install, before the source. Docker
# caches this layer, so editing code later rebuilds in seconds instead of
# re-installing every dependency.
COPY pyproject.toml ./
COPY README.md ./
# A minimal tree so `pip install .` can resolve the package metadata; the full
# source is copied in the next step. (setuptools reads pyproject at this point.)
RUN pip install --no-cache-dir --upgrade pip

# Now the full source, then the editable-equivalent install of the package.
COPY . .
RUN pip install --no-cache-dir .

# HF model cache lives on a mounted volume (see docker-compose.yml) so weights
# download once, never into the image.
ENV HF_HOME=/app/data/hf-cache

# Picks honeypot vs dashboard from the SERVICE env var (set by compose).
ENTRYPOINT ["bash", "docker/entrypoint.sh"]
