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

# Dependencies first, in layers that depend only on pyproject.toml, so editing
# code later rebuilds in seconds instead of re-downloading everything.
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip
# CPU-only torch: the CPU image cannot use CUDA, and the CUDA wheel adds several GB.
# Installed first, so the next step sees torch as already satisfied.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))" > /tmp/requirements.txt \
    && pip install --no-cache-dir -r /tmp/requirements.txt

# Opt-in: the on-device model needs llama-cpp-python, which has no wheels and
# compiles from source (several minutes). Off by default so the image stays lean.
ARG WITH_LOCAL_MODEL=0
RUN if [ "$WITH_LOCAL_MODEL" = "1" ]; then pip install --no-cache-dir llama-cpp-python; fi

# Now the full source, installed EDITABLE like the native door. Paths in the code
# (config.yaml, data/, the account DB) resolve relative to the source tree, so
# they must land in /app where compose mounts them -- a normal install would
# resolve them inside site-packages and miss the mounted volume.
COPY . .
RUN pip install --no-cache-dir -e . --no-deps

# HF model cache lives on a mounted volume (see docker-compose.yml) so weights
# download once, never into the image.
ENV HF_HOME=/app/data/hf-cache

# Picks honeypot vs dashboard from the SERVICE env var (set by compose).
ENTRYPOINT ["bash", "docker/entrypoint.sh"]
