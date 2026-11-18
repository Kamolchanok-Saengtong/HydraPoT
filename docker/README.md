# Running HydraPoT with Docker

HydraPoT has **two front doors onto one codebase** — pick by what you want to do:

| | GitHub clone | Docker |
|---|---|---|
| **For** | reading / editing / extending the code, re-running experiments | deploying a working honeypot with zero setup |
| **How** | `pip install -e .` then `hp --run` | `docker compose up` |
| **Needs** | a Python 3.10+ env (GPU for on-device) | just Docker |

Both run the **same `main.py`** and — critically — the **same `config.yaml`**.

---

## config.yaml is the single source of truth

This is the rule that keeps the two doors from diverging. **Neither door
configures HydraPoT by changing code or rebuilding an image** — both read
`config.yaml`:

- GitHub: the `config.yaml` in your working tree.
- Docker: that **same file, mounted** into the container read-only
  (`./config.yaml:/app/config.yaml:ro`).

To change the model, routing, FI bands, or which arms are enabled, you **edit
`config.yaml` and restart** — never rebuild. The on-device arm is toggled by
`agents.on_device.enabled` in config, so even the CPU and GPU images differ only
in what they *can* run, not in how they are configured.

---

## Quickstart (CPU — no GPU needed)

Runs Cowrie + the Cloud arm. On-device is off by default.

```bash
cp .env.example .env         # paste your cloud API key(s) into .env
docker compose up            # starts cowrie + honeypot + dashboard
```

- Dashboard: http://localhost:8050
- Edit `config.yaml`, then `docker compose restart` to apply changes.

Secrets (API keys) live in `.env` and are passed at runtime — they are **never**
baked into the image (see `docker/.dockerignore`).

---

## Full / research variant (GPU — on-device arm on)

Needs an NVIDIA GPU and the NVIDIA Container Toolkit.

```bash
docker build -f docker/Dockerfile.gpu -t hydrapot:gpu .
# set agents.on_device.enabled: true in config.yaml, then run with the GPU:
#   docker run --gpus all ... hydrapot:gpu
```

Model weights download once at runtime into the `hf-cache` volume — not into the
image.

---

## What's in this folder

| file | role |
|---|---|
| `Dockerfile` | CPU image (`hydrapot:latest`) — the default |
| `Dockerfile.gpu` | GPU image (`hydrapot:gpu`) — adds the on-device arm |
| `.dockerignore` | keeps secrets + large data OUT of the image |
| `entrypoint.sh` | one image, picks honeypot vs dashboard via `SERVICE` |
| `README.md` | this file |
