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

Runs Cowrie + the Cloud arm. The CPU image has no on-device model, so set
`agents.on_device.enabled: false` in `config.yaml` first — otherwise the
honeypot container stops at startup and prints your options.

```bash
cp .env.example .env         # paste your cloud API key(s) into .env
docker compose up            # starts cowrie + honeypot + dashboard + TLS proxy
docker compose run --rm dashboard hp --dashboard-passwd    # create the operator login
```

- Dashboard: **https://localhost** (HTTPS only; port from `HTTPS_PORT`, default 443).
  Caddy's internal CA signs the certificate, so the browser warns once. Set
  `TLS_SITE` in `.env` to your hostname to use your own name and certificate.
- Edit `config.yaml`, then `docker compose restart` to apply changes.
- Services restart on their own after a crash or a host reboot.
- The dashboard hides sessions from private and loopback source IPs by default,
  treating them as experiment traffic. On a LAN or lab sensor, where private
  addresses are the real attackers, set `dashboard.show_private_sources: true`
  in `config.yaml`.

### On-device model on CPU

Build the CPU image with the model runtime, then put the model in the cache volume:

```bash
WITH_LOCAL_MODEL=1 docker compose build     # compiles llama-cpp-python (minutes)
# set agents.on_device.enabled: true, then start as above
```

A 9B model on CPU answered in about 60 s per command on a 16-core host, so an
attacker would see a hang. Use the GPU image, `agents.on_device.mode: remote`
pointing at a GPU host, or a smaller model.

Secrets (API keys) live in `.env` and are passed at runtime — they are **never**
baked into the image (see `docker/.dockerignore`).

---

## Full / research variant (GPU — on-device arm on)

Needs an NVIDIA GPU and the NVIDIA Container Toolkit on the host. The overlay
builds the CUDA image and passes the GPU to the honeypot; the rest of the stack
is unchanged.

```bash
# set agents.on_device.enabled: true in config.yaml, then:
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up --build
```

The agent offloads every layer to the GPU (`n_gpu_layers=-1`), so the model
must fit in VRAM. The first build compiles llama-cpp-python with CUDA and
needs roughly 10 GB of disk. Model weights download once at runtime into the
`hf-cache` volume, not into the image.

---

## What's in this folder

| file | role |
|---|---|
| `Dockerfile` | CPU image (`hydrapot:latest`) — the default |
| `Dockerfile.gpu` | GPU image (`hydrapot:gpu`) — adds the on-device arm; used via `docker-compose.gpu.yml` |
| `.dockerignore` | keeps secrets + large data OUT of the image |
| `entrypoint.sh` | one image, picks honeypot vs dashboard via `SERVICE` |
| `README.md` | this file |
