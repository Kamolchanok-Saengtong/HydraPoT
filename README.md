# HydraPoT
# 🍯 HydraPoT

**An Intelligent Honeypot Framework Using Large Language Models for Interactive Attack Analysis**

HydraPoT is a multi-agent SSH honeypot that tricks attackers into thinking they're on a real Linux server. Every command typed by the attacker is routed to the best agent for a convincing response — a static emulator for fast simple commands, a local LLM for context-aware interactions, or a cloud LLM for the most dangerous obfuscated attacks.

> By Kamolchanok Saengtong

---

## What Does It Do?

When an attacker connects via SSH, HydraPoT:

1. **Accepts any password** — every login attempt is logged
2. **Scores each command** using Functional Impact (FI) scoring (0-4)
3. **Routes to the best agent** based on command complexity
4. **Generates realistic fake output** so the attacker stays engaged
5. **Logs everything** — commands, responses, timestamps, IPs, agent used
6. **Shows it all** on a real-time SIEM dashboard with world map

---

## Requirements

- **Python 3.10+**
- **NVIDIA GPU** with CUDA 12+ (for on-device LLM)
- **Docker** (for Cowrie container)
- **~8GB VRAM** minimum (for Qwen3.5-9B, Q5_K_M quantized GGUF)

---

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/Kamolchanok-Saengtong/HydraPoT.git
cd HydraPoT
```

### 2. Create virtual environment

```bash
python3 -m venv honeypot_new
source honeypot_new/bin/activate
pip install -e .
```

### 3. Start Cowrie (Docker)

```bash
# Pull and run the Cowrie container
sudo docker run -d --name cowrie -p 2222:2222 cowrie/cowrie
```

### 4. Run the setup wizard

```bash
hp init
```

This walks you through configuration:

```
╔══════════════════════════════════════════════════╗
║                                                  ║
║  Welcome to HydraPoT                             ║
║    Honeypot Framework Setup                      ║
║                                                  ║
╚══════════════════════════════════════════════════╝

╭─────────────────────── Review Configuration ───────────────────────╮
│    1       Hostname               <your choice, e.g. svr04>        │
│    2       OS                     <your choice, e.g. Ubuntu 22.04> │
│    3       Bind address           <your choice, e.g. 0.0.0.0:2223> │
│    4       Cowrie host:port       <your Cowrie container address>  │
│    5       On-device model        <any GGUF model you point to>    │
│    6       Cloud LLM              <any OpenAI-compatible provider> │
╰────────────────────────────────────────────────────────────────────╯
  📦 Plugins: 1 rule(s) loaded (crypto mining)
  📤 Exporters: 1 configured (edit in plugins/export/)
```

### 5. Run the honeypot

```bash
hp run
```

You should see:

```
[on_device] Ready.
[cowrie_agent] Connected.
[HydraPot] SSH server listening on 0.0.0.0:2223
```

### 6. Test it (from another terminal)

```bash
ssh root@localhost -p 2223
# password: anything
```

### 7. Open the dashboard

```bash
hp dashboard
```

Opens the SIEM dashboard (default `http://localhost:8050`, override with `hp dashboard --host --port`) with live session feed, world map, auth intelligence, and session replay.

---

## Daily Usage (Quick Reference)

Once everything is installed, here's the routine for using it day to day.

### 1. Activate the environment

Do this every time, in every new terminal, before running any `hp` command:

```bash
cd HydraPoT   # or wherever you cloned it
source honeypot_new/bin/activate
```

### 2. Make sure Cowrie is running

```bash
docker ps
```

If "cowrie" is not in the list, start it:

```bash
docker compose up -d
```

### 3. Run the honeypot

```bash
hp run
```

Wait for:

```
[on_device] Ready.
[cowrie_agent] Connected.
[HydraPot] SSH server listening on 0.0.0.0:2223
```

Keep this terminal open — closing it stops the honeypot.

### 4. Try it out (new terminal)

```bash
ssh root@localhost -p 2223
```

Any password works. Try commands like `ls`, `whoami`, `cat /etc/passwd`. Type `exit` to leave.

### 5. Watch the dashboard (new terminal)

```bash
hp dashboard
```

Then open `http://localhost:8050` in your browser.

### 6. Check logs from the terminal (optional)

```bash
hp logs              # recent commands
hp logs --auth       # recent login attempts
hp logs -n 50        # show 50 lines instead of the default
```

### Stopping everything

1. `Ctrl+C` in the `hp run` terminal
2. `Ctrl+C` in the `hp dashboard` terminal
3. Optional: `docker compose down`

### Troubleshooting

| Problem | Fix |
|---|---|
| `command not found: hp` | You forgot to activate the environment (step 1) |
| Dashboard is empty | No one has connected yet — try step 4 first |
| `hp run` can't connect to Cowrie | Cowrie container isn't running — see step 2 |
| On-device model takes a while to start | Normal — the model is loading into the GPU. Wait for `[on_device] Ready.` |

---

## How It Works

FI (Functional Impact) scoring and agent routing are **two independent things** — a command's FI level does not by itself send it to any particular agent.

```
Attacker ──SSH──▶ HydraPoT ──▶ Router
                                 │
                 ┌───────────────┴────────────────────┐
                 │                                     │
     obfuscated/indirect command?              ordinary command
   (mechanism-based detection in router.py,            │
    independent of FI — e.g. base64 payloads,   FI Scorer (0-4)
    /dev/tcp redirects, dynamic construction)           │
                 │                            routing.fi_routing in
                 ▼                             config.yaml decides the
             Cloud LLM                         agent per FI level —
                                                fully configurable
```

- **Cloud routing** is triggered by detecting that a command needs semantic reconstruction to know what it actually does — a fixed, mechanism-based check in `router.py`, not tied to FI score.
- **Everything else** is routed per FI level according to `config.yaml`'s `routing.fi_routing` map — you choose which agent (Cowrie / On-Device / Cloud) handles each FI level.
- FI score also independently controls which interactions get retained in cross-agent memory (`logging.fi_threshold`).

### FI Scoring (Functional Impact)

Every command gets a score from 0-4, used for routing decisions (via your configured `fi_routing` map) and memory retention:

| FI | Label | Examples |
|----|-------|----------|
| 0 | Read/Display | `whoami`, `ls`, `cat /etc/passwd` |
| 1 | Create/Install | `apt install nmap`, `wget`, `touch` |
| 2 | Modify/Navigate | `chmod`, `sed`, `mv` |
| 3 | Service/Elevate | `systemctl`, `nmap scan`, `sudo` |
| 4 | Impact/Delete | `passwd root`, `rm -rf /`, `useradd` |

### Agents

- **Cowrie** — Docker-based SSH emulator. Handles simple commands instantly (~100ms). No context, no memory.
- **On-Device LLM** — Any local GGUF model you point it to (`agents.on_device.model` in `config.yaml`). Handles context-dependent commands. Sees file state, installed packages, and interaction history.
- **Cloud LLM** — Any OpenAI-compatible API provider you configure (`agents.cloud` in `config.yaml`). Reserved for obfuscated/indirect commands that need semantic reconstruction to execute safely. Most capable but costs money.

### Cross-Agent State

When an attacker creates a file via Cowrie (`echo '#!/bin/bash' > scan.sh`), the on-device LLM can see it and execute it (`bash scan.sh`). A shared in-memory state register (`SYSTEM_STATE`) bridges all agents.

---

## Project Structure

```
HydraPoT/
├── main.py                 # Command routing and orchestration
├── ssh_server.py           # SSH server (asyncssh)
├── router.py               # Obfuscation detection (_is_cloud)
├── config.yaml             # Generated by hp init
├── config_loader.py        # Loads config into dataclass
├── setup_wizard.py         # Interactive setup (hp init)
├── dashboard.py            # Dash SIEM dashboard
├── hp.py                   # CLI entry point (hp run/init/dashboard)
│
├── agent_manager/
│   ├── cowrie_agent.py     # Paramiko SSH to Cowrie Docker
│   ├── ondevice_agent.py   # HuggingFace/GGUF model loader
│   └── static_handler.py   # Fake nmap/ping/traceroute output
│
├── prompt/
│   ├── fi_manager.py       # FI scoring + memory pruning
│   ├── prompt_manager.py   # Builds LLM prompts with state
│   └── templates/          # Editable prompt templates
│       ├── base_prompt.txt
│       ├── system_setting.txt
│       └── user_prompt.txt
│
├── plugins/                # Extensible plugin system
│   ├── plugin_loader.py    # Loads rules, static handlers, exporters
│   ├── rules/              # Custom FI detection rules (YAML)
│   │   └── crypto_mining.yml
│   ├── static/             # Custom fake command output (Python)
│   │   └── fake_docker.py
│   └── export/             # SIEM export configs (YAML)
│       └── syslog.yml
│
├── data/
│   ├── logs/
│   │   ├── sessions/       # Per-session command logs (JSON)
│   │   ├── impactful/      # FI >= 2 commands only
│   │   └── auth_log.json   # Login attempts + port scans
│   └── hostkey_asyncssh.key
│
└── evaluation/             # Research evaluation scripts (internal, not
    ├── fidelity.py         #   part of the installed package)
    ├── normalization.py    # Cosine, Sequence, BLEU, BERTScore, and more
    └── ...                 # cost/comparison scripts, etc.
```

---

## CLI Commands

```bash
hp init          # Run setup wizard
hp run           # Start the honeypot
hp dashboard     # Open SIEM dashboard
```

---

## Plugin System

HydraPoT is extensible. Drop files into the `plugins/` folder and restart.

### Custom FI Rules

Create a YAML file in `plugins/rules/` to add your own detection patterns:

```yaml
# plugins/rules/my_rules.yaml
name: My Custom Rules
author: your_name
version: 1.0

rules:
  - fi: 4
    description: "Crypto mining"
    patterns:
      - "xmrig"
      - "stratum\\+tcp://"
  - fi: 3
    description: "SSH key theft"
    patterns:
      - "cat ~/.ssh/id_rsa"
      - "cat /etc/shadow"
```

### SIEM Export

Configure forwarding to Splunk, Elasticsearch, or syslog in `plugins/export/`:

```yaml
# plugins/export/splunk.yaml
name: Splunk HEC Export
enabled: true
type: splunk_hec

connection:
  url: "https://splunk.company.com:8088/services/collector"
  token_env: "SPLUNK_HEC_TOKEN"

filters:
  min_fi: 0
  include_auth: true
```

### Custom Static Handlers

Write Python files in `plugins/static/` to fake output for any command:

```python
# plugins/static/fake_kubectl.py
COMMANDS = ["kubectl"]

def handle(cmd, write_fn):
    if "get pods" in cmd:
        return "NAME        READY   STATUS    AGE\nweb-app     1/1     Running   3d"
    return "error: unknown command"
```

---

## Dashboard

The SIEM dashboard shows:

- **Live session feed** — real-time commands with FI scores and agent routing
- **World map** — attacker geolocations (requires GeoIP mmdb file)
- **Auth intelligence** — top passwords, usernames, login attempts
- **Session explorer** — drill into any session with terminal replay
- **Agent distribution** — which agent handled what percentage of commands

---

## Configuration

Edit `config.yaml` directly or re-run `hp init`:

```yaml
honeypot:
  hostname: svr04           # Fake hostname shown to attackers
  os: Ubuntu 22.04 LTS      # OS banner
  host: 0.0.0.0             # Bind address (0.0.0.0 = all interfaces)
  port: 2223                # SSH port

agents:
  cowrie:
    host: 127.0.0.1
    port: 2222
  on_device:
    model: unsloth/Qwen3.5-4B-GGUF
    quantization: 4bit
    temperature: 0.1
  cloud:
    enabled: false           # Enable when ready, costs money

system_state:
  base_tools:                # Commands the honeypot always simulates as
    - ls, cat, cp, mv, rm     # available, no install-check needed — list
    - wget, curl, bash        # is yours, comma-separated per line
    # ... add more as needed
  starting_files:             # Pre-seeded file state (perms/size) shown
    /root/.bashrc:             # to attackers before they create anything
      perms: -rw-r--r--
      size: 3.7K
```

---

## Troubleshooting

**"Address already in use" on startup**
```bash
sudo fuser -k 2223/tcp
```

**Git push fails after running honeypot**
```bash
unset GIT_ASKPASS VSCODE_GIT_ASKPASS_MAIN VSCODE_GIT_ASKPASS_NODE
```

**Cowrie won't connect**
```bash
sudo docker ps -a              # Check if container is running
sudo docker start cowrie       # Start it if stopped
```

**Model won't load (CUDA error)**
```bash
export CUDA_HOME=/usr/local/cuda-12.4
export PATH=$CUDA_HOME/bin:$PATH
export LD_LIBRARY_PATH=$CUDA_HOME/lib64:$LD_LIBRARY_PATH
```

---

## License

This project is part of an academic thesis at Prince of Songkla University. See [`license`](license) for the full usage agreement (NSTDA National Software Contest disclaimer).