<p align="center">
  <a href="https://hydrapot.vercel.app/page.html">
    <img src="assets/demo_button.png" alt="HydraPoT — try the live demo" width="440">
  </a>
</p>

![CI](https://github.com/Kamolchanok-Saengtong/HydraPoT/actions/workflows/ci.yml/badge.svg?branch=main)
![Dependencies](https://github.com/Kamolchanok-Saengtong/HydraPoT/actions/workflows/dependencies.yml/badge.svg?branch=main)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Last Commit](https://img.shields.io/github/last-commit/Kamolchanok-Saengtong/HydraPoT)
[![License](https://img.shields.io/badge/license-MIT-green)](./license)
![Research](https://img.shields.io/badge/type-research-blue)
![Peer Review](https://img.shields.io/badge/peer%20review-in%20progress-orange)
![Publication](https://img.shields.io/badge/publication-in%20progress-orange)

**A Configurable Multi-Agent Framework for Cost-Aware LLM-Assisted Honeypots**

HydraPoT is an SSH honeypot that answers attacker commands using three
different responders: a static emulator, a local language model, and a cloud
language model. Each command is routed to one of them according to how much
interaction it implies, so that cheap commands are answered cheaply and only
demanding commands reach a paid model.

> By Kamolchanok Saengtong

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API](#api)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Limitations](#limitations)
- [Threat Intelligence Sources and Attribution](#threat-intelligence-sources-and-attribution)
- [License](#license)

## Overview

A traditional low-interaction honeypot answers from a fixed script, which is
cheap but easy to detect. A honeypot backed entirely by a large language model
is more convincing but costs money for every command, including trivial ones.

HydraPoT sits between the two. Each incoming command is scored, and the score
selects a responder. A shared session state is kept across responders, so the
attacker sees one consistent machine even though different components answered
different commands.

The project is research software written for a thesis. Some components are
complete and usable; others are experiments that are not connected to the
running system. The [Features](#features) and [Limitations](#limitations)
sections say which is which.

## Features

| Feature | Description | Status |
|---|---|---|
| SSH honeypot | Interactive SSH server that records every session | Available |
| Three responders | Cowrie (static), local GGUF model, cloud model | Available |
| Score-based routing | Routes each command to a responder by its score | Available |
| Shared session state | Keeps one consistent machine across responders | Available |
| SQLite storage | Sessions, commands, responses, authentication attempts | Available |
| Web dashboard | Browsable sessions, sources, geolocation, SQL console | Available |
| REST API | 16 read-only endpoints under `/api/v1` | Available |
| Event WebSocket | `/ws/events` pushes new events to connected clients | Available |
| Threat intelligence | IOC extraction, MITRE ATT&CK mapping, detection rules, alerts | Available |
| Setup wizard | Interactive configuration generator | Available |
| Prompt-injection guardrail | Sanitises prompts, fences attacker text, checks replies | Off by default in v1.0.0 |
| Reinforcement-learning router | Replaces the score-based policy with a learned one | Experimental, not connected |
| Model fine-tuning | LoRA training scripts for the local responder | Development only |

The guardrail is wired in but shipped **off**: the published results were
produced before it existed, so `config.yaml` sets `guardrail.enabled: false`
and the honeypot behaves as measured. Turn it on to use it.

The reinforcement-learning router is not connected at all -- nothing outside
`honeyrouter/` imports it. Routing uses `routing.fi_routing` from
`config.yaml`.

## Architecture

```
attacker
   │  SSH
   ▼
core/ssh_server.py ─► shell/session.py ─► core/router.py
                                          │
                        ┌─────────────────┼─────────────────┐
                        ▼                 ▼                 ▼
                 cowrie (Docker)     local model       cloud model
                        └─────────────────┼─────────────────┘
                                          ▼
                                  core/storage.py (SQLite)
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
                 threat_intel/                  api/api_server.py
            IOC, MITRE, detection, alerts        REST API + dashboard
```

`main.py` connects these components and holds no honeypot behaviour itself.
Command handling lives in `shell/`, and the choice of responder in
`core/router.py`.

The dashboard is a Dash application mounted underneath FastAPI, so the web UI
and the REST API are served by one process on one port.

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.10 or newer | Declared in `pyproject.toml` |
| Docker | Only for the Cowrie responder; Compose v1 or v2 |
| A GGUF model file | Only for the local responder; downloaded by the setup wizard |
| An API key | Only for the cloud responder; read from an environment variable |

All Python dependencies are declared in `pyproject.toml` and installed by
`pip`. There is no `requirements.txt`.

`llama-cpp-python` is not installed by default -- see the optional extra under
[Installation](#installation). `bitsandbytes` is installed on Linux only; it
provides CUDA quantisation, which has no macOS equivalent.

Each responder is optional. Setting `enabled: false` for a responder in
`config.yaml` means its dependencies are not exercised at runtime.

## Installation

```bash
git clone https://github.com/Kamolchanok-Saengtong/HydraPoT.git
cd HydraPoT

python -m venv .venv
source .venv/bin/activate

pip install -e .
```

This installs the honeypot, the dashboard, and the cloud responder. It needs no
compiler and works on Linux and macOS.

### Optional: the local GGUF responder

The on-device responder needs `llama-cpp-python`, which publishes no wheels and
is always compiled from source:

```bash
pip install -e ".[local-model]"
```

That requires a C++ toolchain:

| Platform | Command |
|---|---|
| macOS | `xcode-select --install` |
| Debian/Ubuntu | `sudo apt install build-essential cmake` |
| NVIDIA GPU | `CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python` |

Without it, set `agents.on_device.enabled: false` in `config.yaml`; Cowrie and
the cloud responder cover every command.

This registers the `hp` command. Confirm it:

```bash
hp --version
```

To use the Cowrie responder, start its container:

```bash
docker-compose up -d          # Compose v2: docker compose up -d
```

Cowrie binds `127.0.0.1:2222` and runs with its own built-in filesystem. No
generated file is required, so this works immediately after cloning.

### Using your own filesystem in Cowrie

By default Cowrie shows its stock filesystem, which does not match the
hostname, operating system and files declared in `config.yaml`. To make the
container match:

```bash
python plugins/cowrie_fs.py
docker-compose down && docker-compose up -d
```

This writes `plugins/cowrie/fs.pickle`, the identity files under
`plugins/cowrie/honeyfs/`, and `docker-compose.override.yml`, which Compose
merges automatically. Deleting the override returns the container to stock
Cowrie.

Re-run the same command after changing the honeypot's identity or declared
files in `config.yaml`.

## Configuration

Configuration lives in `config.yaml` at the project root. Generate it
interactively:

```bash
hp --init
```

The file can also be edited directly. Re-running the wizard keeps values that
were edited by hand, unless the declared operating system changes, in which
case the values derived from it are regenerated.

### Main options

| Key | Description | Example |
|---|---|---|
| `honeypot.hostname` | Hostname shown to the attacker | `psu` |
| `honeypot.os` | Operating system the honeypot claims to run | `Ubuntu 22.04 LTS` |
| `honeypot.host` | Address the SSH server binds | `127.0.0.1` |
| `honeypot.port` | Port the SSH server binds | `2223` |
| `honeypot.instance_name` | Name for this sensor, shown in the dashboard | `default` |
| `agents.cowrie.enabled` | Use the Cowrie container | `true` |
| `agents.cowrie.port` | Where Cowrie listens | `2222` |
| `agents.on_device.enabled` | Use the local model | `true` |
| `agents.on_device.model` | Hugging Face repository of the local model | `unsloth/Qwen3.5-4B-GGUF` |
| `agents.on_device.gguf_file` | Weight file inside that repository | `Qwen3.5-4B-Q4_K_M.gguf` |
| `agents.cloud.enabled` | Use the cloud model | `true` |
| `agents.cloud.provider` | Cloud provider | `openai` |
| `agents.cloud.model` | Model name at that provider | `your-model-name` |
| `agents.cloud.base_url` | API endpoint, for OpenAI-compatible providers | `https://api.example.com/v1` |
| `routing.fi_routing` | Responder for each score from 0 to 4 | see below |
| `routing.fallback` | Responder used when the chosen one fails | `cowrie` |
| `logging.fi_threshold` | Minimum score for a session to be kept as notable | `2` |
| `logging.retention_days` | Delete records older than this; `0` disables | `0` |

### Routing

Each command receives a score from 0 to 4. `routing.fi_routing` maps each
score to a responder:

```yaml
routing:
  fi_routing:
    0: cowrie
    1: cowrie
    2: on_device
    3: on_device
    4: cloud
  fallback: cowrie
```

Commands that imply little interaction go to the static responder; commands
that imply the most go to the cloud model. Changing this mapping changes the
cost and the realism of the honeypot together.

### API key

Secrets are never stored in `config.yaml`. They are read from `.env` at the
project root, or from the real environment, under fixed names:

| Variable | Used by |
|---|---|
| `CLOUD_AGENT_API_KEY` | the cloud responder |
| `AI_API_KEY` | the AI Security Analyst |
| `HYDRAPOT_API_KEY` | the REST API, when you want it authenticated |

```bash
cp .env.example .env
$EDITOR .env
```

A real environment variable overrides a line in `.env`, so a systemd unit or
container secret always wins.

## Usage

The `hp` command takes flags only. There are no subcommands, and exactly one
action flag may be given per invocation.

| Flag | Action |
|---|---|
| `hp --init` | Run the setup wizard |
| `hp --run` | Start the honeypot |
| `hp --dashboard` | Start the dashboard in the background |
| `hp --dashboard-stop` | Stop the background dashboard |
| `hp --config` | Show the active configuration |
| `hp --version` | Show the version |

### Basic workflow

```bash
hp --init            # 1. configure
docker-compose up -d # 2. start Cowrie, if enabled
hp --run             # 3. start the honeypot
hp --dashboard       # 4. inspect results
```

Connect to the honeypot as an attacker would, using the address and port set
in `config.yaml`:

```bash
ssh root@127.0.0.1 -p 2223
```

The dashboard reads the database directly. It shows previously collected data
whether or not the honeypot is currently running.

### Dashboard options

| Flag | Default | Purpose |
|---|---|---|
| `--port` | `8050` | Port to serve on |
| `--host` | `127.0.0.1` | Address to bind |
| `--foreground` | off | Run in the terminal instead of the background |
| `--debug` | off | Enable the Flask reloader |
| `--i-accept-public-exposure` | off | Required to bind a non-loopback address |

The dashboard has no authentication and includes a read-only SQL console over
the capture database, which contains every credential and address the honeypot
collected. It therefore binds loopback only. To view it from another machine,
use an SSH tunnel rather than exposing the port:

```bash
ssh -N -L 8050:127.0.0.1:8050 user@sensor-host
```

Then open `http://localhost:8050` locally.

## API

The REST API is served by the same process as the dashboard, under
`/api/v1`. All endpoints are read-only and unauthenticated, and are reachable
wherever the dashboard is bound.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/health` | Component status and dependency checks |
| GET | `/api/v1/capabilities` | Which features are enabled |
| GET | `/api/v1/overview` | Summary counts and recent sessions |
| GET | `/api/v1/sessions` | List sessions |
| GET | `/api/v1/sessions/{session_id}` | One session with its commands |
| GET | `/api/v1/sources/{ip}` | Activity from one source address |
| GET | `/api/v1/alerts` | List alerts |
| GET | `/api/v1/alerts/{alert_id}` | One alert |
| GET | `/api/v1/detections` | List detections |
| GET | `/api/v1/detections/{detection_id}` | One detection |
| GET | `/api/v1/correlations/{correlation_id}` | One correlation |
| GET | `/api/v1/threats/iocs` | Extracted indicators of compromise |
| GET | `/api/v1/threats/iocs/{ioc}` | One indicator |
| GET | `/api/v1/threats/mitre` | MITRE ATT&CK techniques observed |
| GET | `/api/v1/threats/mitre/{technique_id}` | One technique |
| GET | `/api/v1/export` | Export collected data |

A WebSocket at `/ws/events` pushes new events as they are recorded.

```bash
curl http://127.0.0.1:8050/api/v1/health
```

## Project Structure

```
HydraPoT/
├── main.py              wires the running system together
├── config.yaml          configuration
├── core/                the honeypot itself
│   ├── ssh_server.py      listens for SSH connections
│   ├── router.py          chooses a responder for each command
│   ├── storage.py         SQLite layer
│   └── config_loader.py   reads config.yaml and .env
├── cli/                 the `hp` command and the setup wizard
├── shell/               command handling and session state
├── agent_manager/       the three responders
├── prompt/              prompt templates for the language models
├── plugins/             scoring rules, static handlers, Cowrie filesystem
├── cost/                API billing and GPU electricity
├── threat_intel/        IOC extraction, MITRE mapping, detection, alerts
├── SIEM/                dashboard pages and geolocation
├── api/                 REST API and the FastAPI host
├── guardrail/           prompt-injection defences (off by default)
├── honeyrouter/         reinforcement-learning router (not connected)
├── finetuning/          LoRA training scripts
├── deploy/              systemd unit templates
├── tools/               maintenance scripts
└── tests/               test suite
```

## Troubleshooting

### The dashboard says "No data yet"

The database contains no sessions. This is expected on a new installation and
does not indicate that the dashboard is broken. Run the honeypot and connect
to it once.

If the database should contain data, check that you are running `hp` from the
project directory, since the database path is resolved relative to it.

### Port already in use

The SSH server, Cowrie and the dashboard use separate ports, set in
`config.yaml` and by `hp --dashboard --port`. If the dashboard fails to start,
check for an existing instance:

```bash
hp --dashboard-stop
```

### The dashboard refuses to bind an address

Binding anything other than a loopback address requires
`--i-accept-public-exposure`, because the dashboard is unauthenticated. Use an
SSH tunnel instead where possible.

### The world map is empty

The geolocation database is downloaded automatically when the dashboard
starts, and requires network access. An empty map usually means that download
did not complete.

### The cloud responder is disabled at runtime

The key is read from the environment variable named in
`agents.cloud.api_key_env`, not from `config.yaml`. Confirm it is exported in
the shell that runs `hp --run`.

## Development

### Checking dependencies

Every third-party import must be declared in `pyproject.toml`. A package that
is imported but not declared works on a machine where something else installed
it, and fails on a fresh clone. `deptry` checks this:

```bash
pip install deptry
deptry .
```

Expected output when the project is consistent:

```
Success! No dependency issues found.
```

| Code | Meaning |
|---|---|
| `DEP001` | Imported, but no package provides it |
| `DEP002` | Declared in `pyproject.toml`, never imported |
| `DEP003` | Imported, but only present as another package's dependency |

`DEP003` is the important one: the import works today only because another
package happened to install it, and breaks as soon as that package changes its
own requirements.

Configuration is in `pyproject.toml` under `[tool.deptry]`. It requires no
dependencies to be installed, so it gives the same result on a developer
machine and on a CI runner.

### Continuous integration

Two workflows run on every push. They are separate files because a GitHub
status badge covers a whole workflow, not a single job, so the dependency
check needs its own file to have its own badge.

| Workflow | Job | Checks |
|---|---|---|
| `ci.yml` | `syntax-check` | Every Python file compiles |
| `ci.yml` | `dashboard-boot` | The dashboard installs, starts, and serves requests |
| `dependencies.yml` | `deptry` | No imported package is undeclared |

The badges at the top of this file report their current status.

The GPU stack is never installed in CI. `.github/workflows/ci_deps.py` reads
the dependency list from `pyproject.toml` and removes the packages a standard
runner cannot build.

### Tests

The test suite is in `tests/` and requires `pytest`, which is not part of the
declared dependencies:

```bash
pip install pytest
pytest tests/
```

### Running as a service

`tools/install_service.py` renders systemd units from the templates in
`deploy/`:

```bash
python tools/install_service.py --user --print
```

The script prints the installation commands rather than running them.

## Limitations

- **The guardrail is off by default.** It is wired into `prompt/prompt_manager.py`
  and `shell/session.py`, but `config.yaml` ships it disabled so the honeypot
  matches the published results.
- **The reinforcement-learning router is not connected.** `honeyrouter/`
  replays recorded sessions offline. The running system uses the score-based
  policy in `core/router.py`.
- **The dashboard has no authentication.** It exposes a read-only SQL console
  over collected credentials, and binds loopback only for that reason.
- **The REST API has no authentication.** It is reachable wherever the
  dashboard is bound.
- **The test suite has not been verified in this documentation.** `pytest` is
  not a declared dependency, and the tests were not run while writing this
  README.
- **`torch` is always installed**, even when only the dashboard will be used.
  Only `llama-cpp-python` has been made optional so far.
- **Cowrie requires Docker.** There is no alternative static responder.

## Threat Intelligence Sources and Attribution

HydraPoT implements a dedicated Threat Intelligence feature that leverages
established and trusted open-source cybersecurity resources to enhance its
attack analysis capabilities.

The feature integrates threat intelligence from **SigmaHQ, MISP, and MITRE**
to support attack pattern detection, MITRE ATT&CK technique identification,
IOC filtering, and security analytics evaluation.

### Threat Intelligence Sources

| Threat Intelligence Source | HydraPoT Implementation | Purpose | Local Path |
|---|---|---|---|
| **[SigmaHQ Rules](https://github.com/SigmaHQ/sigma)** | Sigma rule integration | Detects suspicious attack patterns and supports mapping observed attacker behavior to relevant techniques. | `threat_intel/rules/upstream/` |
| **[MISP Warninglists](https://github.com/MISP/misp-warninglists)** | IOC filtering | Identifies known benign or commonly observed indicators to reduce false positives during IOC extraction and analysis. | `threat_intel/.fp_cache/` |
| **[MITRE CAR Analytics](https://github.com/mitre-attack/car)** | Offline validation reference | Provides security analytics that support the evaluation and validation of HydraPoT's threat detection and technique-tagging results. | `threat_intel/.car_cache/` |
| **[MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data)** | ATT&CK metadata catalog | Provides standardized technique and tactic metadata used for threat analysis, classification, and reporting. | `threat_intel/mitre_catalog.json` |
| **[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)** | Ground truth for rule evaluation | Provides red-team test commands with a known technique label, used as independent ground truth when measuring the accuracy of HydraPoT's ATT&CK mapping. | fetched by `threat_intel/validate_rules.py` |
| **[IANA TLD List](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)** | Domain validation | Authoritative list of valid top-level domains, used to reject non-existent domains during IOC extraction. | `threat_intel/.fp_cache/tlds.txt` |


### Scope of Use

To make the boundary explicit, the following describes precisely how each
resource is used and what remains HydraPoT's own work.

**ATT&CK technique mapping**

| Component | Origin |
|---|---|
| 180 upstream detection rules (`threat_intel/rules/upstream/`) | SigmaHQ |
| 39 detection rules (`threat_intel/rules/local_custom/`) | **HydraPoT** — authored for this project, written in Sigma's schema. They are not SigmaHQ rules. |
| Two-tier resolution (upstream consulted first, local as fallback; `tag()` strict priority, `tag_all()` union) | **HydraPoT** |
| Technique IDs, names, tactics | MITRE ATT&CK |
| Accuracy measurement against labelled red-team commands | Atomic Red Team (ground truth) |
| Independent detection-theory cross-check | MITRE CAR — **validation only; CAR never produces a tag at runtime** |

**IOC extraction**

| Component | Origin |
|---|---|
| Observable patterns — URL, IPv4, IPv6, MD5/SHA1/SHA256, BTC/ETH/XMR wallet addresses, CVE, email, file paths | **HydraPoT** — the regex table in `threat_intel/ioc_extractor.py`. No external rule template is used for detection. |
| Extraction approach (a regex table per observable type) | Follows the design of Microsoft's [msticpy](https://github.com/microsoft/msticpy) `IoCExtract`. **msticpy is not a dependency and is not installed.** |
| False-positive suppression | MISP Warninglists + IANA TLD list |
| STIX 2.1 export (indicator, attack-pattern, identity, malware, relationship objects) | **HydraPoT** |

Only benign-listing sources are consulted. No external malicious-indicator
feed is used, so every positive detection produced by HydraPoT originates from
its own rules.

### Attribution & Acknowledgements

The HydraPoT Threat Intelligence feature builds upon the valuable work of the
open-source cybersecurity community. We gratefully acknowledge and thank the
maintainers and contributors of the following projects for providing the
security resources used by HydraPoT:

- **SigmaHQ** — for the [Sigma](https://github.com/SigmaHQ/sigma) detection
  rule format and community-maintained detection rules.

- **MISP Project** — for the
  [MISP Warninglists](https://github.com/MISP/misp-warninglists), which help
  identify commonly observed or non-actionable indicators and reduce potential
  false positives.

- **MITRE** — for the
  [Cyber Analytics Repository (CAR)](https://github.com/mitre-attack/car),
  which provides security analytics used as a reference for evaluating
  defensive detection capabilities.

- **MITRE** — for the
  [ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data),
  which provides structured MITRE ATT&CK knowledge used to construct
  HydraPoT's local technique catalog.

- **Red Canary** — for
  [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), whose
  labelled test commands make an independent, reproducible accuracy
  measurement of technique mapping possible.

- **IANA** — for the publicly maintained
  [TLD list](https://data.iana.org/TLD/tlds-alpha-by-domain.txt), used to
  validate extracted domain indicators.

- **Microsoft** — for [msticpy](https://github.com/microsoft/msticpy), whose
  `IoCExtract` informed the design of HydraPoT's IOC extraction. No msticpy
  code is used.

We sincerely thank the respective maintainers and contributors for making
these resources openly available to the cybersecurity community. Their work
provides an important foundation for HydraPoT's threat intelligence and
attack analysis capabilities.

> **Attribution Notice:** The original rules, analytics, datasets, and
> associated intellectual property remain with their respective authors,
> contributors, and organizations. HydraPoT does not claim ownership of these
> third-party resources, and their inclusion does not imply endorsement,
> affiliation, or ownership by HydraPoT. Please refer to each upstream
> repository for the applicable license, attribution requirements, and terms
> of use.

## License

MIT. See [license](./license).
