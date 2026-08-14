# HydraPoT — Architecture

How the pieces fit together, as the code actually stands today.

HydraPoT is an SSH honeypot that fakes a Linux box convincingly enough to keep an
attacker talking. It does that by routing each command to one of three backends
of increasing cost and capability, and by carrying two kinds of memory between
commands so the fake machine stays self-consistent.

---

## 1. The ten-second version

```
attacker
   │  ssh root@host
   ▼
ssh_server.py ───────────────► auth attempt ──► SQLite (auth)
   │  per-session shell
   ▼
main.py  make_command_handler()          ← the core of the system
   │
   ├─ 1. static?      static_handler.py   nmap/ping/top → canned output, no LLM
   ├─ 2. deterministic? main.py handlers  cd/chmod/mkdir/cat/apt → computed from state
   ├─ 3. router.py classify(cmd)          pick an agent
   │        ├── cowrie      (real Cowrie container, cheap, real shell)
   │        ├── on_device   (local GGUF model, ~6 s)
   │        └── cloud       (DeepSeek API, ~1–2 s, costs money)
   │
   ├─ 4. prompt_manager builds the prompt  ← injects SRi + H_i
   ├─ 5. agent answers
   └─ 6. update SRi, H_i, FI log, MITRE tag
            │
            ▼
        SQLite (sessions, impactful)
            │
            ▼
     dashboard.py / hp / replay.py
```

Everything production writes goes into **one SQLite file**:
`data/logs/hydrapot.db`. Nothing writes JSON logs any more.

---

## 2. File map

### Entry points

| File | Role |
|---|---|
| `hp.py` | The CLI. `hp run`, `hp dashboard`, `hp logs`, `hp intel`, `hp init`, `hp config`. Everything a user touches. |
| `main.py` | **The core.** `make_command_handler()` builds the per-session closure that decides what every command does. The biggest and most important file. |
| `ssh_server.py` | asyncssh frontend. Accepts connections, fakes the login, records auth attempts, hands each session a command handler from `main.py`. |
| `dashboard.py` | Plotly Dash web UI on `:8050`. Three pages: Summary, Threat Intel, MITRE ATT&CK. |
| `replay.py` | Terminal replay of a recorded session, with typing animation. Reads SQLite. |
| `setup_wizard.py` | The `hp init` interactive wizard (writes `config.yaml`). |

### The decision layer

| File | Role |
|---|---|
| `router.py` | `classify(cmd, history) -> "cowrie" \| "on_device" \| "cloud"`. See §4. |
| `prompt/fi_manager.py` | FI scoring (0–4) + `MemoryPruner`, which holds **H_i**. |
| `prompt/prompt_manager.py` | Assembles the system/user prompt, injecting SRi and H_i. |

### The agents

| File | Role |
|---|---|
| `agent_manager/cowrie_agent.py` | SSH client into a real Cowrie container. Genuine shell behaviour, no LLM. |
| `agent_manager/ondevice_agent.py` | Local model via `llama-cpp-python` (GGUF) or transformers. Slowest, free. |
| `agent_manager/cloud_agent.py` | OpenAI-compatible API (DeepSeek). Fastest good answers, costs money. |
| `agent_manager/static_handler.py` | Hand-written output for commands no LLM should ever be asked (`nmap`, `ping`, `top`, `vim`…). |

### Storage & support

| File | Role |
|---|---|
| `storage.py` | **The single data layer.** Schema, WAL setup, all inserts/queries, and the JSON→SQLite migrators. |
| `config_loader.py` | Loads `config.yaml` into typed objects, applies the per-sensor profile. |
| `geoip_fetch.py` | Downloads the DB-IP database for the dashboard's world map. |
| `plugins/plugin_loader.py` | Optional extras: extra FI rules, static commands, SIEM export (`plugins/export/syslog.yml`). |

### Threat intelligence

| File | Role |
|---|---|
| `threat_intel/ioc_extractor.py` | Pulls IPs/URLs/hashes/paths out of commands **and responses**. Exports JSON, CSV, STIX 2.1. |
| `threat_intel/mitre_mapper.py` | Tags commands with ATT&CK techniques. Detection rules are ours; technique names/tactics come from MITRE's official STIX. |
| `threat_intel/mitre_catalog.json` | Generated. Small runtime catalog distilled from the 46 MB STIX bundle. Rebuild: `python threat_intel/mitre_mapper.py --build`. |
| `threat_intel/alerting.py` | Multi-channel alerts (email/webhook), configured in `threat_intel/alerts.yml`. Disabled by default. |

---

## 3. What happens to one command

Inside `main.py`'s `make_command_handler()`, in order. **The first branch that
matches wins** — an LLM is the last resort, not the first.

1. **Static?** `static_handler.is_static(cmd)` → canned output. `nmap`, `ping`,
   `top`, `vim`… Things an LLM would either hallucinate badly or that need to
   animate.

2. **Deterministic?** `_needs_llm(cmd, base, state)` decides whether the answer
   can be *computed* from what we already know. `cd`, `chmod`, `mkdir`, `apt
   install`, `cat` of a file we've tracked — all answered from `SYSTEM_STATE`
   with no model call. This is where most of the consistency comes from: a
   computed answer can't contradict itself.

3. **Route it.** `router.classify()` picks an agent (§4).

4. **Build the prompt.** `PromptManager` injects both memories (§5).

5. **Ask the agent**, streaming output back to the attacker's terminal.

6. **Record.** Update `SYSTEM_STATE`, add to `MemoryPruner`, MITRE-tag the
   command, `storage.insert_command()`, and fire a SIEM event / alert if
   configured.

---

## 4. Routing

`router.classify()` runs these checks in order:

1. **Only one agent enabled?** Route everything there. No decision to make.
2. **`_is_cloud(cmd)`?** Obfuscation, decoding, reverse shells, pipe-to-interpreter,
   indirect execution → **cloud**. These need semantic reconstruction of intent,
   which is the one thing worth paying for.
3. **In `COWRIE_UNIMPLEMENTED`?** Commands Cowrie always fails on regardless of
   arguments → **on_device**. Deliberately *not* "the strongest agent": these are
   ordinary commands Cowrie just lacks, not obfuscation, so escalating to cloud
   would be an expensive mistake.
4. **Otherwise, FI band decides**, via `config.yaml`'s `fi_routing` table.

### FI bands (`prompt/fi_manager.py`)

| FI | Label | Typical |
|---|---|---|
| 0 | Read/Display | `ls`, `cat`, `whoami` |
| 1 | Create/Install | `touch`, `mkdir`, `apt install` |
| 2 | Modify/Navigate | `cd`, `chmod`, `mv` |
| 3 | Service/Download/Elevate | `wget`, `systemctl`, `sudo` |
| 4 | Impact/Delete/Passwd | `rm -rf`, `passwd` |

> **`fi_routing` is fully hand-editable in `config.yaml`.** This is the single
> knob that changes the honeypot's cost/quality balance, and `hp init` rewrites
> it — always check it before an experiment run.

---

## 5. The two memories — SRi and H_i

These are **different things** and the distinction matters.

|  | **SRi** — system state | **H_i** — impactful history |
|---|---|---|
| Lives in | `SYSTEM_STATE` dict in `main.py` | `MemoryPruner.buffer` in `fi_manager.py` |
| Holds | current *facts*: files, perms, installed packages, cwd | verbatim command/response transcript |
| Update | overwritten — only the latest truth | first-seen entry locked, never rewritten |
| Bounded by | nothing (facts are small) | `max_events`, `min_fi` (2) |
| Answers | "does `/tmp/x.sh` exist and is it executable?" | "what did the attacker already see me say?" |

`MemoryPruner` scores retention as `(0.7 * fi_weight) + (0.3 * recency_weight)`
(`fi_manager.py:166`) — high-impact and recent events survive; trivial old ones
get dropped once the buffer is full.

> **`max_events` differs between production and experiments.** `main.py:1407`
> calls `make_command_handler()` without `sri_max_events`, so production runs on
> the default **10**. `NSC/agents.py` passes **20** explicitly. If you compare a
> live session against a Part B/C result, this is one of the differences.

**Important:** `H_i` comes from the **in-memory buffer**, never from disk. The
`impactful` table is an audit log only — changing how it's stored cannot change
model behaviour or experiment results.

### `_resolve_path()`

Every file operation resolves paths through one helper, so `cd /tmp` then
`chmod +x x.sh` and `chmod +x /tmp/x.sh` hit the same `SYSTEM_STATE` key.
Bypassing it causes state-tracking bugs that only show up as the model
contradicting itself several commands later.

---

## 6. Storage (`storage.py`)

One SQLite file, `data/logs/hydrapot.db`, in **WAL mode** so the dashboard reads
while the sensor writes.

| Table | Rows | Written by | Contents |
|---|---|---|---|
| `sessions` | 132,282 | `main.py log()` | every command: cmd, response, agent, fi_score, latency, MITRE tag |
| `auth` | 286 | `ssh_server.py` | login attempts and port probes |
| `impactful` | 49,204 | `fi_manager` (`store="sqlite"`) | FI ≥ threshold events, incl. `score_method` |

### Why it replaced JSON

The old design was one JSON file per session, and **every command rewrote the
whole file** — read the array, append one record, dump it back. That's O(n²)
bytes per session. One real session with 844 impactful commands rewrote ~118 MB
of disk to record 287 KB of data.

Reads were as bad: the dashboard globbed and parsed 3,811 files (~300 ms) on
every cache miss.

Key design points:

- **Natural key** `(instance, session_id, seq)` with a UNIQUE index → migrations
  are idempotent, re-running can't double-insert.
- **`instance` column** → many sensors share one DB; no per-sensor files.
- **`SUMMARY_COLUMNS`** excludes `response` (51.8 MB of a 92 MB table). Page
  renders never read it; only the IOC extractor does.
- **Fresh connection per call** — sqlite3 connections aren't thread-safe and the
  dashboard serves threaded.

### Useful commands

```bash
python3 storage.py --stats      # row counts per table / instance
python3 storage.py --migrate    # import any legacy JSON (idempotent)
```

### Read paths at a glance

| Function | Used by | Notes |
|---|---|---|
| `query_all_df()` | `load_all()` — every page render | drops `response` (`SUMMARY_COLUMNS`) |
| `query_recent(n, instance)` | live feed | sensor filter pushed into SQL |
| `query_all()` | IOC extraction, `replay.py` | full width, `response` included |
| `query_session(sid)` | session drill-down | one session, full width |
| `browse_table()` / `run_readonly_query()` | Database page | **read-only connection** (§7) |

---

## 7. Dashboard (`dashboard.py`)

Plotly Dash, four pages, one router callback (`render_router`):
**Summary**, **Threat Intel**, **MITRE ATT&CK**, **Database**.

**Three caches, and they exist for different reasons:**

| Cache | TTL | Guards |
|---|---|---|
| `_cache` (`all_df`, `auth`, `raw_rows`) | 30 s | the data query |
| `_feed_cache` | 4 s | live terminal rows, keyed per sensor |
| `_page_cache` | 30 s | **fully rendered pages**, keyed per page+sensor |

The page cache is what makes clicking fast: profiling showed a Summary render is
26% Plotly, 39% Dash component construction, 35% pandas — so the fix was to *not
rebuild it*, not to speed up the query. Revisiting a page: **~1000 ms → ~8 ms**.

The live terminal is deliberately outside the page cache: it has its own 5 s
callback writing into `live-feed-wrap`, so a cached page still ticks.

> The sensor filter is pushed **into the SQL query**, not applied in pandas
> afterwards. Taking the newest N globally and filtering later looks equivalent
> but isn't — one busy sensor fills the whole window and every quieter sensor
> renders empty.

```bash
hp dashboard          # background, logs to data/dashboard.log
hp dashboard-stop
```

### The Database page

A read-only SQLite browser: table picker with row counts, schema, paginated
grid with search-across-all-columns, and a free-text SQL box.

**Its security model is SQLite's, not a filter.** Two independent locks in
`storage.connect_readonly()`:

| Lock | Stops |
|---|---|
| `file:...?mode=ro` URI | all writes — `DELETE`, `DROP`, `UPDATE`, `CREATE`, `VACUUM` |
| authorizer denying `SQLITE_ATTACH` | reaching *other* files on disk |

Both are needed. `mode=ro` alone was **verified insufficient**: a read-only
connection could still `ATTACH DATABASE '/tmp/x.db'` and select out of it.
Keyword blocklisting is deliberately *not* used — it's the usual approach and
the wrong one, since `PRAGMA`, sub-statements and `ATTACH` all slip past it.

This matters because `hp dashboard --host 0.0.0.0` is a documented way to run
the dashboard.

> Results are capped at `storage.MAX_BROWSE_ROWS` (500). That cap is about not
> shipping 132k rows into a browser, *not* about security.

> **Known sharp edge:** `dashboard-stop` trusts `data/dashboard.pid`. If an
> orphan process holds :8050, the stop targets the wrong PID and the next start
> fails with "Address already in use" — while the *old* code keeps serving.
> Check `ss -ltnp | grep 8050` if behaviour doesn't match your edits.

---

## 8. Config (`config.yaml`)

Written by `hp init`, hand-editable. Key sections:

- `honeypot` — hostname, OS string, `instance_name` (tags every row for
  multi-sensor deployments), bind host/port.
- `agents` — per-agent enable flag, model, temperature, API key env var.
- `routing.fi_routing` — FI band → agent. **The main knob.**
- `static_commands` — routed to `static_handler`, never an LLM.
- `system_state` — `pre_installed`, `base_tools`, `starting_files`. The initial SRi.
- `sensors` — named profiles (dbserver / dmz / internal), each with its own port
  and instance name.
- `power_tariff` — Thai electricity tiers, for the on-device cost analysis.

---

## 9. NSC — the thesis experiments (separate, still JSON)

`NSC/` is the experiment harness and is **deliberately not part of production**.
It builds its own `FILogManager` and writes its own JSON logs.

```
NSC/PartA/   architecture overhead — latency, runtime, power/cost
NSC/PartB/   state-tracking correctness against ground-truth pairs
NSC/PartC/   fidelity scoring, LLM-as-judge, token/cost accounting
NSC/agents.py, workloads.py    shared harness
```

**The boundary is `FILogManager(store=...)`:**

| Caller | `store` | Writes to |
|---|---|---|
| `main.py` (production) | `"sqlite"` — explicit | `impactful` table |
| `NSC/agents.py` | default | its own JSON |
| `NSC/PartC/estimate_electricity_bill.py` | default (no args) | its own JSON |

`"json"` is the **default on purpose**. That last NSC call site constructs
`FILogManager()` with no arguments, so a SQLite default would silently redirect
it. Production opting in explicitly is what keeps the two apart.

---

## 10. Gotchas

- **`hp init` rewrites `fi_routing`** and can disable agents. Always check
  `config.yaml` before an experiment run.
- **Cowrie must be running** for FI 0–1 routing to work (`docker-compose up`,
  port 2222). Without it those commands have no backend.
- **MITRE tags are applied at read time** in `dashboard.py`, not stored — so
  editing `MITRE_RULES` re-tags all history with no migration. The `technique_id`
  column exists but only new rows populate it.
- **`response` is excluded from `load_all()`.** Anything needing it should call
  `storage.query_session()`.
- **The old JSON archives** (`data/logs/_archive_*`) are pre-existing backups.
  Nothing reads them; the DB can be rebuilt from them with `--migrate`.

---

## 11. Quick reference

```bash
hp init                  # interactive setup → config.yaml
hp run                   # start the honeypot
hp dashboard             # web UI on :8050 (background)
hp dashboard-stop
hp logs -n 20            # newest session
hp logs --auth           # login attempts
hp intel --out ./intel   # IOC extraction → JSON/CSV/STIX
python3 replay.py        # animated session replay
python3 storage.py --stats
```
