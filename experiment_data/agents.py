"""
experiment_data/agents.py — single source of truth for agent setup.
─────────────────────────────────────────────────────────────────
build_agents() constructs cowrie / on-device / cloud + the real routed
handler ONCE, from config.yaml. Every part of the eval (A, B, C) starts here
instead of re-deriving agent setup. No hardcoding — everything from config.

Returns an Agents bundle exposing:
    .handle_cowrie/.handle_on_device/.handle_cloud(cmd, write_fn, read_fn)
                   real HydraPoT pipeline (main.handle), force-routed to that
                   agent — each is its OWN make_command_handler() closure with
                   an isolated SYSTEM_STATE/fi_manager (not shared between them)
    .handle_honeyrouter(cmd, write_fn, read_fn)
                   real HydraPoT pipeline, natural routing via classify() —
                   also its own isolated SYSTEM_STATE
    .direct_pure(agent_name, cmd) -> str
                   that agent ALONE, zero HydraPoT involvement: no proxy, no
                   router, no PromptManager, no SYSTEM_STATE. cowrie gets a
                   raw SSH send; on_device/cloud get the mrheinen dataset's
                   own "instruction" field as prompt instead of HydraPoT's
    .last_usage                       set after a "cloud" direct_pure() call —
                   dict with prompt/completion tokens + cost from the
                   proxy response, or None if unavailable/not cloud
    .scorer                           FIScorer (for FI bands)
    .cowrie/.ondevice/.cloud          raw agents if you need them
─────────────────────────────────────────────────────────────────
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))

# Route each arm's log to its own Part folder (see _paths.py).
from _paths import session_dir_for

sys.path.insert(0, _ROOT)
sys.path.insert(0, _HERE)

from core.config_loader import load_config
from agent_manager.cowrie_agent import CowrieAgent
from agent_manager.ondevice_agent import OnDeviceAgent
from agent_manager.cloud_agent import CloudAgent
import main as hydrapot_main


class Agents:
    def __init__(self, config, cowrie, ondevice, cloud, handle, pm, scorer,
                 cowrie_ok=True, handle_cowrie=None, handle_on_device=None,
                 handle_cloud=None, pm_standalone=None):
        self.config       = config
        self.cowrie       = cowrie
        self.ondevice     = ondevice
        self.cloud        = cloud
        self.handle       = handle          # real routed pipeline (natural routing)
        self.pm           = pm              # sync-off builder; Part B still uses it
        # Production's prompt assembly, per agent — handle.build_agent_prompt
        # from each HydraPoT arm. Keyed by agent so the cloud baseline reads
        # cloud's state, not on-device's.
        self.build_prompt = pm_standalone or {}
        self.scorer       = scorer
        self.cowrie_ok    = cowrie_ok
        self.last_usage   = None            # set by direct_pure("cloud", cmd); else None
        # force-routed, per-arm-isolated HydraPoT pipelines (own SYSTEM_STATE
        # each) — used by Part A to measure "agent X, but inside HydraPoT"
        self.handle_cowrie        = handle_cowrie
        self.handle_on_device     = handle_on_device
        self.handle_cloud         = handle_cloud

    # ── direct_pure: agent ALONE, zero HydraPoT involvement ───────────────────
    def direct_pure(self, agent_name: str, cmd: str) -> str:
        """
        The agent and nothing else: no proxy, no router, no pipeline. cowrie gets
        a raw SSH send; on_device and cloud get PRODUCTION'S prompt — built by
        the pipeline's own _build_agent_prompt, not reassembled here — so prompt
        and state tracking are shared and the measured difference is HydraPoT's
        machinery alone: routing (classify) and the multi-agent Cowrie
        history-sync. See build_prompt in build_agents() for why.
        """
        self.last_usage = None   # reset every call; only "cloud" sets it below

        base = cmd.strip().split()[0] if cmd.strip() else ""

        if agent_name == "cloud":
            if self.cloud is None:
                return ""
            sys_p, usr_p = self.build_prompt["cloud"]("cloud", cmd, base)
            text, usage = self.cloud.send_with_usage(sys_p, usr_p)
            self.last_usage = usage
            return text
        if agent_name == "on_device":
            if self.ondevice is None:
                return ""
            sys_p, usr_p = self.build_prompt["on_device"]("on_device", cmd, base)
            return self.ondevice.send(sys_p, usr_p)
        out, _ = self.cowrie.send(cmd)
        return out


def _scan_cached_models():
    """List downloaded HF models from cache (reused idea from setup_wizard)."""
    cache = os.path.expanduser("~/.cache/huggingface/hub/")
    models = []
    try:
        for folder in os.listdir(cache):
            if not folder.startswith("models--"):
                continue
            name = folder[len("models--"):].replace("--", "/", 1)
            fp = os.path.join(cache, folder)
            has = any(f.endswith((".gguf", ".safetensors", ".bin"))
                      for _, _, files in os.walk(fp) for f in files)
            if has:
                models.append(name)
    except FileNotFoundError:
        pass
    return sorted(models)


def pick_model() -> str | None:
    """Prompt user to choose a cached on-device model. Returns model id or None."""
    cached = _scan_cached_models()
    if not cached:
        print("[pick_model] no cached models found; using config default")
        return None
    print("\nCached models:")
    for i, m in enumerate(cached, 1):
        print(f"  {i}) {m}")
    print(f"  0) use config.yaml default")
    choice = input("Pick on-device model #: ").strip()
    if choice in ("", "0"):
        return None
    try:
        return cached[int(choice) - 1]
    except (ValueError, IndexError):
        print("[pick_model] invalid choice; using config default")
        return None


def build_agents(connect_cowrie: bool = True, model_override: str | None = None,
                 sync_state: bool = True, load_on_device: bool = True) -> Agents:
    # config_loader reads config.yaml by RELATIVE path, so we must run from the
    # project root (where config.yaml lives), not from experiment_data/. Otherwise it falls
    # back to built-in defaults (wrong creds, wrong model).
    if os.path.abspath(os.getcwd()) != _ROOT:
        os.chdir(_ROOT)
        print(f"[build_agents] chdir -> {_ROOT} (so config.yaml is found)")

    config = load_config()

    od_model = model_override or config.agents.on_device.model
    if model_override:
        print(f"[build_agents] on-device model override: {od_model}")

    # Only load the on-device GGUF model when the caller actually needs it.
    # It's a ~6.5 GB GPU load, wasted (and a hard failure if the GPU is busy)
    # for runs that never touch on_device — e.g. `--arms cloud`. Callers that
    # do route to on_device (on_device / honeyrouter arms) pass load_on_device=True.
    ondevice = OnDeviceAgent(
        model        = od_model,
        quantization = config.agents.on_device.quantization,
        gguf_file    = config.agents.on_device.gguf_file,
        temperature  = config.agents.on_device.temperature,
        max_tokens   = config.agents.on_device.max_tokens,
        do_sample    = config.agents.on_device.do_sample,
    ) if (load_on_device and config.agents.on_device.enabled) else None

    # CloudAgent reads its key itself from CLOUD_AGENT_API_KEY (core.config_loader
    # .CLOUD_API_KEY_ENV); it no longer takes an api_key_env arg after the refactor.
    cloud = CloudAgent(
        provider    = config.agents.cloud.provider,
        model       = config.agents.cloud.model,
        base_url    = getattr(config.agents.cloud, "base_url", "https://ai.psu.blue/v1"),
        temperature = config.agents.cloud.temperature,
        max_tokens  = config.agents.cloud.max_tokens,
    ) if config.agents.cloud.enabled else None

    cowrie = CowrieAgent(
        host     = config.agents.cowrie.host,
        port     = config.agents.cowrie.port,
        username = config.agents.cowrie.username,
        password = config.agents.cowrie.password,
    )
    cowrie_ok = False
    if connect_cowrie:
        try:
            cowrie._connect()
            cowrie_ok = True
        except Exception as e:
            print(f"[build_agents] WARNING: Cowrie connect failed ({e}). "
                  f"Cowrie-routed commands will be skipped; on-device/cloud "
                  f"arms still run.")
            cowrie_ok = False

    # wire main's globals so its handle() uses these instances
    hydrapot_main.config   = config
    hydrapot_main.ondevice = ondevice
    hydrapot_main.cloud    = cloud
    # store="json" keeps every experiment run OUT of the production database.
    # Without it, make_command_handler() writes each command straight into
    # hydrapot.db — which is how 88% of that DB ended up being benchmark
    # traffic. Building our own FILogManager was never enough: that governs
    # the `impactful` table only, not session rows.
    handle = hydrapot_main.make_command_handler(
        cowrie, src_ip="eval", public_ip="eval", plugins=None, sri_max_events=20,
        store="json", store_dir=session_dir_for("eval", __file__),
    )

    # force-routed, per-arm-isolated closures for Part A's "agent X inside
    # HydraPoT" arms — own SYSTEM_STATE/fi_manager each (not shared with
    # `handle` above or with each other), same pattern as run_partC.py's
    # _make_arm_sessions(). capture_cost=True so cloud/on_device usage lands
    # on each closure's own .last_usage.
    handle_cowrie = hydrapot_main.make_command_handler(
        cowrie, src_ip="parta_cowrie", public_ip="parta_cowrie",
        plugins=None, sri_max_events=20, capture_cost=True,
        store="json", store_dir=session_dir_for("parta_cowrie", __file__),
    )
    handle_on_device = hydrapot_main.make_command_handler(
        cowrie, src_ip="parta_on_device", public_ip="parta_on_device",
        plugins=None, sri_max_events=20, capture_cost=True,
        store="json", store_dir=session_dir_for("parta_on_device", __file__),
    )
    handle_cloud = hydrapot_main.make_command_handler(
        cowrie, src_ip="parta_cloud", public_ip="parta_cloud",
        plugins=None, sri_max_events=20, capture_cost=True,
        store="json", store_dir=session_dir_for("parta_cloud", __file__),
    )

    # Prompt builder for the standalone (direct_pure) arm.
    #
    # This is just another real pipeline, built the same way as the three above,
    # with sync_state=False — then we borrow its prompt_manager. Hand-building a
    # second PromptManager here is what broke Part A twice: the kwargs have to be
    # kept in step with shell/session.py by hand, and they weren't. builtins=set()
    # gated off every behavioural rule (user prompt 121 chars vs 5,314), and an
    # empty users dict made the SYSTEM prompt claim a one-user box. Both were
    # invisible because sync_state doesn't gate either of them.
    #
    # Going through make_command_handler() means there is ONE prompt code path
    # and sync_state is the only difference between the arms by construction,
    # not by a comment asking the next editor to remember. Only .prompt_manager
    # is used — direct_pure() never calls this handler, so no routing, no state
    # mutation, no Cowrie, no FI logging runs for the baseline.
    standalone_handle = hydrapot_main.make_command_handler(
        cowrie, src_ip="parta_standalone", public_ip="parta_standalone",
        plugins=None, sri_max_events=20, capture_cost=True, sync_state=False,
        store="json", store_dir=session_dir_for("parta_standalone", __file__),
    )
    pm = standalone_handle.prompt_manager

    # ── the standalone arms' prompt source (professor's fair baseline) ────────
    # Each standalone arm calls its HydraPoT twin's OWN prompt assembly —
    # handle.build_agent_prompt, the same function the pipeline uses to build
    # what it sends. Not a copy configured to match: the same code on the same
    # state, so the two arms cannot disagree about the prompt even in principle.
    #
    # This keeps the SRi state block and state tracking in BOTH arms, because
    # any stateful on-device honeypot needs state injection — charging it to
    # HydraPoT measured prompt size, not architecture. What's left in the
    # difference is HydraPoT's own machinery: routing (classify) and the
    # multi-agent Cowrie history-sync, neither of which direct_pure touches.
    #
    # Safe to call: _build_agent_prompt only reads state, never mutates it, and
    # PartA/overhead.py measures the standalone arm BEFORE its HydraPoT twin for
    # each command — so both see the same pre-command state.
    pm_standalone = {
        "on_device": handle_on_device.build_agent_prompt,
        "cloud":     handle_cloud.build_agent_prompt,
    }

    return Agents(config, cowrie, ondevice, cloud, handle, pm,
                  standalone_handle.fi_manager.scorer,
                  cowrie_ok=cowrie_ok, handle_cowrie=handle_cowrie,
                  handle_on_device=handle_on_device, handle_cloud=handle_cloud,
                  pm_standalone=pm_standalone)