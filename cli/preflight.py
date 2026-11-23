"""
cli/preflight.py -- what must be true before the honeypot starts.

`hp --run` and the wizard's "Run honeypot" both go through here, so a missing piece is
named with the command that fixes it, not met later as a traceback or a silent fallback.
"""
import sys

ROUTER_STEPS = {
    "not_trained": "Honey Router has not been trained yet.",
    "partial": "Honey Router training did not finish.",
    "trained": "Honey Router is trained but no omega has been approved.",
}
ROUTER_FIX = ("  Train and approve it once with:\n"
              "      hp --router\n"
              "  (it trains the three phases, shows what each omega costs, and you pick one)")


def router_problem(config):
    """Why smart_router cannot run yet, or None when it can (or is not in use)."""
    if config.routing.mode != "smart_router":
        return None
    try:
        from honeyrouter import cli as router_cli
        state = router_cli.status()["state"]
    except ImportError as exc:
        return (f"Honey Router needs its training packages ({exc.name}).\n"
                f"  Install them, then run `hp --router`.")
    if state in ROUTER_STEPS:
        return f"{ROUTER_STEPS[state]}\n{ROUTER_FIX}"
    return None            # approved, or stale (trained on older data: still works)


def ollama_problem(config):
    od = config.agents.on_device
    if not od.enabled or (getattr(od, "mode", "local") or "local").lower() != "ollama":
        return None
    from agent_manager import ollama_support as ol
    return ol.check(ol.host(getattr(od, "base_url", None)), od.model)


def local_model_problem(config):
    """The default on-device path: a model downloaded from Hugging Face into its cache."""
    od = config.agents.on_device
    if not od.enabled or (getattr(od, "mode", "local") or "local").lower() != "local":
        return None
    from agent_manager.ondevice_agent import _find_gguf_file, _is_gguf
    from cli.setup_wizard import _is_cached
    if _is_gguf(od.model):
        ok = _find_gguf_file(od.model, getattr(od, "gguf_file", "") or "") is not None
    else:
        ok = _is_cached(od.model)
    if ok:
        return None
    name = getattr(od, "gguf_file", "") or ""
    cli_fetch = (f"huggingface-cli download {od.model}" + (f" {name}" if name else ""))
    return (f"The on-device model '{od.model}' is not downloaded yet.\n"
            f"  Download it with:\n"
            f"      hp --init            (pick it and say yes to the download)\n"
            f"  or:\n"
            f"      {cli_fetch}\n"
            f"  or switch to Ollama (`hp --init`), or turn the on-device model off.")


def problems(config) -> list:
    return [p for p in (router_problem(config), ollama_problem(config), local_model_problem(config)) if p]


def require(config) -> None:
    """Exit with an explanation, instead of starting a honeypot that would misbehave."""
    found = problems(config)
    if not found:
        return
    print("\nHydraPoT is not ready to run:\n", file=sys.stderr)
    for p in found:
        print("  ✗ " + p.replace("\n", "\n    "), file=sys.stderr)
        print(file=sys.stderr)
    sys.exit(1)
