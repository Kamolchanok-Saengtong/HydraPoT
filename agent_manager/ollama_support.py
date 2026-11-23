"""
agent_manager/ollama_support.py -- run the on-device model through Ollama.

Ollama serves any model you `ollama pull` over an OpenAI-compatible API, so the
honeypot needs no model files or GPU libraries of its own: set
agents.on_device.mode to `ollama` and name the model the way Ollama does
(`qwen2.5:7b`). Stdlib + requests only.
"""
import json
import os

import requests

DEFAULT_HOST = "http://127.0.0.1:11434"


def host(base_url: str = None) -> str:
    """The Ollama server: config's base_url, else OLLAMA_HOST, else the default.

    OLLAMA_HOST is written both as a URL and as a bare `host:port`; both work.
    """
    raw = (base_url or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST).strip().rstrip("/")
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    if raw.endswith("/v1"):
        raw = raw[:-3]
    return raw


def _tag(name: str) -> str:
    """`qwen2.5` and `qwen2.5:latest` are the same model."""
    return name if ":" in name else name + ":latest"


def models(server: str, timeout: float = 5.0):
    """Names of the models already pulled, or None when the server is not answering."""
    try:
        r = requests.get(f"{server}/api/tags", timeout=timeout)
        r.raise_for_status()
        return [m.get("name") or m["model"] for m in r.json().get("models", [])]
    except (requests.RequestException, ValueError, KeyError):
        return None


def has_model(server: str, model: str) -> bool:
    return _tag(model) in {_tag(m) for m in (models(server) or [])}


def check(server: str, model: str):
    """None when ready, else the sentence telling the operator what to do."""
    have = models(server)
    if have is None:
        return (f"Ollama is not answering at {server}. Install it from https://ollama.com, "
                f"start it (`ollama serve`), then run this again.")
    if _tag(model) not in {_tag(m) for m in have}:
        return (f"Ollama does not have '{model}' yet. Pull it with:\n"
                f"      ollama pull {model}\n"
                f"    or run `hp --init` and pick Ollama to pull it from there.")
    return None


def pull(server: str, model: str, on_progress=None) -> bool:
    """`ollama pull`, streamed. on_progress(status, done_bytes, total_bytes). True on success."""
    try:
        with requests.post(f"{server}/api/pull", json={"model": model, "name": model, "stream": True},
                           stream=True, timeout=(10, None)) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                msg = json.loads(line)
                if msg.get("error"):
                    if on_progress:
                        on_progress(f"error: {msg['error']}", 0, 0)
                    return False
                if on_progress:
                    on_progress(msg.get("status", ""), msg.get("completed", 0), msg.get("total", 0))
        return has_model(server, model)
    except (requests.RequestException, ValueError):
        return False
