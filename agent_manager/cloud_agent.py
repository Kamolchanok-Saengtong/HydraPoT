"""cloud_agent.py — OpenAI-compatible cloud LLM agent for HydraPoT."""

import os
import re
import time
import requests
from openai import OpenAI

# Safety-net for "chatty" models. A real terminal NEVER emits a lone meta-note
# like "<nothing>" or "(no output)" or "(empty response - command succeeded)"
# as its ENTIRE stdout — it either prints real bytes or nothing. Some models
# (e.g. GLM-5) describe the emptiness instead of being empty, which tanks
# fidelity on silent-success commands (rm/chmod/echo>file, common in FI4). The
# prompt forbids this, but as belt-and-suspenders we also strip it in code.
#
# SAFETY: only fires when the WHOLE trimmed response is a single bracketed/
# angled note containing an emptiness keyword. Genuine command output is never
# a lone "(...)"/"<...>"/"[...]" wrapper of these words, so this can never
# truncate or corrupt real output — it can only turn a pure meta-note empty.
_META_WORDS = re.compile(
    r"no\s*output|empty|blank|nothing|silent|succeed|success|completed|executed|no\s+response",
    re.I,
)


def _strip_whole_annotation(text: str) -> str:
    s = (text or "").strip()
    if len(s) >= 2 and s[0] in "(<[" and s[-1] in ")>]" and _META_WORDS.search(s):
        return ""
    return text

# DeepSeek doesn't return billed cost in the response — compute locally from
# published per-1M-token rates. Keyed by the *served* model (response "model"
# field), since e.g. "deepseek-chat" is an alias that can resolve to a newer
# model than requested. Verify against https://api-docs.deepseek.com/quick_start/pricing
# before trusting these for a paper — DeepSeek revises pricing over time.
DEEPSEEK_PRICING = {
    "deepseek-v4-flash": {"cache_hit": 0.0028,   "cache_miss": 0.1400, "output": 0.2800},
    "deepseek-v4-pro":   {"cache_hit": 0.003625, "cache_miss": 0.4350, "output": 0.8700},
}


class CloudAgent:
    def __init__(self, provider: str, model: str, api_key_env: str,
                 base_url: str = None, temperature: float = 0.3, max_tokens: int = 512):
        self.model       = model
        self.temperature = temperature
        self.max_tokens  = max_tokens

        self.api_key_env = api_key_env
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise EnvironmentError(
                f"[CloudAgent] API key env var '{api_key_env}' is not set. "
                f"Run: export {api_key_env}=sk-..."
            )
        self._api_key = api_key
        self._base_url = (base_url or "https://ai.psu.blue/v1").rstrip("/")

        self.client = OpenAI(
            api_key  = api_key,
            base_url = base_url or "https://ai.psu.blue/v1",
        )
        print(f"[CloudAgent] Ready — {provider} / {model} @ {base_url or 'openai default'}")

    def _stream_chat(self, system_prompt: str, user_prompt: str, want_usage: bool = False):
        """
        Internal: always requests stream=True via the SDK (PSU's proxy
        streams regardless of the stream flag when called through the SDK),
        and consumes the stream properly via the SDK's own SSE iterator.

        Returns (text: str, usage: dict | None). usage is essentially always
        None here — PSU's streaming responses don't attach usage to any
        chunk (confirmed via raw curl test). Use send_with_usage() instead
        if you need real cost data.
        """
        kwargs = dict(
            model       = self.model,
            temperature = self.temperature,
            max_tokens  = self.max_tokens,
            stream      = True,
            messages    = [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
        )
        if want_usage:
            kwargs["stream_options"] = {"include_usage": True}

        chunks = []
        usage_obj = None
        cost_val = None
        cost_details = None

        stream = self.client.chat.completions.create(**kwargs)
        for chunk in stream:
            if chunk.choices:
                delta = chunk.choices[0].delta
                if delta and delta.content:
                    chunks.append(delta.content)
            chunk_usage = getattr(chunk, "usage", None)
            if chunk_usage is not None:
                usage_obj = chunk_usage
            chunk_cost = getattr(chunk, "cost", None)
            if chunk_cost is not None:
                cost_val = chunk_cost
            chunk_cost_details = getattr(chunk, "cost_details", None)
            if chunk_cost_details is not None:
                cost_details = chunk_cost_details

        text = _strip_whole_annotation("".join(chunks).strip())

        usage = None
        if want_usage and (usage_obj is not None or cost_val is not None):
            usage = {
                "prompt_tokens":     getattr(usage_obj, "prompt_tokens", None),
                "completion_tokens": getattr(usage_obj, "completion_tokens", None),
                "total_tokens":      getattr(usage_obj, "total_tokens", None),
                "cost":              cost_val,
                "upstream_inference_cost": (
                    cost_details.get("upstream_inference_cost")
                    if isinstance(cost_details, dict) else
                    getattr(cost_details, "upstream_inference_cost", None)
                ) if cost_details is not None else None,
            }

        return text, usage

    def send(self, system_prompt: str, user_prompt: str) -> str:
        """Send a command to the cloud LLM and return its response.

        Streams under the hood via the SDK (PSU's proxy streams regardless
        of the stream flag) and reassembles the full text via the SDK's
        proper SSE chunk iterator. External behavior (plain string return)
        is unchanged; main.py needs no changes.
        """
        try:
            text, _ = self._stream_chat(system_prompt, user_prompt, want_usage=False)
            return text
        except Exception as e:
            print(f"[CloudAgent] Error: {e}")
            return ""

    def send_with_usage(self, system_prompt: str, user_prompt: str):
        """Same as send(), but also returns real token/cost usage.

        Bypasses the OpenAI SDK entirely and POSTs directly to PSU's
        endpoint with stream=False. Confirmed via raw curl test that PSU's
        gateway DOES return a proper single JSON object with usage/cost
        when called this way — the SDK was the one mishandling stream=False
        (it returned SSE chunks as a raw unparsed string instead). Going
        straight to HTTP avoids that SDK quirk entirely.

        Used by the architecture-overhead experiment (NSC/) to log real
        billed cost per command. NOT used by main.py's production path —
        that keeps using send() (streaming via SDK), unchanged.

        Returns:
            (text: str, usage: dict | None)
            usage = {
                "prompt_tokens": int, "completion_tokens": int,
                "total_tokens": int, "cost": float | None,
                "upstream_inference_cost": float | None,
            } or None if the request failed or the response didn't include
            usage (shouldn't happen based on testing, but handled safely).
        """
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model":       self.model,
            "temperature": self.temperature,
            "max_tokens":  self.max_tokens,
            "stream":      False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
        }

        # Retry with backoff. Without this, ONE slow/hiccuping proxy response
        # returned an empty string that was then recorded as the model's actual
        # answer — a silently corrupted data point that scores as a blank
        # response. Big models (qwen *-plus) regularly exceed a 30s budget, and
        # the PSU proxy intermittently 502s under load, so both are retried
        # rather than surfaced as fake "empty" answers.
        _RETRY_STATUS = {408, 429, 500, 502, 503, 504}
        resp = None
        delay = 2.0
        last_err = "unknown"
        for attempt in range(4):
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=120)
                if resp.status_code == 200:
                    break
                last_err = f"HTTP {resp.status_code}"
                if resp.status_code not in _RETRY_STATUS:
                    print(f"[CloudAgent] Error: HTTP {resp.status_code} - {resp.text[:200]}")
                    return "", None
            except requests.exceptions.Timeout:
                last_err = "timeout"
                resp = None
            except requests.exceptions.RequestException as e:
                last_err = str(e)[:120]
                resp = None
            if attempt < 3:
                print(f"[CloudAgent] {last_err} — retry {attempt + 1}/3 in {delay:.0f}s")
                time.sleep(delay)
                delay = min(delay * 2, 20)

        if resp is None or resp.status_code != 200:
            # Do NOT return a bare "" — that would be scored as a real (blank)
            # answer. Mark it so corrupt records are identifiable afterwards.
            print(f"[CloudAgent] Error: giving up after retries ({last_err})")
            return f"[cloud error: {last_err}]", None

        try:
            data = resp.json()
        except ValueError:
            print(f"[CloudAgent] Error: non-JSON response - {resp.text[:300]}")
            return "", None

        try:
            # content can be None (not "") when the model returns an empty
            # response — obedient models like gpt-4o-mini legitimately do this
            # for silent-success commands. `None or ""` keeps it an empty string
            # instead of crashing on None.strip().
            _content = data["choices"][0]["message"]["content"] or ""
            text = _strip_whole_annotation(_content.strip())
        except (KeyError, IndexError, TypeError, AttributeError):
            print(f"[CloudAgent] Error: unexpected response shape - {data}")
            return "", None

        usage_data = data.get("usage") or {}
        cost_details = usage_data.get("cost_details") or {}

        cost = usage_data.get("cost")
        if cost is None:
            served_model = data.get("model", self.model)
            pricing = DEEPSEEK_PRICING.get(served_model)
            if pricing:
                cache_hit_tok  = usage_data.get("prompt_cache_hit_tokens", 0) or 0
                cache_miss_tok = usage_data.get("prompt_cache_miss_tokens", 0) or 0
                completion_tok = usage_data.get("completion_tokens", 0) or 0
                cost = (
                    cache_hit_tok  * pricing["cache_hit"] +
                    cache_miss_tok * pricing["cache_miss"] +
                    completion_tok * pricing["output"]
                ) / 1_000_000

        usage = {
            "prompt_tokens":           usage_data.get("prompt_tokens"),
            "completion_tokens":       usage_data.get("completion_tokens"),
            "total_tokens":            usage_data.get("total_tokens"),
            "cache_hit_tokens":        usage_data.get("prompt_cache_hit_tokens"),
            "cache_miss_tokens":       usage_data.get("prompt_cache_miss_tokens"),
            "cost":                   cost,
            "upstream_inference_cost": cost_details.get("upstream_inference_cost"),
        } if usage_data else None

        return text, usage