"""
api/assistant.py — the AI Security Analyst.

    you  ->  assistant  ->  TOOLS  ->  api/services  ->  HydraPoT pipeline
                                            ^
                        the same functions /api/v1 routes call

The assistant has NO database access and no ability to run anything. It can
only call the read-only functions below, which are the same ones the REST API
exposes. That is the whole design: every claim it makes can be traced to a
tool result, and it physically cannot reach a fact HydraPoT did not already
establish.

IN-PROCESS, NOT OVER HTTP. The tools call api.services directly rather than
looping back through uvicorn. Same functions, same answers, but no self-call
into a server that is currently blocked serving this very request -- which on a
thread-pooled deployment is a way to deadlock. The boundary is enforced by
WHICH functions are reachable, not by the transport.

WHAT IT MUST NOT DO
  * invent a severity, a risk score, or an attacker identity -- HydraPoT
    deliberately produces none of those, and a confident guess is worse than
    "not determined"
  * treat FI as danger; it is the routing metric
  * claim a correlation means the same operator or campaign
  * answer from memory when a tool could answer from evidence

The system prompt states those rules, and the tool surface makes most of them
impossible to break: there is no endpoint that returns a risk score, so it has
nothing to quote.
"""
import json
import os

from config_loader import load_config

# ── tool surface ────────────────────────────────────────────────────────────
# One entry per question an analyst actually asks. Deliberately NOT one per
# endpoint: `investigate_*` already bundles what a human would otherwise fetch
# in six calls, and a smaller surface means fewer wrong turns per answer.

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_overview",
            "description": "High-level security picture for a time window: "
                           "activity counts, timeline, top source addresses, "
                           "MITRE distribution, IOC counts, categories, alert "
                           "counts. Start here when asked 'what is happening'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "since": {"type": "string", "enum": ["15m", "1h", "24h", "7d", "all"],
                              "description": "Time window, measured back from "
                                             "the NEWEST event that exists (not "
                                             "from now). Use 'all' unless the "
                                             "user asked for a period -- a "
                                             "capture can span years, so a "
                                             "short window is often legitimately "
                                             "empty."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_alerts",
            "description": "The alert queue: findings a rule decided a human "
                           "should act on. Filter by state or severity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "state": {"type": "string", "enum": ["new", "acknowledged", "closed"]},
                    "severity": {"type": "string",
                                 "enum": ["info", "low", "medium", "high", "critical"]},
                    "limit": {"type": "integer", "description": "Default 20."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_detections",
            "description": "Detections for a window. bucket='detections' is "
                           "what was surfaced; 'suppressed' was filtered by a "
                           "rule; 'unmatched' matched no rule -- which does "
                           "NOT mean benign. IMPORTANT: to count detections, "
                           "call this ONCE with no severity filter and read "
                           "'total'. Filtering by severity EXCLUDES unrated "
                           "findings, so summing per-severity calls "
                           "undercounts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "since": {"type": "string", "enum": ["15m", "1h", "24h", "7d", "all"]},
                    "severity": {"type": "string",
                                 "enum": ["info", "low", "medium", "high", "critical"]},
                    "bucket": {"type": "string",
                               "enum": ["detections", "suppressed", "unmatched", "all"]},
                    "limit": {"type": "integer"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_alert",
            "description": "Full investigation package for one alert: what "
                           "fired, why, the correlation behind it, MITRE "
                           "mapping, member sessions and evidence.",
            "parameters": {
                "type": "object",
                "properties": {"alert_id": {"type": "string"}},
                "required": ["alert_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_session",
            "description": "Full investigation package for one session: "
                           "commands in order, MITRE, IOCs, what it is "
                           "correlated with, and any detections or alerts.",
            "parameters": {
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_ip",
            "description": "Everything recorded from one source address. "
                           "NOTE: an address is not an identity -- NAT and "
                           "rotation both break that assumption.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigate_ioc",
            "description": "Which sessions referenced an indicator (URL, IP, "
                           "domain, hash) and what they did. Accepts "
                           "'type:value' or a bare value.",
            "parameters": {
                "type": "object",
                "properties": {"ioc": {"type": "string"}},
                "required": ["ioc"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_mitre_activity",
            "description": "ATT&CK tactics and techniques observed, with "
                           "tagging coverage.",
            "parameters": {
                "type": "object",
                "properties": {
                    "since": {"type": "string", "enum": ["15m", "1h", "24h", "7d", "all"]},
                    "technique_id": {"type": "string",
                                     "description": "Optional: detail for one technique."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_sessions",
            "description": "Sessions in a window, filterable by source address "
                           "or ATT&CK technique.",
            "parameters": {
                "type": "object",
                "properties": {
                    "since": {"type": "string", "enum": ["15m", "1h", "24h", "7d", "all"]},
                    "src_ip": {"type": "string"},
                    "technique": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_capabilities",
            "description": "What this HydraPoT deployment supports: which rule "
                           "sets are loaded, severity levels, correlation "
                           "types. Use when asked what the system can do.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


def _dispatch(name: str, args: dict) -> dict:
    """Run one tool. The ONLY way the assistant reaches HydraPoT.

    Every branch calls api.services -- the same functions the REST routes call
    -- so a tool can never return something the API would not. An unknown name
    is an error rather than a silent empty result: a model that thinks it
    called something is worse than one told it cannot.
    """
    from api import services as svc

    since = args.get("since", "all")

    def _windowed(result):
        """Attach the RESOLVED window to any windowed result.

        Without it an empty answer is indistinguishable from a quiet system.
        This capture spans 2019 to today, so `since=24h` resolves to a real
        but empty window and the model reported "0 detections" as fact. Now it
        can see the window it got and retry with a wider one.
        """
        try:
            result = dict(result)
            result["window"] = svc.overview(since)["window"]
        except Exception:
            pass
        return result

    if name == "get_overview":
        o = svc.overview(since)
        # The full overview is large and mostly timeline; the assistant needs
        # the shape of it, not every bucket. Trimmed here rather than in the
        # service, because the REST API's consumers DO want the whole thing.
        return {"window": o.get("window"), "activity": o.get("activity"),
                "funnel": o.get("funnel"), "mitre": o.get("mitre"),
                "iocs": o.get("iocs"), "categories": o.get("categories"),
                "top_sources": (o.get("source_ips") or [])[:10],
                "alerts": svc.alert_counts()}
    if name == "list_alerts":
        # Alerts are not window-scoped -- they persist until closed -- so no
        # window is attached here; saying otherwise would imply a filter that
        # is not applied.
        return svc.list_alerts(args.get("state"), args.get("severity"), None,
                               args.get("limit", 20), 0)
    if name == "list_detections":
        out = _windowed(svc.list_detections(
            since, None, args.get("severity"), args.get("bucket", "detections"),
            args.get("limit", 20), 0))
        # The breakdown comes WITH the result, so "how many detections" is one
        # call. Telling the model in prose to avoid per-severity enumeration
        # did not work -- it kept issuing one call per level and summing them,
        # which silently drops UNRATED findings and undercounted 15 as 9.
        # Shaping the data to match the question is more reliable than asking
        # the model not to ask it badly.
        # ALWAYS attached, even when a severity filter was applied. Only
        # adding it to unfiltered calls left a filtered call looking like the
        # whole picture: the model picked severity='info', got 0, and reported
        # "0 detections in total". The unfiltered count now travels with every
        # response, so no single call can be mistaken for the total.
        counts = {}
        for d in svc.list_detections(since, None, None,
                                     args.get("bucket", "detections"),
                                     500, 0)["items"]:
            key = d.get("severity") or "unrated"
            counts[key] = counts.get(key, 0) + 1
        out["total_all_severities"] = sum(counts.values())
        out["by_severity"] = counts
        out["note"] = ("'total' reflects any filter you applied. "
                       "'total_all_severities' is the complete count for this "
                       "window and bucket -- use it when asked how many. "
                       "by_severity includes 'unrated': findings the severity "
                       "ruleset could not read, because the relationship shares "
                       "a value rather than a command sequence.")
        return out
    if name == "investigate_alert":
        return svc.investigate_alert(args["alert_id"], since) or {"error": "alert not found"}
    if name == "investigate_session":
        return svc.investigate_session(args["session_id"], since) or {"error": "session not found"}
    if name == "investigate_ip":
        return svc.investigate_ip(args["ip"], since) or {"error": "address not seen"}
    if name == "investigate_ioc":
        return svc.investigate_ioc(args["ioc"], since) or {"error": "indicator not found"}
    if name == "get_mitre_activity":
        tid = args.get("technique_id")
        if tid:
            return svc.mitre_technique(tid, since) or {"error": "technique not observed"}
        return svc.mitre_activity(since)
    if name == "list_sessions":
        return _windowed(svc.list_sessions(
            since, None, args.get("src_ip"), args.get("technique"), None, None,
            args.get("limit", 20), 0))
    if name == "get_capabilities":
        return svc.capabilities()
    return {"error": f"unknown tool {name!r}"}


ASSISTANT_NAME = "Hydra"

GREETING = (
    "Hi, I'm **Hydra**!! HydraPoT's security analyst.\n\n"
    "HydraPoT is a decoy SSH server. Attackers break into it believing it is "
    "real, and every command they run is recorded. My job is to tell you what "
    "they did here and **what that same activity would have meant for a real "
    "production host**.\n\n"
    "Ask me about alerts, a session, a source address, an indicator, or an "
    "ATT&CK technique. I answer from HydraPoT's own findings and show you "
    "which ones I used."
)

SYSTEM_PROMPT = f"""You are {ASSISTANT_NAME}, HydraPoT's security analyst.

WHAT HYDRAPOT IS, AND WHY IT MATTERS
HydraPoT is a HONEYPOT: a decoy SSH server, deliberately exposed. Every session
in it is an intrusion -- nobody has a legitimate reason to log in. Attackers
believe they are on a real machine, so what they type is what they would have
typed against production.

That is the value, and it is your job to convert it. The operator does not
mainly need "what happened in the decoy"; they need "what would this have done
to a real server, and what should I check or harden". You are an early-warning
analyst reading a rehearsal of an attack that has not hit them yet.

So when the evidence supports it, explain the OPERATIONAL CONSEQUENCE of the
observed behaviour: what a command sequence is trying to achieve, what it would
have installed, persisted, destroyed, exfiltrated or exposed on a real host,
and which defences would have stopped it. Ground every such statement in what
was actually observed, quoting the commands or techniques.

THE LIMIT ON THAT, AND IT IS A HARD ONE
You know NOTHING about the operator's real infrastructure -- not their hosts,
their patch level, their network, their exposure, or whether the attacker's
technique would even work there. Never state or imply that their systems are
compromised, vulnerable, or affected. Distinguish plainly:

  observed   what HydraPoT recorded ("the session ran wget, chmod +x, sh")
  meaning    what that behaviour is for ("a loader fetching and running a
             payload -- on a real host this is code execution as the login user")
  advice     framed as a check, never a finding ("worth confirming outbound
             egress is filtered")

If asked "am I affected" or "is my server compromised", say clearly that
HydraPoT cannot see their infrastructure and can only report what the decoy
observed.

HydraPoT's pipeline is: raw events -> aggregation -> correlation -> detection
-> severity -> alerting. You answer by calling tools. You have no database
access and cannot run commands.

HOW TO ANSWER
- Call a tool before answering anything factual. Never answer from memory.
- Default to since='all' unless the user names a period. This deployment's
  capture can span years, so a short window may be genuinely empty. If a result
  is empty, check the 'window' field in it: if the window is narrow, say so and
  retry with 'all' before reporting zero.
- Cite what you used: session ids, alert ids, technique ids, timestamps.
- Be brief. An analyst wants the finding, not an essay. Use short paragraphs or
  a compact list. Two or three sentences is often the whole answer.
- If a tool returns nothing, say so plainly. "No alerts in this window" is a
  complete and useful answer.

WHAT YOU MUST NOT DO
- Do not invent a severity, risk score, or threat rating. HydraPoT produces
  severity only from its rule set; if a finding is unrated, say "unrated" and
  explain that means the behaviour ruleset found no command sequence to read.
- Do not attribute activity to a named actor, group, or campaign. HydraPoT has
  no attribution data.
- A correlation means observations share a value. "same_sequence" means the
  same command sequence was observed -- NOT the same attacker, operator, or
  campaign. Never upgrade it.
- FI score is HydraPoT's internal ROUTING metric: it decides which agent
  answered a command. It is NOT severity or danger. A loud `rm` of a file the
  attacker created themselves is FI 4 and harmless. Never present FI as risk.
- "unmatched" means no detection rule claimed it. That is not a finding of
  benign.
- Do not recommend actions as if you know the environment. You can describe
  what the evidence supports.

If you are unsure, say what you checked and what was missing."""


class Assistant:
    """One conversation. Stateless between calls: the caller owns the history,
    so a browser refresh or a second tab cannot inherit someone else's chat."""

    def __init__(self, config=None):
        cfg = (config or load_config()).ai_assistant
        self.cfg = cfg
        self.api_key = os.environ.get(cfg.api_key_env, "")
        self._client = None

    @property
    def available(self) -> bool:
        return bool(self.api_key) and bool(self.cfg.enabled)

    @property
    def client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key, base_url=self.cfg.base_url)
        return self._client

    def _turn(self, messages):
        """One model call. -> (content, [tool_call, ...])

        ALWAYS STREAMS. This endpoint returns server-sent events even when
        `stream` is not requested, so a non-streaming call hands the SDK
        `text/event-stream` and it returns the raw body as a str -- which fails
        later with "'str' object has no attribute 'choices'". Asking for a
        stream explicitly is what makes the SDK parse it.

        Streaming means tool calls arrive in FRAGMENTS: the name in one chunk,
        the JSON arguments a few characters at a time across many more, keyed
        only by `index`. They are accumulated per index and assembled at the
        end; parsing a partial argument string is the classic bug here.
        """
        stream = self.client.chat.completions.create(
            model=self.cfg.model, messages=messages, tools=TOOLS,
            temperature=self.cfg.temperature, max_tokens=self.cfg.max_tokens,
            stream=True)

        content, partial = [], {}
        for chunk in stream:
            if not chunk.choices:
                continue                      # usage-only trailer
            delta = chunk.choices[0].delta
            if getattr(delta, "content", None):
                content.append(delta.content)
            for tc in (getattr(delta, "tool_calls", None) or []):
                slot = partial.setdefault(tc.index,
                                          {"id": "", "name": "", "arguments": ""})
                if tc.id:
                    slot["id"] = tc.id
                fn = getattr(tc, "function", None)
                if fn is not None:
                    if fn.name:
                        slot["name"] = fn.name
                    if fn.arguments:
                        slot["arguments"] += fn.arguments

        calls = [c for _, c in sorted(partial.items()) if c["name"]]
        return "".join(content), calls

    def ask(self, question: str, history=None) -> dict:
        """One turn. -> {"answer": str, "tools": [...], "error": str|None}

        `tools` lists what was actually called, and is shown in the UI. That is
        not decoration: it is how someone checks the answer came from HydraPoT
        rather than from the model's priors.
        """
        if not self.available:
            # Same text the panel shows, not a terser error: the key can be
            # removed between opening the panel and asking, and two different
            # explanations for one condition is how a user concludes something
            # is subtly broken.
            return {"answer": unavailable_message(), "tools": [],
                    "error": None, "unavailable": True}

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for turn in (history or [])[-8:]:      # keep the prompt bounded
            if turn.get("role") in ("user", "assistant") and turn.get("content"):
                messages.append({"role": turn["role"], "content": turn["content"]})
        messages.append({"role": "user", "content": question})

        used = []
        try:
            # Bounded loop. A model that keeps calling tools without answering
            # would otherwise spend the user's money in a circle; at the cap we
            # ask it to answer with what it has rather than failing.
            for step in range(self.cfg.max_tool_calls):
                content, calls = self._turn(messages)
                if not calls:
                    return {"answer": content.strip(), "tools": used,
                            "error": None}

                messages.append({
                    "role": "assistant", "content": content or None,
                    "tool_calls": [{"id": c["id"], "type": "function",
                                    "function": {"name": c["name"],
                                                 "arguments": c["arguments"]}}
                                   for c in calls]})
                for call in calls:
                    name = call["name"]
                    try:
                        args = json.loads(call["arguments"] or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    try:
                        result = _dispatch(name, args)
                    except Exception as e:
                        # A failing tool is reported TO THE MODEL rather than
                        # raised: it can then say what it could not check,
                        # instead of the whole turn dying.
                        result = {"error": f"{type(e).__name__}: {e}"}
                    used.append({"tool": name, "args": args})
                    messages.append({"role": "tool", "tool_call_id": call["id"],
                                     "content": json.dumps(result, default=str)[:12000]})

            return {"answer": "I gathered evidence but ran out of tool calls "
                              "before finishing. Try a narrower question.",
                    "tools": used, "error": None}
        except Exception as e:
            return {"answer": "", "tools": used, "error": f"{type(e).__name__}: {e}"}


# Shown when no key is configured. Written to be READ BY SOMEONE WHO DID
# NOTHING WRONG: an unset optional feature is not an error, so this states
# plainly what is missing, what still works, and the two steps to enable it.
# The reassurance in the middle is the important line -- without it, a panel
# announcing "unavailable" reads as though the dashboard is broken.
UNAVAILABLE_MESSAGE = (
    "**The AI analyst is not enabled.**\n\n"
    "Hydra needs a language-model API key to answer questions. "
    "**Everything else in HydraPoT works without it** — detections, severity, "
    "alerts, the investigation workspace and the REST API are all unaffected.\n\n"
    "To turn it on:\n\n"
    "1. Add your key to `.env` in the project root:\n"
    "   `{key_env}=sk-...`\n"
    "2. Restart the dashboard.\n\n"
    "Hydra only ever reads HydraPoT's own findings through the read-only API. "
    "It has no database access and cannot run commands."
)


def unavailable_message() -> str:
    """The 'not enabled' text, naming the variable THIS deployment expects.

    Read from config rather than hardcoded: someone who renamed the variable
    would otherwise be told to set one that nothing reads, which is a
    particularly annoying way to lose twenty minutes.
    """
    try:
        key_env = load_config().ai_assistant.api_key_env
    except Exception:
        key_env = "AI_API_KEY"
    return UNAVAILABLE_MESSAGE.format(key_env=key_env)


def is_available() -> bool:
    """Whether the assistant can answer at all.

    Deliberately cheap and side-effect free -- no OpenAI client is constructed
    -- because the UI calls it on every render to decide what to draw.
    """
    try:
        cfg = load_config().ai_assistant
        return bool(cfg.enabled) and bool(os.environ.get(cfg.api_key_env, ""))
    except Exception:
        return False


_assistant = None


def ask(question: str, history=None) -> dict:
    """Module-level entry point, with the client built once per process."""
    global _assistant
    if _assistant is None:
        _assistant = Assistant()
    return _assistant.ask(question, history)
