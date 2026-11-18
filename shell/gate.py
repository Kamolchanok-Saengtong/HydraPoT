"""
shell/gate.py — the consistency gate between the agents and the attacker.

Implements the consistency gate and claim-output extractor of Section IV-B
and VI-K, and the turn of Algorithm 1, in Gil et al., "OSCAR: Provably
Consistent LLM Honeypots via Ontology-Constrained Response Generation",
IEEE TDSC 2026 (DOI 10.1109/TDSC.2026.3749501).

An agent proposes (output, effects, claims). The gate admits the first
proposal whose claims agree with the world-state and whose committed
post-state satisfies Sigma (Def. 1); otherwise it serves a fallback that is
feasible by construction. Every decision is logged for the contradiction and
open-tail-fallback metrics.
"""
import json
import posixpath
import re
from dataclasses import dataclass, field

from shell.world import Fact, Instance, Proposal, feasible

# Appended to an agent's system prompt to get the structured triple
CONTRACT = """
Reply with ONE JSON object and nothing else:
{"output": "<exact terminal output>",
 "effects": [{"op": "create_file|create_dir|write|append|remove|chmod",
              "path": "<path>", "content": "<text>", "mode": "<octal>"}],
 "claims": [{"type": "file|dir|absent|content", "path": "<path>",
             "content": "<text>"}]}
effects: every change the command makes. claims: every file, directory,
missing path or file content your output asserts. Use [] when there are none.
""".strip()

# Denial lexicon of the output extractor (Sec. VI-K)
_DENIAL = re.compile(r"no such file|not found|does not exist|"
                     r"cannot (?:access|stat|open|remove)", re.I)
_IS_DIR = re.compile(r"is a directory", re.I)
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def parse_triple(text: str):
    """The (output, effects, claims) object, or None if it can't be recovered.

    Accepts markdown-fenced and prose-embedded JSON; anything malformed,
    truncated or mistyped is None, so the caller rejects it.
    """
    if not isinstance(text, str):
        return None
    for chunk in _FENCE.findall(text) + [text]:
        start = chunk.find("{")
        while start != -1:
            try:
                obj, _ = json.JSONDecoder().raw_decode(chunk[start:])
            except ValueError:
                start = chunk.find("{", start + 1)
                continue
            if _well_typed(obj):
                return obj
            start = chunk.find("{", start + 1)
    return None


def _well_typed(obj) -> bool:
    if not isinstance(obj, dict) or not isinstance(obj.get("output"), str):
        return False
    for key in ("effects", "claims"):
        items = obj.get(key, [])
        if not isinstance(items, list):
            return False
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                return False
    return True


def _norm_text(data) -> str:
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    return data.replace("\r\n", "\n").rstrip("\n")


def _as_file_bytes(text: str) -> bytes:
    # Text files end with a newline; terminals don't show it
    return text.encode() + (b"\n" if text and not text.endswith("\n") else b"")


class Gate:
    """One session's gate over the world-state.

        gate = Gate(resolve=fs.resolve)
        output, state = gate.turn(state, cmd, candidates, source="cloud")
    """

    def __init__(self, resolve=posixpath.normpath, witness=None):
        self.resolve = resolve
        self.witness = witness
        self.log = []

    # ── Algorithm 1, lines 4-8 ─────────────────────────────────────────────

    def turn(self, inst: Instance, cmd: str, candidates, source: str = "llm"):
        """-> (output for the attacker, committed successor state)."""
        reasons = []
        for i, raw in enumerate(candidates):
            triple = parse_triple(raw)
            if triple is None:
                reasons.append("malformed")
                continue
            verdict = self._check(inst, self.proposal(inst, cmd, triple))
            if verdict.ok:
                self._record(cmd, source, "accepted", i + 1, reasons)
                return triple["output"], verdict.successor
            reasons.append(verdict.reason)
        output, nxt = self.fallback(inst, cmd)
        self._record(cmd, source, "fallback", len(reasons), reasons)
        return output, nxt

    def check_text(self, inst: Instance, cmd: str, output: str, source: str):
        """Gate a free-text answer (Cowrie): claims come from the extractor alone."""
        verdict = self._check(inst, self.proposal(inst, cmd, {"output": output}))
        if verdict.ok:
            self._record(cmd, source, "accepted", 1, [])
            return output, verdict.successor
        out, nxt = self.fallback(inst, cmd)
        self._record(cmd, source, "fallback", 1, [verdict.reason])
        return out, nxt

    def _check(self, inst, prop):
        if self.witness:
            return feasible(inst, prop, self.witness)
        return feasible(inst, prop)

    # ── proposal = declared triple + extracted claims ──────────────────────

    def proposal(self, inst: Instance, cmd: str, triple: dict) -> Proposal:
        add, remove, claims, denies = set(), set(), set(), set()
        for eff in triple.get("effects", []):
            self._effect(inst, eff, add, remove)
        for claim in triple.get("claims", []):
            self._claim(inst, claim, claims, denies)
        ex_claims, ex_denies = self.extract(inst, cmd, triple["output"])
        claims |= ex_claims
        denies |= ex_denies
        return Proposal(triple["output"], frozenset(add), frozenset(remove),
                        frozenset(claims), frozenset(denies))

    def _effect(self, inst, eff, add, remove):
        op, path = eff.get("op"), self.resolve(eff["path"])
        if op in ("create_file", "write", "append"):
            text = eff.get("content", "") or ""
            old = inst.get("content", path)
            data = _as_file_bytes(text)
            if op == "append":
                data = (old or b"") + data if old is not None else None
            for attr in ("content", "size"):
                if inst.get(attr, path) is not None:
                    remove.add(Fact(attr, path, inst.get(attr, path)))
            add.add(Fact("kind", path, "file"))
            if data is not None:
                add |= {Fact("content", path, data), Fact("size", path, len(data))}
        elif op == "create_dir":
            # A directory the attacker creates is closed-world and empty
            add |= {Fact("kind", path, "dir"), Fact("sealed", path)}
        elif op == "remove":
            remove |= _subtree(inst, path)
            add.add(Fact("absent", path))
        elif op == "chmod" and re.fullmatch(r"[0-7]{3,4}", str(eff.get("mode", ""))):
            if inst.get("mode", path) is not None:
                remove.add(Fact("mode", path, inst.get("mode", path)))
            add.add(Fact("mode", path, int(eff["mode"], 8)))

    def _claim(self, inst, claim, claims, denies):
        kind, path = claim.get("type"), self.resolve(claim["path"])
        if kind in ("file", "dir"):
            claims.add(Fact("kind", path, kind))
        elif kind == "absent":
            denies.add(path)
        elif kind == "content":
            claims |= self._content_claim(inst, path, claim.get("content", "") or "")

    def _content_claim(self, inst, path, text):
        stored = inst.get("content", path)
        if stored is not None and _norm_text(stored) == _norm_text(text):
            data = stored
        else:
            data = _as_file_bytes(text)
        return {Fact("kind", path, "file"), Fact("content", path, data)}

    # ── output extractor (Sec. VI-K) ───────────────────────────────────────

    def extract(self, inst: Instance, cmd: str, output: str):
        """Claims the output text makes, whether or not the agent declared them."""
        claims, denies = set(), set()
        args = _path_args(cmd)
        for line in (output or "").splitlines():
            named = [a for a in args if _mentions(line, a)]
            if _DENIAL.search(line):
                denies |= {self.resolve(a) for a in named}
            elif _IS_DIR.search(line):
                claims |= {Fact("kind", self.resolve(a), "dir") for a in named}
        # A successful single-file cat asserts that file's content
        parts = cmd.split()
        if (len(parts) == 2 and parts[0] == "cat" and not parts[1].startswith("-")
                and not denies and not _IS_DIR.search(output or "")
                and not set(cmd) & set("|;&<>`$*?")):
            claims |= self._content_claim(inst, self.resolve(parts[1]), output or "")
        return claims, denies

    # ── fallback: feasible by construction ─────────────────────────────────

    def fallback(self, inst: Instance, cmd: str):
        parts = cmd.split()
        # Serve stored content rather than leak the contradiction (Fig. 1)
        if len(parts) == 2 and parts[0] == "cat":
            path = self.resolve(parts[1])
            kind = inst.get("kind", path)
            if inst.get("content", path) is not None:
                return _norm_text(inst.get("content", path)), inst
            if kind == "dir":
                return f"cat: {parts[1]}: Is a directory", inst
            if kind is None:
                v = self._check(inst, Proposal("", denies=frozenset({path})))
                if v.ok:
                    return f"cat: {parts[1]}: No such file or directory", v.successor
        # Silent output asserts nothing, so it contradicts nothing
        return "", inst

    def _record(self, cmd, source, status, tried, reasons):
        self.log.append({"cmd": cmd, "source": source, "status": status,
                         "candidates_tried": tried, "rejections": list(reasons)})

    def metrics(self) -> dict:
        """Gate counters for the evaluation section."""
        total = len(self.log)
        rejected = sum(len(r["rejections"]) for r in self.log)
        fallback = sum(r["status"] == "fallback" for r in self.log)
        return {"turns": total, "rejected_candidates": rejected,
                "fallbacks": fallback,
                "fallback_rate": fallback / total if total else 0.0}


def _path_args(cmd: str):
    """Arguments that may name paths: not options, not the bare command name."""
    parts = cmd.split()
    args = [p.strip("'\"") for p in parts[1:] if not p.startswith("-")]
    if parts and "/" in parts[0]:
        args.append(parts[0])
    return [a for a in args if a]


def _mentions(line: str, arg: str) -> bool:
    # Whole-token match so a file named "a" doesn't match every line
    return re.search(rf"(?<![\w./-]){re.escape(arg)}(?![\w./-])", line) is not None


def _subtree(inst: Instance, path: str):
    """Every fact about `path` and everything under it."""
    prefix = path.rstrip("/") + "/"
    out = set()
    for fact in inst.facts():
        if fact.rel in ("user", "uid", "gid", "home", "shell", "env", "proc", "cwd"):
            continue
        key = fact.key
        if isinstance(key, str) and (key == path or key.startswith(prefix)):
            out.add(fact)
    return out
