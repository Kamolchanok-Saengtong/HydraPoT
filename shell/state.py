
"""
shell/state.py — what changed after a command ran.

One job: the attacker typed something, so what does the fake box look like now?
`touch x` makes a file, `rm x` removes it, `cd /tmp` moves the cwd, `apt remove`
uninstalls, `chmod +x` flips a permission bit.

RUNS FOR EVERY AGENT, ALWAYS. This is the reason it exists separately from the
code that produces the RESPONSE. cowrie, on_device and cloud all answer
commands, and tracking used to live inside the response path -- so when an LLM
answered `cd`, the honeypot silently forgot where the attacker was and every
later path was wrong. Recording is not answering. Keep them apart.

IDEMPOTENT. Re-running record() for a command a deterministic responder already
handled recomputes the identical result. `cd` in particular is computed by
fakefs.compute_cd() here AND in the responder, and being side-effect free is
what lets both callers get the same answer.

PER-SESSION, like everything else in this package.

THE ECHO PARSER lives here because nothing else uses it. Rebuilding a file from
`echo -ne '\\xNN...' >> f` is how chunked-ELF droppers write a binary one piece
at a time, and getting the quoting wrong corrupts the content the agents are
then shown -- see _ECHO_WRITE_RE.
"""
import posixpath
import re

from prompt.prompt_manager import _decode_echo_payload
from shell.fakefs import mode_to_perms


# `echo [flags] <content> >|>> <path>` -- one pattern for all three real forms.
# A looser pattern is what broke SRi: for `echo -e '\xNN...' > f` it kept the
# flag AND the opening quote but ate the closing one, leaving an unbalanced
# string. _decode_echo_payload() then skipped its quote-strip (it needs matching
# quotes) and decoded the stray quote as a literal byte, so the model was shown
# "'Grop/tmp" instead of "Grop/tmp" -- and faithfully echoed the corruption back.
# The flag must survive (echo only expands \xNN with -e/-ne) and the quotes must
# stay balanced for that decode to work.
# `>(?!>)` stops this also matching `>>` and storing a junk "> path" key.
_ECHO_WRITE_RE = re.compile(
    r"""^echo\s+
        (?P<flag>-[a-zA-Z]+\s+)?
        (?:(?P<q>['"])(?P<qbody>.*)(?P=q)|(?P<body>.+?))
        \s*(?P<op>>>|>(?!>))\s*
        (?P<path>.+)$""",
    re.VERBOSE,
)


def echo_write_parts(cmd: str):
    """(flag, quote, body, op, path) for an echo-redirect, else None."""
    m = _ECHO_WRITE_RE.match(cmd.strip())
    if not m:
        return None
    flag = (m.group("flag") or "").strip()
    if m.group("q") is not None:
        quote, body = m.group("q"), m.group("qbody")
    else:
        quote, body = "", (m.group("body") or "").strip()
    return flag, quote, body, m.group("op"), m.group("path").strip()


def split_raw_arg(raw: str):
    r"""Inverse of join_raw_arg: "-ne '\xea'" -> ('-ne', "'", '\xea')."""
    s = (raw or "").strip()
    m = re.match(r"^(-[a-zA-Z]+)\s+(.*)$", s, re.DOTALL)
    flag = m.group(1) if m else ""
    if m:
        s = m.group(2)
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return flag, s[0], s[1:-1]
    return flag, "", s


def join_raw_arg(flag: str, quote: str, body: str) -> str:
    """Rebuild the raw echo argument, quotes balanced so decoding works."""
    return (f"{flag} " if flag else "") + (f"{quote}{body}{quote}" if quote else body)


class StateTracker:
    """Applies one command's effects to one session's state.

        tracker = StateTracker(SYSTEM_STATE, fs, sw)
        tracker.record("touch /tmp/x", response="")

    `fs` is a shell.fakefs.FakeFS and `sw` a shell.software.Software -- the
    path rules and the package list must be the SAME objects the responders
    use, or state and answers drift apart.
    """

    def __init__(self, state: dict, fs, software):
        self.state = state
        self.fs = fs
        self.sw = software

    # ── entry point ─────────────────────────────────────────────────────────

    def record(self, cmd: str, response: str = ""):
        """Apply whatever `cmd` changed. Safe to call for any command."""
        text = cmd.strip()
        bare = text[5:].strip() if text.startswith("sudo ") else text

        # `cd` first and alone: it is the one effect that must be tracked no
        # matter which agent answered, and nothing else below applies to it.
        if bare.split()[:1] == ["cd"]:
            handled, new_cwd, _err = self.fs.compute_cd(bare)
            if handled and new_cwd is not None:
                self.state["cwd"] = new_cwd
            return

        for effect in (self._uninstall, self._remember_version, self._echo_write,
                       self._touch, self._download, self._chpasswd,
                       self._chmod, self._remove, self._mkdir, self._sed,
                       self._move):
            effect(text, response)

    # ── packages ────────────────────────────────────────────────────────────

    def _uninstall(self, cmd, response):
        if not re.search(r'\b(apt|apt-get)\s+(remove|purge)\b', cmd):
            return
        parts = cmd.split()
        verb = next((i for i, p in enumerate(parts) if p in ("remove", "purge")), -1)
        if verb < 0:
            return
        self.sw.remove([p for p in parts[verb + 1:] if not p.startswith("-")])

    def _remember_version(self, cmd, response):
        """Pin whatever a `--version` actually printed.

        Cached so the same tool cannot report two versions in one session --
        including when the answer came from a model, which will not repeat
        itself otherwise.
        """
        m = re.match(r'^(?:sudo\s+)?([\w.\-]+)\s+(--version|-V)', cmd)
        if m and response and m.group(1) not in self.state["versions"]:
            self.state["versions"][m.group(1)] = response.strip().splitlines()[0]

    # ── file content ────────────────────────────────────────────────────────

    def _echo_write(self, cmd, response):
        parts = echo_write_parts(cmd)
        if not parts:
            return
        flag, quote, body, op, path = parts
        path = self.fs.resolve(path)
        existing = self.state["files"].get(path, {})

        if op == ">>" and "content" in existing:
            prev_flag, prev_quote, prev_body = split_raw_arg(existing["content"])
            if prev_flag == flag:
                # Same echo form both times -- merge the payload BODIES inside
                # one quote pair so the result stays a single valid escape
                # string. -n/-ne suppress echo's trailing newline, so those
                # chunks concatenate directly: this is how chunked-ELF droppers
                # rebuild a binary. Any other form gets the newline echo adds.
                sep = "" if "n" in flag else "\n"
                body = prev_body + sep + body
                quote = quote or prev_quote
                content = join_raw_arg(flag, quote, body)
            else:
                content = existing["content"] + "\n" + join_raw_arg(flag, quote, body)
        else:
            content = join_raw_arg(flag, quote, body)

        self.state["files"][path] = {
            "content": content,
            "perms": existing.get("perms", "-rw-r--r--"),
            "size": f"{len(_decode_echo_payload(content))}B",
        }

    def _touch(self, cmd, response):
        m = re.match(r"^touch\s+(.+)$", cmd)
        if not m:
            return
        path = self.fs.resolve(m.group(1))
        self.state["files"].setdefault(
            path, {"content": "", "perms": "-rw-r--r--", "size": "0B"})

    def _download(self, cmd, response):
        """wget/curl -- record the file, and WHO holds the real bytes.

        Cowrie performs the transfer for real. The stored content is only a
        placeholder for the prompt; `backend: cowrie` is what tells every reader
        to go ask Cowrie instead of trusting it.
        """
        m = re.match(r"^curl\s+.*?-o\s+(\S+)", cmd)
        if m:
            url_m = re.search(r"https?://\S+", cmd)
            self.state["files"][self.fs.resolve(m.group(1))] = {
                "content": f"[downloaded from {url_m.group(0) if url_m else 'unknown'}]",
                "source": url_m.group(0) if url_m else "unknown",
                "perms": "-rw-r--r--", "size": "4.2K",
            }
            return
        m = re.match(r"^(wget|curl)\s+.*?(https?://\S+)", cmd)
        if m:
            url = m.group(2)
            name = self.fs.resolve(url.rstrip("/").split("/")[-1] or "index.html")
            self.state["files"][name] = {
                "content": f"[downloaded from {url}]", "source": url,
                "perms": "-rw-r--r--", "size": "4.2K",
                "backend": "cowrie",
            }

    def _sed(self, cmd, response):
        m = re.match(r"^sed\s+(-i\s+)?'s/(.+?)/(.+?)/(g?)'\s+(.+)$", cmd)
        if not m:
            return
        old, new, glob, path = m.group(2), m.group(3), m.group(4), self.fs.resolve(m.group(5))
        rec = self.state["files"].get(path)
        if rec and "content" in rec:
            rec["content"] = (rec["content"].replace(old, new) if glob
                              else rec["content"].replace(old, new, 1))

    # ── metadata and layout ─────────────────────────────────────────────────

    def _chpasswd(self, cmd, response):
        m = re.match(r'^echo\s+["\']?(\w+):(\S+?)["\']?\s*\|\s*chpasswd', cmd)
        if m and m.group(1) in self.state["users"]:
            self.state["shadow"][m.group(1)] = f"$6$salt${m.group(2)}_hashed"

    def _chmod(self, cmd, response):
        m = re.match(r"^chmod\s+\+x\s+(.+)$", cmd)
        if m:
            path = self.fs.resolve(m.group(1))
            if path in self.state["files"]:
                self.state["files"][path]["perms"] = "-rwxr-xr-x"
            return
        m = re.match(r"^chmod\s+(\d{3,4})\s+(.+)$", cmd)
        if m:
            path = self.fs.resolve(m.group(2))
            if path in self.state["files"]:
                self.state["files"][path]["perms"] = mode_to_perms(m.group(1))

    def _remove(self, cmd, response):
        # `rm -rf` is excluded on purpose: it is handled on the response path,
        # where Cowrie owns what actually disappears.
        m = re.match(r"^rm\s+(?!.*-rf)(.+)$", cmd)
        if m:
            self.state["files"].pop(self.fs.resolve(m.group(1)), None)

    def _mkdir(self, cmd, response):
        m = re.match(r"^mkdir\s+(?:-p\s+)?(.+)$", cmd)
        if not m:
            return
        # Stored under the SAME absolute key compute_cd() looks up. `mkdir test`
        # once stored the key "test" while `cd test` resolved "/root/test", so
        # the two never matched and cd reported "No such file or directory" for
        # a directory mkdir had just made.
        target = m.group(1).strip()
        resolved = (target if target.startswith("/")
                    else posixpath.join(self.state["cwd"], target))
        self.state["files"][posixpath.normpath(resolved)] = {
            "perms": "drwxr-xr-x", "size": "4.0K"}

    def _move(self, cmd, response):
        m = re.match(r"^mv\s+(\S+)\s+(\S+)$", cmd)
        if not m:
            return
        src, dst = self.fs.resolve(m.group(1)), self.fs.resolve(m.group(2))
        if src in self.state["files"]:
            self.state["files"][dst] = self.state["files"].pop(src)

