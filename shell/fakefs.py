"""
fakefs.py — the honeypot's pretend filesystem.

Everything that answers "where am I, what path is this, what's in that file".
Moved out of main.py, where it was eight closures inside a 1,500-line function.

READ-ONLY, ON PURPOSE. Nothing here mutates SYSTEM_STATE, runs a command or
talks to Cowrie. That is what lets `cd` be routed to ANY agent and still tracked:
compute_cd() is called twice per command, once to produce the response and once
from update_state() to keep cwd correct no matter who answered. Two callers, one
answer, because the answer has no side effects.

The responders that DO mutate -- _resolve_cd (writes cwd, asks Cowrie) and
_resolve_chmod (calls update_state) -- deliberately stayed in main.py. They are
responders that happen to use this module, not part of it.

PER-SESSION. FakeFS holds one session's state dict, so two SSH sessions can
never see each other's files. That is why this is a class and not a module of
functions reading a global.
"""
import posixpath

# A real filesystem is case- and spelling-agnostic: `foo`, `./foo` and
# `/root/foo` are one file. Every path entering state["files"] goes through
# resolve() so the dict has ONE key per real file.


def mode_to_perms(mode: str) -> str:
    """Numeric chmod mode ('777', '600') -> the `ls -la` string ('-rwxrwxrwx').

    Free function: it reads no state, so there is nothing for a session to own.
    """
    chars = "rwxrwxrwx"
    bits = int(mode[-3:], 8)          # last 3 digits, octal
    perms = "".join(chars[8 - i] if bits & (1 << i) else "-"
                    for i in range(8, -1, -1))
    return f"-{perms}"


class FakeFS:
    """One session's view of the fake filesystem.

        fs = FakeFS(SYSTEM_STATE, username="root", known_dirs=...)
        fs.resolve("../x")          -> "/root/x"
        fs.compute_cd("cd /tmp")    -> (True, "/tmp", None)
        fs.virtual_file("/etc/passwd")

    `state` is held by reference, not copied -- the honeypot mutates it as the
    session runs and every read here must see the current values.
    """

    def __init__(self, state: dict, username: str = "root",
                 known_dirs=frozenset()):
        self.state = state
        self.username = username
        # Standard top-level layout from config.yaml system_state.known_dirs --
        # the same set system_setting.txt declares to the model. Enumerated so
        # `cd /var` resolves deterministically instead of being guessed.
        self.known_dirs = frozenset(known_dirs)
        # Where the last failed compute_cd() pointed. main.py's _resolve_cd
        # reads it to ask Cowrie whether the directory exists after all, before
        # the "No such file" answer reaches the attacker.
        self.last_resolved = None

    # ── paths ───────────────────────────────────────────────────────────────

    def home(self, username: str = None) -> str:
        user = self.state.get("users", {}).get(username or self.username, {})
        return user.get("home", "/root")

    def resolve(self, p: str) -> str:
        """Absolute, normalized form of `p` as the shell sees it from cwd.

        `touch foo` then `cat /root/foo` used to look like two unrelated files,
        and same-named files in different directories collided on one key. cd
        already resolved this way, so every file operation must agree with it.
        """
        if not p:
            return p
        s = p.strip().strip("\"'")
        home = self.home()
        if s == "~":
            s = home
        elif s.startswith("~/"):
            s = home + s[1:]
        if not s.startswith("/"):
            s = posixpath.join(self.state["cwd"], s)
        resolved = posixpath.normpath(s)
        # normpath KEEPS a leading "//" -- POSIX leaves it implementation-
        # defined and posixpath preserves exactly two. That made //tmp/x and
        # /tmp/x two keys for one file, breaking the one-key-per-file rule this
        # method exists to enforce: `touch //tmp/a` then `cat /tmp/a` looked
        # like two unrelated files.
        return "/" + resolved.lstrip("/") if resolved.startswith("//") else resolved

    def directories(self) -> set:
        """Every path this session can `cd` into: the configured layout, every
        user's home, and anything tracked with a directory permission bit."""
        dirs = set(self.known_dirs)
        dirs |= {u["home"] for u in self.state.get("users", {}).values()}
        dirs |= {p for p, f in self.state.get("files", {}).items()
                 if f.get("perms", "").startswith("d")}
        return dirs

    def compute_cd(self, cmd: str):
        """`cd` resolved WITHOUT touching state.

        -> (handled, new_cwd_or_None, error_or_None)
             (True,  "/tmp", None)  cd succeeds; caller sets cwd
             (True,  None,  "...")  cd fails; this is the exact bash error
             (False, None,  None)   not handled here (e.g. `cd -`)
        """
        args = cmd.split()[1:]

        # `cd -` FIRST, before the flag filter. It looks like a flag, so
        # filtering flags removed it, positional came back empty, target
        # defaulted to "~" and the `target == "-"` branch further down could
        # never run -- dead code. `cd /tmp; cd -` landed in /root silently, and
        # the honeypot then disagreed with the attacker about where they were.
        if args[:1] == ["-"]:
            previous = self.state.get("oldpwd")
            if not previous:
                # Real bash before any cd: "OLDPWD not set", cwd unchanged.
                return True, None, "bash: cd: OLDPWD not set"
            # Real `cd -` PRINTS the directory it moved to. The caller shows
            # this, which is why it comes back as the third element even on
            # success -- the one cd form that is not silent.
            return True, previous, previous

        # flags aside, real `cd` takes at most one positional argument
        positional = [a for a in args if not a.startswith("-")]
        if len(positional) > 1:
            return True, None, "bash: cd: too many arguments"

        target = positional[0] if positional else "~"

        home = self.home()
        if target == "~":
            target = home
        elif target.startswith("~/"):
            target = home + target[1:]

        joined = (target if target.startswith("/")
                  else posixpath.join(self.state["cwd"], target))
        resolved = posixpath.normpath(joined)

        if resolved in self.directories():
            return True, resolved, None

        tracked = self.state.get("files", {}).get(resolved)
        if tracked and not tracked.get("perms", "").startswith("d"):
            return True, None, f"bash: cd: {target}: Not a directory"

        # Unknown to US is not the same as absent: Cowrie's filesystem holds
        # ~26,000 entries we never declared, plus whatever plugins/cowrie_fs.py
        # added. `cd coc-student-portal` failed here for a directory `ls` had
        # just listed. The resolved path is published so the caller can ask
        # Cowrie before this answer reaches the attacker.
        self.last_resolved = resolved
        return True, None, f"bash: cd: {target}: No such file or directory"

    # ── who owns a file ─────────────────────────────────────────────────────
    # Two mirrors of one question, kept side by side because getting them
    # backwards is what produced the honeypot's worst contradictions.

    def locally_owned(self, cmd: str):
        """The tracked path this command names that COWRIE MAY NOT HAVE.

        Files made by echo/touch or invented by a model exist only in our
        state, so a command touching one must not be routed to Cowrie.

        A wget/curl download is excluded: Cowrie IS managing that one and holds
        the real bytes. Claiming it here dragged `cat` onto on_device, which
        answered "No such file or directory" for a file `ls` had just listed at
        5,278 bytes.

        Exact token match, deliberately -- see cowrie_owned() for the contrast.
        """
        for token in cmd.split():
            token = token.strip('|;&\'"')
            rec = self.state["files"].get(token)
            if rec is None or rec.get("backend") == "cowrie":
                continue
            return token
        return None

    def cowrie_owned(self, cmd: str):
        """The path this command names that COWRIE DEFINITELY DOES HAVE.

        Anything reading or changing such a file has to go to Cowrie, which
        holds the real bytes -- otherwise `rm README.md` answers "No such file
        or directory" while the very next `cat README.md` prints 5KB.

        RESOLVES relative paths, unlike locally_owned's exact match: the
        attacker types `rm README.md` but it is stored as /root/README.md.
        """
        for token in cmd.split():
            token = token.strip('|;&\'"')
            if not token or token.startswith("-"):
                continue
            path = self.resolve(token)
            rec = self.state["files"].get(path)
            if rec and rec.get("backend") == "cowrie":
                return path
        return None

    # ── file content ────────────────────────────────────────────────────────

    def passwd(self) -> str:
        """/etc/passwd generated from the configured persona."""
        lines = []
        for name, u in self.state.get("users", {}).items():
            uid = u.get("uid", 1000)
            gid = u.get("gid", uid)
            lines.append(f"{name}:x:{uid}:{gid}:{u.get('gecos', name)}:"
                         f"{u.get('home', f'/home/{name}')}:{u.get('shell', '/bin/sh')}")
        return "\n".join(lines)

    def shadow(self) -> str:
        """/etc/shadow generated from the configured persona.

        These are the hashes config.yaml declares for the decoy accounts, not
        anything an attacker submitted -- attacker-supplied credentials never
        reach a prompt or an export.
        """
        return "\n".join(
            f"{name}:{self.state.get('shadow', {}).get(name, '*')}:15800:0:99999:7:::"
            for name in self.state.get("users", {}))

    # Generated on read rather than stored, so editing config.yaml's users is
    # immediately reflected and the two files can never drift apart.
    VIRTUAL_PATHS = ("/etc/passwd", "/etc/shadow")

    def is_virtual(self, path: str) -> bool:
        return path in self.VIRTUAL_PATHS

    def virtual_file(self, path: str):
        """Content for a virtual file, or a tracked file's stored content.
        None when we know nothing about the path."""
        if path == "/etc/passwd":
            return self.passwd()
        if path == "/etc/shadow":
            return self.shadow()
        rec = self.state.get("files", {}).get(self.resolve(path), {})
        return rec.get("content") if rec else None
