"""
shell/routing.py — does this command need a model at all?

NOT the same question as router.py's. That one picks WHICH agent (cowrie /
on_device / cloud) from the FI band. This one asks whether a model is needed at
all for THIS session's state -- and the answer changes as the session runs.
`cat notes.txt` needs a model only once notes.txt exists and only we have it.

ONE RULE UNDERNEATH ALL OF THEM: a model is needed when the honest answer
depends on something only THIS session knows. Cowrie cannot read a file that
exists only in our state, cannot report a version the attacker installed here,
and cannot know what a script the attacker wrote would print.

THE INVERSE MATTERS JUST AS MUCH. A file Cowrie really downloaded is NOT ours,
even though it is in our files dict -- the stored content is a placeholder and
Cowrie holds the true bytes. Claiming it sent `cat` to on_device, which then
answered "No such file or directory" for a file `ls` had just listed at 5,278
bytes. Hence the `backend == "cowrie"` skip below.
"""
import re

# Answered from local state rather than the container: our service table, our
# hostname, our compiler behaviour.
_ALWAYS = frozenset({"systemctl", "service", "journalctl", "hostname",
                     "gcc", "g++", "make", "gdb", "strace", "ltrace"})

# Tools whose version flag is lowercase -v. The shared pattern below is
# `--version|-V`, which is right for coreutils but wrong for these -- and
# widening the pattern is not the fix, because `-v` means INVERT for grep and
# VERBOSE for rm, ssh and curl. Per-tool, not per-regex.
_LOWERCASE_V = frozenset({"nginx", "php", "node", "npm", "redis-server",
                          "redis-cli", "mysql", "mysqld"})

# Interpreters: only interesting when the script they are given is one WE hold.
_INTERPRETERS = frozenset({"bash", "sh", "python", "python3", "perl",
                           "node", "ruby", "php", "lua"})


class Routing:
    """One session's needs-a-model decision.

        routing = Routing(SYSTEM_STATE, fs, sw)
        routing.needs_llm("cat notes.txt", "cat")   -> True once we hold it
    """

    def __init__(self, state: dict, fs, software):
        self.state = state
        self.fs = fs
        self.sw = software

    def needs_llm(self, cmd: str, cmd_base: str) -> bool:
        text = cmd.strip()
        files = self.state.get("files", {})

        # A version query is answerable only for a tool that exists here.
        if self.is_version_query(cmd, cmd_base):
            return self.sw.available(cmd_base)

        if cmd_base in _ALWAYS:
            return True

        # Installed by the attacker, not shipped with the box. Was two
        # near-identical blocks (direct name, then the package that provides
        # it); Software.installed_by_attacker owns both cases.
        if self.sw.installed_by_attacker(cmd_base):
            return True

        if cmd_base in _INTERPRETERS:
            parts = text.split()
            if len(parts) > 1 and self._is_ours(parts[1], files):
                return True

        if text.startswith("./"):
            if text[2:].split()[0] in files:
                return True

        if cmd_base == "cat":
            return any(self._cat_needs_model(arg, files)
                       for arg in text.split()[1:])

        if cmd_base == "sed":
            parts = text.split()
            return len(parts) > 1 and parts[-1] in files

        return False

    @staticmethod
    def is_version_query(cmd: str, cmd_base: str) -> bool:
        """`--version`, `-V`, or `-v` for the tools that spell it that way."""
        if re.search(r'--version\b|-V\b', cmd):
            return True
        return cmd_base in _LOWERCASE_V and re.search(r'(?<!\S)-v\b', cmd) is not None

    # ── helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _is_ours(token: str, files: dict) -> bool:
        """Tracked here AND holding content we wrote. Exact token, no resolve --
        matching the original, which only ever saw the literal argument."""
        return token in files and bool(files[token].get("content"))

    def _cat_needs_model(self, arg: str, files: dict) -> bool:
        if arg.startswith("-"):
            return False
        if self.fs.is_virtual(arg):
            return True                   # generated on read, always has content
        path = self.fs.resolve(arg)
        record = files.get(path)
        if not record or not record.get("content"):
            return False
        # Cowrie downloaded it and holds the real bytes; ours is a placeholder.
        return record.get("backend") != "cowrie"
