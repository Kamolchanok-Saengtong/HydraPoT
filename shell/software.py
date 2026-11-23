"""
shell/software.py — what is installed on the fake box.

Everything that answers "does this command exist, what version is it, and what
does apt print when you install it". Was seven closures scattered through
main.py's 1,500-line handler.

WHY THESE BELONG TOGETHER. `apt install nmap` has to make `nmap -V` start
working and `nmap` stop saying "command not found" -- three questions, one
answer, and they drifted apart when the code that answered them lived in three
places. Registering an install therefore lives here too: it writes only
state["installed"] and state["versions"], which is exactly what this module is
about. (Contrast shell/fakefs.py, which is strictly read-only, because the
things that mutate ITS state -- cwd, tracked files -- belong to other jobs.)

THREE TIERS OF "INSTALLED", and they mean different things:

    base          what a stock install has (plugins/ubuntu_commands.txt, read from
                    the real image) + system_state.extra_tools - missing_tools.
                    Always available, never install-gated.
    pre_installed   config.yaml system_state.pre_installed. Present at boot but
                    NOT base -- wget, curl. Routing treats these differently
                    from something the attacker installed themselves.
    installed       what this session installed. Per-session, so one attacker's
                    `apt install nmap` is invisible to every other session.

PER-SESSION. `state` is held by reference, so the object always sees the live
dict as the session mutates it.
"""
import functools
import os
import random
import re
import subprocess

# Shell builtins handled directly in main.py's dispatcher. Listed so
# availability and version checks treat them as present too -- otherwise
# `cd --version` reported "command not found" for a thing bash itself provides.
SHELL_BUILTINS = frozenset({
    "cd", "exit", "logout", "clear", "alias", "export",
    "history", "source", "bg", "fg", "jobs", "umask",
})


@functools.lru_cache(maxsize=None)
def _bash_list(flag: str) -> frozenset:
    try:
        out = subprocess.run(["bash", "-c", f"compgen {flag}"], capture_output=True,
                             text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    return frozenset(out.split())


def bash_builtins() -> frozenset:
    return _bash_list("-b")


def bash_keywords() -> frozenset:
    return _bash_list("-k")


def bash_words() -> frozenset:
    """Builtins and reserved words of the real bash on this host.

    Asked of bash itself (compgen) rather than listed here, so `unset`, `help`,
    `for` and the rest are real by the same rule the shell uses.
    """
    return bash_builtins() | bash_keywords() | SHELL_BUILTINS


# A word that could name a command: no shell syntax in it and not a flag. Any
# script is allowed, since bash does not care what letters a command is spelled in.
COMMAND_WORD = re.compile(r"^(?![-~%@^,])[^\s;&|<>(){}\[\]$`'\"\\*?!#=/]+$")


_STOCK_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "plugins", "ubuntu_commands.txt")


def _read_commands(path=None) -> dict:
    """{command: path} from the snapshot (plugins/ubuntu_commands.py writes it).
    A line with no path is a bare name. Empty if the file is missing."""
    path = path or _STOCK_FILE
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(_STOCK_FILE), os.pardir, path)
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    name, _, where = line.partition(" ")
                    out[name] = where.strip()
    except OSError:
        pass
    return out


def stock_commands(path=None) -> frozenset:
    """What a stock install already has."""
    return frozenset(_read_commands(path))


def stock_command_paths(path=None) -> dict:
    """{command: where `which` finds it} on a stock install."""
    return {n: p for n, p in _read_commands(path).items() if p}


_PACKAGES_FILE = os.path.join(os.path.dirname(_STOCK_FILE), "ubuntu_packages.txt")


def stock_packages(path=None) -> dict:
    """{package: version} a stock install ships, from plugins/ubuntu_packages.txt."""
    path = path or _PACKAGES_FILE
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(_STOCK_FILE), os.pardir, path)
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    name, _, ver = line.partition(" ")
                    out[name] = ver
    except OSError:
        pass
    return out


def parse_base_tools(raw) -> set:
    """config.yaml's base_tools -> a set.

    The YAML is written comma-per-line for readability, so one entry may list
    several tools. Parsed here rather than demanding one tool per line.
    """
    tools = set()
    for entry in (raw or []):
        for tool in str(entry).split(","):
            tool = tool.strip()
            if tool:
                tools.add(tool)
    return tools


def random_version() -> str:
    """A plausible x.y.z for a package config.yaml pins no version for."""
    return f"{random.randint(1, 3)}.{random.randint(0, 19)}.{random.randint(0, 9)}"


def canonical_package(pkg: str) -> str:
    """Versioned package name -> the command it actually provides.

    `apt install python3.11` must make `python3` work, not a command called
    "python3.11". Without this, installing a versioned package registered a
    name nothing would ever run.
    """
    for pattern, name in ((r'^python3\.\d+', "python3"), (r'^python2\.\d+', "python2"),
                          (r'^gcc-\d+', "gcc"), (r'^g\+\+-\d+', "g++"),
                          (r'^ruby\d+\.\d+', "ruby"), (r'^php\d+\.\d+', "php"),
                          (r'^nodejs\d+', "node")):
        if re.match(pattern, pkg):
            return name
    return pkg


class Software:
    """One session's installed-software view.

        sw = Software(SYSTEM_STATE, base_tools=..., tool_packages=...,
                      default_versions=...)
        sw.available("nmap")      -> False
        sw.install(["nmap"])      -> registers it
        sw.available("nmap")      -> True
        sw.version("nmap")        -> "nmap 2.7.0"
    """

    def __init__(self, state: dict, base_tools=(), tool_packages=None,
                 default_versions=None, pre_installed=(),
                 stock=(), extra_tools=(), missing_tools=(), stock_pkgs=None, stock_paths=None):
        self.state = state
        # stock install, plus what this persona adds, minus what it lacks
        self._missing_tools = parse_base_tools(missing_tools)
        self._extra_tools = parse_base_tools(base_tools) | parse_base_tools(extra_tools)
        self.stock_paths = dict(stock_paths or {})
        present = (set(stock) - parse_base_tools(missing_tools)) \
            | parse_base_tools(base_tools) | parse_base_tools(extra_tools)
        self.builtins = frozenset(present) | SHELL_BUILTINS | bash_words()
        # Package names are distro-specific DATA (config.yaml
        # system_state.tool_packages); the logic that uses the mapping is here.
        self.tool_packages = dict(tool_packages or {})
        # Version strings pin the persona to a distro release, so they come from
        # config.yaml rather than being literals in code.
        self.default_versions = dict(default_versions or {})
        # Shipped with the box = what the stock image has + what the persona adds.
        # Only the persona's own entries are seeded into the session state; the
        # stock ones are a lookup, so they cost the prompt nothing.
        self.stock_pkgs = dict(stock_pkgs or {})
        self.pre_installed = list(pre_installed or [])
        self._shipped = set(self.stock_pkgs) | set(self.pre_installed)

    # ── availability ────────────────────────────────────────────────────────

    def available(self, cmd_base: str) -> bool:
        """Is this command present? Base tool, installed package, or a command
        provided by an installed package (`nc` from `netcat`)."""
        if cmd_base in self.builtins:
            return True
        if cmd_base in self.state["installed"]:
            return True
        pkg = self.tool_packages.get(cmd_base)
        return bool(pkg and pkg in self.state["installed"])

    def path_of(self, name: str):
        """Where `which` finds a command, or None. A file-backed command only:
        stock (path read from the image), an extra, or one this session installed."""
        if name in self._missing_tools:
            return None
        if name in self.stock_paths:
            return self.stock_paths[name]
        if name in self._extra_tools or name in self.state["installed"]:
            return f"/usr/bin/{name}"
        pkg = self.tool_packages.get(name)
        return f"/usr/bin/{name}" if pkg and pkg in self.state["installed"] else None

    def kind(self, name: str):
        """How bash resolves a name: keyword, builtin, file, or None."""
        if name in bash_keywords():
            return "keyword"
        if name in bash_builtins():
            return "builtin"
        return "file" if self.path_of(name) else None

    def installed_by_attacker(self, cmd_base: str) -> bool:
        """Present, but NOT base and NOT there at boot -- the attacker put it
        here. Routing cares: a tool they installed themselves is worth a better
        agent than a coreutil."""
        if cmd_base in self.builtins:
            return False
        if (cmd_base in self.state["installed"]
                and cmd_base not in self._shipped):
            return True
        pkg = self.tool_packages.get(cmd_base)
        return bool(pkg and pkg in self.state["installed"]
                    and pkg not in self._shipped)

    # ── versions ────────────────────────────────────────────────────────────

    def version(self, cmd_base: str) -> str:
        """`--version` output, decided once and remembered.

        Cached into state["versions"] on first ask so the same tool never
        reports two different versions in one session -- a contradiction an
        attacker can probe for with two identical commands.
        """
        if cmd_base in self.state["versions"]:
            return self.state["versions"][cmd_base]
        if cmd_base in self.default_versions:
            self.state["versions"][cmd_base] = self.default_versions[cmd_base]
            return self.state["versions"][cmd_base]
        info = self.state["installed"].get(cmd_base, {})
        if not info and cmd_base in self.stock_pkgs:
            info = {"version": self.stock_pkgs[cmd_base]}
        ver = (info.get("version_str")
               or f"{cmd_base} version {info.get('version', '1.0.0')}")
        self.state["versions"][cmd_base] = ver
        return ver

    # ── installing ──────────────────────────────────────────────────────────

    def seed_pre_installed(self):
        """Register what the box ships with, at session start.

        The version NUMBER is parsed out of the configured display string so
        `wget --version` and the apt output agree -- they were two independent
        strings before, and disagreed.
        """
        for pkg in self.pre_installed:
            if pkg in self.state["installed"]:
                continue
            display = self.default_versions.get(pkg)
            match = re.search(r'(\d+\.\d+(?:\.\d+)*)', display or "")
            ver_num = match.group(1) if match else "1.0.0"
            self.state["installed"][pkg] = {
                "version": ver_num,
                "version_str": display or f"{pkg} version {ver_num}",
            }

    def install(self, pkgs: list, log=print):
        """Register packages as installed. Idempotent per package."""
        for pkg in pkgs:
            name = canonical_package(pkg)
            if name in self.state["installed"]:
                continue
            ver_num = random_version()
            self.state["installed"][name] = {
                "version": ver_num,
                "version_str": self.default_versions.get(name) or f"{name} {ver_num}",
            }
            if log:
                log(f"[state] installed: {name} {ver_num}")

    def apt_output(self, pkgs: list) -> str:
        """What `apt install` prints. Call install() first -- this reads the
        versions that registered, so the transcript matches the state."""
        total_kb = sum(random.randint(200, 900) for _ in pkgs)
        total_mb = round(total_kb * 2.2 / 1024, 1)

        def ver(pkg):
            return self.state["installed"][canonical_package(pkg)]["version"]

        lines = [
            "Reading package lists... Done",
            "Building dependency tree",
            "Reading state information... Done",
            "The following NEW packages will be installed:",
            f"  {' '.join(pkgs)}",
            f"0 upgraded, {len(pkgs)} newly installed, 0 to remove and 259 not upgraded.",
            f"Need to get {total_kb}.2kB of archives.",
            f"After this operation, {total_mb}MB of additional disk space will be used.",
        ]
        lines += [f"Get:1 http://archive.ubuntu.com/ubuntu jammy/main amd64 "
                  f"{pkg} {ver(pkg)} [{random.randint(200, 900)}.2 kB]" for pkg in pkgs]
        lines += [
            f"Fetched {total_kb}.2kB in 1s (4493B/s)",
            "Selecting previously unselected package(s).",
            "(Reading database ... 177887 files and directories currently installed.)",
        ]
        for pkg in pkgs:
            lines.append(f"Preparing to unpack .../archives/{pkg}_{ver(pkg)}_amd64.deb ...")
            lines.append(f"Unpacking {pkg} ({ver(pkg)}) ...")
        lines.append("Processing triggers for man-db (2.10.2-1) ...")
        lines += [f"Setting up {pkg} ({ver(pkg)}) ..." for pkg in pkgs]
        return "\n".join(lines)

    def remove(self, pkgs: list):
        """`apt remove/purge` -- drop the package and its cached version."""
        for pkg in pkgs:
            self.state["installed"].pop(pkg, None)
            self.state["versions"].pop(pkg, None)
