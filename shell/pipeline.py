"""
shell/pipeline.py -- the filters that follow a `|`, run exactly.

`ps aux | grep sshd` went to Cowrie whole, and Cowrie's piped `ps` has no
COMMAND column: the grep found nothing, on a box with sshd running. The rule
core answers the first command from the register; this module answers what the
pipe does to that text.

Only what is modelled completely is answered. Any flag or shape not handled
here returns None and the line takes the old path unchanged.
"""
import re
import shlex


def split_pipes(text: str):
    """Top-level `|` stages, or None when the line is not a plain pipeline.

    `||`, `;`, `&`, redirects, `$(`, backticks and a newline are not modelled.
    """
    stages, cur, quote, i, n = [], [], None, 0, len(text)
    while i < n:
        c = text[i]
        if quote:
            cur.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                i += 1
                cur.append(text[i])
            elif c == quote:
                quote = None
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c == "\\" and i + 1 < n:
            cur.append(c + text[i + 1])
            i += 1
        elif c == "|":
            if i + 1 < n and text[i + 1] == "|":
                return None
            stages.append("".join(cur))
            cur = []
        elif c == ">" and text[:i].endswith("2") and re.match(r">\s*/dev/null(?![\w/.-])", text[i:]):
            m = re.match(r">\s*/dev/null", text[i:])        # `2>/dev/null`: stderr thrown away
            cur.append(m.group(0))
            i += len(m.group(0)) - 1
        elif c in ";&<>`\n" or text.startswith("$(", i):
            return None
        else:
            cur.append(c)
        i += 1
    if quote:
        return None
    stages.append("".join(cur))
    stages = [s.strip() for s in stages]
    return stages if len(stages) > 1 and all(stages) else None


def _lines(data: str) -> list:
    return data.split("\n") if data else []


def _bre(pattern: str) -> str:
    """POSIX basic regex -> Python: `\\|`, `\\(`, `\\)`, `\\{`, `\\}` are the
    operators, and a bare `+ ? | ( ) { }` is a literal."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            out.append(nxt if nxt in "|(){}+?" else "\\" + nxt)
            i += 2
            continue
        out.append("\\" + c if c in "+?|(){}" else c)
        i += 1
    return "".join(out)


def _grep(argv, data, name):
    flags, pats, rest, it = set(), [], [], iter(argv[1:])
    for a in it:
        if a in ("-e", "--regexp"):
            pats.append(next(it, None))
        elif a.startswith("--"):
            if a.split("=")[0] not in ("--color", "--colour", "--line-buffered", "--ignore-case",
                                       "--invert-match", "--count", "--extended-regexp"):
                return None
            if a in ("--ignore-case",):
                flags.add("i")
            elif a == "--invert-match":
                flags.add("v")
            elif a == "--count":
                flags.add("c")
            elif a == "--extended-regexp":
                flags.add("E")
        elif a.startswith("-") and len(a) > 1 and not rest:
            flags |= set(a[1:])
        else:
            rest.append(a)
    if flags - set("ivcEFwxnq"):
        return None
    if not pats:
        if not rest:
            return None
        pats = [rest.pop(0)]
    if rest or None in pats:
        return None                    # file operands: not a stdin filter
    if name == "egrep":
        flags.add("E")
    if name == "fgrep":
        flags.add("F")
    try:
        parts = [re.escape(p) if "F" in flags else (p if "E" in flags else _bre(p)) for p in pats]
        rx = "|".join(f"(?:{p})" for p in parts)
        if "w" in flags:
            rx = rf"(?<!\w)(?:{rx})(?!\w)"
        if "x" in flags:
            rx = rf"^(?:{rx})$"
        rx = re.compile(rx, re.I if "i" in flags else 0)
    except re.error:
        return None
    hits = [(n, l) for n, l in enumerate(_lines(data), 1) if bool(rx.search(l)) != ("v" in flags)]
    if "q" in flags:
        return "", 0 if hits else 1
    if "c" in flags:
        return str(len(hits)), 0 if hits else 1
    out = [f"{n}:{l}" if "n" in flags else l for n, l in hits]
    return "\n".join(out), 0 if hits else 1


def _count_arg(argv, default=10):
    """-n N, -nN, -N -> N, else None when something else is asked for."""
    n, i = default, 1
    while i < len(argv):
        a = argv[i]
        if a == "-n" and i + 1 < len(argv) and argv[i + 1].isdigit():
            n, i = int(argv[i + 1]), i + 2
        elif re.fullmatch(r"-n\d+", a):
            n, i = int(a[2:]), i + 1
        elif re.fullmatch(r"-\d+", a):
            n, i = int(a[1:]), i + 1
        else:
            return None
    return n


def _head(argv, data):
    n = _count_arg(argv)
    return None if n is None else ("\n".join(_lines(data)[:n]), 0)


def _tail(argv, data):
    n = _count_arg(argv)
    if n is None:
        return None
    lines = _lines(data)
    return ("\n".join(lines[-n:] if n else []), 0)


def _wc(argv, data):
    flags = set()
    for a in argv[1:]:
        if re.fullmatch(r"-[lwcm]+", a):
            flags |= set(a[1:])
        else:
            return None
    lines = data.count("\n") + (1 if data else 0)
    raw = data + "\n" if data else ""
    vals = {"l": lines, "w": len(data.split()), "c": len(raw.encode()), "m": len(raw)}
    if not flags:
        flags = set("lwc")
    order = [f for f in "lwcm" if f in flags]
    if len(order) == 1:
        return str(vals[order[0]]), 0
    return " ".join(f"{vals[f]:>7}" for f in order), 0


def _collate(s: str):
    """en_US.UTF-8 order, approximately: punctuation ignored, case second."""
    return (re.sub(r"[^0-9A-Za-z]", "", s).casefold(), s.swapcase())


def _sort(argv, data):
    flags, sep, field, i = set(), None, None, 1
    while i < len(argv):
        a = argv[i]
        if re.fullmatch(r"-[rnu]+", a):
            flags |= set(a[1:])
        elif a == "-t" and i + 1 < len(argv) and len(argv[i + 1]) == 1:
            sep, i = argv[i + 1], i + 1
        elif re.fullmatch(r"-t.", a):
            sep = a[2:]
        elif a == "-k" and i + 1 < len(argv):
            field, i = argv[i + 1], i + 1
        elif re.fullmatch(r"-k\d+[nr]*", a):
            field = a[2:]
        else:
            return None
        i += 1
    if field is not None:
        m = re.fullmatch(r"(\d+)([nr]*)", field)
        if not m or int(m.group(1)) < 1:
            return None
        field, flags = int(m.group(1)), flags | set(m.group(2))

    def piece(line):
        if field is None:
            return line
        cols = line.split(sep) if sep else line.split()
        return (sep or " ").join(cols[field - 1:])

    def num(line):
        m = re.match(r"\s*(-?\d+(?:\.\d+)?)", piece(line))
        return (float(m.group(1)) if m else 0.0, line)

    key = num if "n" in flags else (lambda l: _collate(piece(l)) + (l,))
    out = sorted(_lines(data), key=key, reverse="r" in flags)
    if "u" in flags:
        seen, uniq = set(), []
        for l in out:
            k = key(l)[0] if "n" in flags else _collate(piece(l))
            if k not in seen:
                seen.add(k)
                uniq.append(l)
        out = uniq
    return "\n".join(out), 0


def _uniq(argv, data):
    flags = set()
    for a in argv[1:]:
        if a == "-c":
            flags.add("c")
        else:
            return None
    groups = []
    for l in _lines(data):
        if groups and groups[-1][0] == l:
            groups[-1][1] += 1
        else:
            groups.append([l, 1])
    return "\n".join(f"{n:>7} {l}" if "c" in flags else l for l, n in groups), 0


def _fields(spec: str, count: int):
    out = []
    for part in spec.split(","):
        m = re.fullmatch(r"(\d*)(-?)(\d*)", part)
        if not m or not part:
            return None
        lo, dash, hi = m.groups()
        if not dash:
            if not lo or int(lo) < 1:
                return None
            out.append(int(lo))
        else:
            a, b = int(lo or 1), int(hi or count)
            out.extend(range(a, b + 1))
    return out


def _cut(argv, data):
    delim, spec, i, chars = "\t", None, 1, False
    while i < len(argv):
        a = argv[i]
        if a == "-c" and i + 1 < len(argv):
            spec, chars, i = argv[i + 1], True, i + 2
        elif a.startswith("-c") and len(a) > 2:
            spec, chars, i = a[2:], True, i + 1
        elif a == "-d" and i + 1 < len(argv):
            delim, i = argv[i + 1], i + 2
        elif a.startswith("-d") and len(a) > 2:
            delim, i = a[2:], i + 1
        elif a == "-f" and i + 1 < len(argv):
            spec, i = argv[i + 1], i + 2
        elif a.startswith("-f") and len(a) > 2:
            spec, i = a[2:], i + 1
        else:
            return None
    if spec is None or len(delim) != 1:
        return None
    out = []
    for line in _lines(data):
        if chars:
            idx = _fields(spec, len(line))
            if idx is None:
                return None
            out.append("".join(line[k - 1] for k in sorted(set(idx)) if k <= len(line)))
            continue
        if delim not in line:
            out.append(line)
            continue
        cols = line.split(delim)
        idx = _fields(spec, len(cols))
        if idx is None:
            return None
        out.append(delim.join(cols[k - 1] for k in sorted(set(idx)) if k <= len(cols)))
    return "\n".join(out), 0


_AWK = re.compile(r"""^\{\s*print(?:\s+(?P<args>\$(?:NF|\d+)(?:\s*,\s*\$(?:NF|\d+))*))?\s*;?\s*\}$""")


def _awk(argv, data):
    fs, rest = None, argv[1:]
    if rest and rest[0] == "-F" and len(rest) > 1:
        fs, rest = rest[1], rest[2:]
    elif rest and rest[0].startswith("-F") and len(rest[0]) > 2:
        fs, rest = rest[0][2:], rest[1:]
    if len(rest) != 1 or (fs is not None and len(fs) != 1):
        return None
    m = _AWK.match(rest[0].replace("\\$", "$").strip())
    if not m:
        return None
    wanted = [w.strip() for w in (m.group("args") or "$0").split(",")]
    out = []
    for line in _lines(data):
        cols = line.split(fs) if fs else line.split()
        vals = []
        for w in wanted:
            k = len(cols) if w == "$NF" else int(w[1:])
            vals.append(line if k == 0 else cols[k - 1] if 1 <= k <= len(cols) else "")
        out.append(" ".join(vals))
    return "\n".join(out), 0


def _cat(argv, data):
    return (data, 0) if len(argv) == 1 else None


_FILTERS = {"head": _head, "tail": _tail, "wc": _wc, "sort": _sort, "uniq": _uniq,
            "cut": _cut, "awk": _awk, "cat": _cat}


def run_filter(stage: str, data: str):
    """(output, exit status) for one filter reading `data`, or None."""
    stage = re.sub(r"\s+2>\s*/dev/null\s*$", "", stage)          # a filter's own stderr is not output
    try:
        argv = shlex.split(stage)
    except ValueError:
        return None
    if not argv:
        return None
    name = argv[0]
    if name in ("grep", "egrep", "fgrep"):
        return _grep(argv, data, name)
    fn = _FILTERS.get(name)
    return fn(argv, data) if fn else None
