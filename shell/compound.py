"""
shell/compound.py -- split a command line into the commands bash runs in order.

`a ; b`, `a && b` and `a || b` are several commands, not one. Splitting happens
outside quotes and substitutions only; anything this does not model (loops,
conditionals, here-documents, subshell groups) is left whole so the existing
path answers it exactly as before.
"""
import re

_FAILED = re.compile(
    r"No such file or directory|command not found|Permission denied|Is a directory"
    r"|Not a directory|File exists|cannot (access|stat|remove|create|open|move|copy|touch)"
    r"|invalid option|missing operand|omitting directory|applet not found"
    r"|Operation not permitted|unable to resolve", re.I)
# Shell keywords only mean something where a command starts; `echo done` is an argument
_KEYWORDS = re.compile(r"(^|[;&|(]\s*|\{\s+)"
                       r"(if|then|else|elif|fi|for|while|until|do|done|case|esac|function)\b")


def split(text: str):
    """[(command, operator before it)] or None when the line is a single command.

    The operator is None for the first command, else ';', '&&' or '||'.
    """
    if "<<" in text or _KEYWORDS.search(text) or ";;" in text:
        return None
    parts, buf, op = [], [], None
    depth, quote, i, n = 0, None, 0, len(text)
    while i < n:
        c = text[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c == "\\" and i + 1 < n:
            buf += [c, text[i + 1]]
            i += 1
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c == "`":
            end = text.find("`", i + 1)
            if end < 0:
                return None
            buf.append(text[i:end + 1])
            i = end
        elif c == "$" and text[i + 1:i + 2] in ("(", "{"):
            depth += 1
            buf += [c, text[i + 1]]
            i += 1
        elif c == "(" or (c == "{" and text[i + 1:i + 2] in (" ", "")):
            depth += 1
            buf.append(c)
        elif c in ")}" and depth:
            depth -= 1
            buf.append(c)
        elif depth == 0 and (c == ";" or text[i:i + 2] in ("&&", "||")):
            sep = c if c == ";" else text[i:i + 2]
            parts.append(("".join(buf).strip(), op))
            buf, op = [], sep
            i += len(sep) - 1
        else:
            buf.append(c)
        i += 1
    if quote or depth:
        return None
    parts.append(("".join(buf).strip(), op))
    parts = [(t, o) for t, o in parts if t]
    if len(parts) < 2:
        return None
    parts[0] = (parts[0][0], None)
    return parts


def failed(output: str) -> bool:
    """A command's exit status, read back from what it printed."""
    return bool(_FAILED.search(output or ""))


def runs(op, last_ok: bool) -> bool:
    """Does the command after `op` run, given how the previous one ended?"""
    return op in (None, ";") or (op == "&&" and last_ok) or (op == "||" and not last_ok)
