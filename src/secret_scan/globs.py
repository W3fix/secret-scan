"""Gitignore-style path globs, compiled to regular expressions.

The standard library's ``fnmatch`` lets ``*`` cross directory separators and
has no ``**``. Path rules need both behaviours, so this is a small translator
instead of a dependency.
"""

from __future__ import annotations

import re


def compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile a glob matched against a POSIX path relative to the scan root.

    - ``*`` matches within one path segment, ``?`` one character.
    - ``**`` matches across segments; ``**/`` may match nothing.
    - A pattern with no ``/`` matches at any depth (``*.pem``).
    - A trailing ``/`` matches everything under that directory.
    """
    pat = pattern.strip()
    if not pat:
        raise ValueError("empty glob")
    if pat.endswith("/"):
        pat += "**"
    if "/" not in pat:
        pat = "**/" + pat
    pat = pat.removeprefix("/")

    out: list[str] = []
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        elif pat[i] == "[":
            end = pat.find("]", i + 1)
            if end == -1:
                out.append(re.escape(pat[i]))
                i += 1
            else:
                body = pat[i + 1 : end].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = end + 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")
