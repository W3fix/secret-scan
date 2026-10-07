"""Match rules against content and decide what counts as a finding.

A finding records where something is, which rule matched, and how long the
match is. It deliberately has no field for the matched text, so no output
format, log line or error message can include it by accident.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from secret_scan.config import LOCAL_FILE, Settings
from secret_scan.rules import looks_like_placeholder, shannon_entropy
from secret_scan.sources import Candidate

#: Bytes inspected for a NUL to decide a file is binary (the same heuristic git uses).
_BINARY_SNIFF = 8000

#: ``secret-scan:allow <reason>`` on the line, or alone on the line above.
_INLINE_ALLOW = re.compile(r"secret-scan:allow(?P<reason>[ \t]+\S[^\r\n]*)?")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int | None
    column: int | None
    rule: str
    length: int
    note: str = ""

    def sort_key(self) -> tuple[str, int, int, str]:
        # Path-rule findings have no line; they sort first within their file.
        return (self.path, self.line or 0, self.column or 0, self.rule)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    skipped_binary: int = 0
    skipped_large: list[str] = field(default_factory=list)
    ignored: int = 0


class _Lines:
    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def locate(self, offset: int) -> tuple[int, int]:
        """1-based line and column for a character offset."""
        idx = bisect.bisect_right(self.starts, offset) - 1
        return idx + 1, offset - self.starts[idx] + 1

    def line(self, number: int) -> str:
        if number < 1 or number > len(self.starts):
            return ""
        start = self.starts[number - 1]
        end = self.starts[number] if number < len(self.starts) else len(self.text)
        return self.text[start:end]


def _inline_allow(lines: _Lines, line_no: int) -> str | None:
    """Return ``"ok"`` if suppressed, ``"no-reason"`` if marked without a reason."""
    m = _INLINE_ALLOW.search(lines.line(line_no))
    if m is None:
        above = lines.line(line_no - 1)
        m = _INLINE_ALLOW.search(above)
        # Above-line markers only count when the marker is the line's content
        # (behind a comment leader), so a stray mention elsewhere doesn't
        # silence the next line.
        if m is None or not re.fullmatch(r"\s*(?:#|//|--|;|/\*|<!--|\*)?\s*", above[: m.start()]):
            return None
    return "ok" if m.group("reason") else "no-reason"


def scan_text(path: str, text: str, settings: Settings) -> list[Finding]:
    lines = _Lines(text)
    # (start, end, generic, finding)
    hits: list[tuple[int, int, bool, Finding]] = []
    for rule in settings.content_rules:
        for m in rule.pattern.finditer(text):
            start, end = rule.secret_span(m)
            if end <= start:
                continue
            value = text[start:end]
            if rule.check_placeholder and looks_like_placeholder(value):
                continue
            if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                continue
            line_no, col = lines.locate(start)
            if rule.line_requires and not rule.line_requires.search(lines.line(line_no)):
                continue
            if any(a.matches(rule.id, path, value) for a in settings.allow):
                continue
            note = ""
            inline = _inline_allow(lines, line_no)
            if inline == "ok":
                continue
            if inline == "no-reason":
                note = "inline allow ignored: add a reason after secret-scan:allow"
            hits.append(
                (start, end, rule.generic, Finding(path, line_no, col, rule.id, end - start, note))
            )

    specific = [(s, e) for s, e, generic, _ in hits if not generic]
    findings = [
        f
        for s, e, generic, f in hits
        if not (generic and any(s < se and ss < e for ss, se in specific))
    ]
    return sorted(set(findings), key=Finding.sort_key)


def scan_path_rules(path: str, settings: Settings) -> list[Finding]:
    name = PurePosixPath(path).name
    out: list[Finding] = []
    for rule in settings.path_rules:
        if rule.pattern.match(name) and not any(
            a.matches(rule.id, path, None) for a in settings.allow
        ):
            out.append(Finding(path, None, None, rule.id, len(name)))
    return out


def scan(candidates: Iterable[Candidate], settings: Settings) -> ScanResult:
    result = ScanResult()
    for c in candidates:
        if PurePosixPath(c.path).name == LOCAL_FILE:
            continue  # It holds the private terms; scanning it would flag every one.
        if settings.is_ignored(c.path):
            result.ignored += 1
            continue
        result.findings.extend(scan_path_rules(c.path, settings))
        if c.size > settings.max_file_bytes:
            result.skipped_large.append(c.path)
            continue
        data = c.read()
        if b"\0" in data[:_BINARY_SNIFF]:
            result.skipped_binary += 1
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(c.path, data.decode("utf-8", "replace"), settings))
    result.findings.sort(key=Finding.sort_key)
    return result
