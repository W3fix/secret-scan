"""Match rules against content and decide what counts as a finding.

A finding records where something is, which rule matched, and how long the
match is. It deliberately has no field for the matched text, so no output
format, log line or error message can include it by accident.
"""

from __future__ import annotations

import bisect
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from secret_scan.config import LOCAL_FILE, WITHHELD_REASON, Settings
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


@dataclass(frozen=True)
class InlineAllow:
    """A match skipped by an inline ``secret-scan:allow``.

    Like a finding, it has no field for the matched text. A reason that
    contains matched text is replaced before it's stored.
    """

    path: str
    line: int
    rule: str
    reason: str
    #: In history, the commit whose version of the line had the marker.
    commit: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    skipped_binary: int = 0
    skipped_large: list[str] = field(default_factory=list)
    ignored: int = 0
    #: Matches each configured allow entry skipped, and files each ignore entry
    #: skipped, by the entry's source.
    applied: Counter[str] = field(default_factory=Counter)
    inline_allows: list[InlineAllow] = field(default_factory=list)


class _Lines:
    def __init__(self, text: str, first_line: int = 1) -> None:
        self.text = text
        #: The number of the text's first line: more than 1 when it's an excerpt.
        self.first = first_line
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def locate(self, offset: int) -> tuple[int, int]:
        """Line and column (from 1) for a character offset."""
        idx = bisect.bisect_right(self.starts, offset) - 1
        return idx + self.first, offset - self.starts[idx] + 1

    def start(self, number: int) -> int:
        return self.starts[number - self.first]

    def line(self, number: int) -> str:
        idx = number - self.first
        if idx < 0 or idx >= len(self.starts):
            return ""
        end = self.starts[idx + 1] if idx + 1 < len(self.starts) else len(self.text)
        return self.text[self.starts[idx] : end]


@dataclass(frozen=True)
class _Marker:
    #: Empty when the marker gives no reason.
    reason: str
    #: Where the reason sits in the scanned text.
    start: int
    end: int


def _inline_allow(lines: _Lines, line_no: int) -> _Marker | None:
    """The ``secret-scan:allow`` marker that covers ``line_no``, if any."""
    number = line_no
    m = _INLINE_ALLOW.search(lines.line(number))
    if m is None:
        number = line_no - 1
        above = lines.line(number)
        m = _INLINE_ALLOW.search(above)
        # Above-line markers only count when the marker is the line's content
        # (behind a comment leader), so a stray mention elsewhere doesn't
        # silence the next line.
        if m is None or not re.fullmatch(r"\s*(?:#|//|--|;|/\*|<!--|\*)?\s*", above[: m.start()]):
            return None
    offset = lines.start(number)
    if not m.group("reason"):
        return _Marker("", offset + m.end(), offset + m.end())
    return _Marker(m.group("reason").strip(), offset + m.start("reason"), offset + m.end("reason"))


def scan_text(
    path: str,
    text: str,
    settings: Settings,
    record: ScanResult | None = None,
    *,
    first_line: int = 1,
    in_scope: Callable[[int, int], bool] | None = None,
    exceptions: bool = True,
) -> list[Finding]:
    """Findings in ``text``. Exceptions that skip a match are noted in ``record``.

    History scanning passes an excerpt of a file: ``first_line`` numbers its
    first line, and ``in_scope(first, last)`` keeps only matches on the lines a
    commit added. ``exceptions=False`` reports what allow entries and inline
    markers would skip, to tell whether a value is still present at all.
    """
    lines = _Lines(text, first_line)
    # (start, end, rank, finding)
    hits: list[tuple[int, int, int, Finding]] = []
    # (start, end, rank, allow entry source or inline allow)
    skipped: list[tuple[int, int, int, str | InlineAllow]] = []
    for rule in settings.content_rules:
        if not rule.applies_to(path):
            continue
        for m in rule.pattern.finditer(text):
            start, end = rule.secret_span(m)
            if end <= start:
                continue
            if in_scope:
                last = rule.secret_end(text, end) - 1
                if not in_scope(lines.locate(start)[0], lines.locate(last)[0]):
                    continue
            value = text[start:end]
            if rule.check_placeholder and looks_like_placeholder(value):
                continue
            if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                continue
            if rule.well_formed and not rule.well_formed(value):
                continue
            line_no, col = lines.locate(start)
            if rule.line_requires and not rule.line_requires.search(lines.line(line_no)):
                continue
            if exceptions:
                allowed_by = next(
                    (a.source for a in settings.allow if a.matches(rule.id, path, value)), None
                )
                if allowed_by is not None:
                    skipped.append((start, end, rule.rank, allowed_by))
                    continue
            note = ""
            marker = _inline_allow(lines, line_no) if exceptions else None
            if marker is not None and marker.reason:
                # A reason that runs over the match would repeat the value.
                overlaps = marker.start < end and start < marker.end
                reason = WITHHELD_REASON if overlaps else settings.safe_reason(marker.reason)
                skipped.append((start, end, rule.rank, InlineAllow(path, line_no, rule.id, reason)))
                continue
            if marker is not None:
                note = "inline allow ignored: add a reason after secret-scan:allow"
            hits.append(
                (start, end, rule.rank, Finding(path, line_no, col, rule.id, end - start, note))
            )

    # A finding is dropped when a better-ranked rule matches overlapping text.
    findings = [
        f
        for s, e, rank, f in hits
        if not any(r < rank and s < he and hs < e for hs, he, r, _ in hits)
    ]
    if record is not None:
        # The same overlap rule, so one skipped value isn't counted twice.
        covered = [(s, e, r) for s, e, r, _ in hits] + [(s, e, r) for s, e, r, _ in skipped]
        for s, e, rank, by in skipped:
            if any(r < rank and s < ce and cs < e for cs, ce, r in covered):
                continue
            if isinstance(by, str):
                record.applied[by] += 1
            elif by not in record.inline_allows:
                record.inline_allows.append(by)
    return sorted(set(findings), key=Finding.sort_key)


def scan_path_rules(
    path: str, settings: Settings, record: ScanResult | None = None
) -> list[Finding]:
    name = PurePosixPath(path).name
    out: list[Finding] = []
    for rule in settings.path_rules:
        if not rule.pattern.match(name):
            continue
        allowed_by = next(
            (a.source for a in settings.allow if a.matches(rule.id, path, None)), None
        )
        if allowed_by is None:
            out.append(Finding(path, None, None, rule.id, len(name)))
        elif record is not None:
            record.applied[allowed_by] += 1
    return out


def scan(candidates: Iterable[Candidate], settings: Settings) -> ScanResult:
    result = ScanResult()
    for c in candidates:
        if PurePosixPath(c.path).name == LOCAL_FILE:
            continue  # It holds the private terms; scanning it would flag every one.
        ignored_by = settings.ignored_by(c.path)
        if ignored_by is not None:
            result.ignored += 1
            result.applied[ignored_by] += 1
            continue
        result.findings.extend(scan_path_rules(c.path, settings, result))
        if c.size > settings.max_file_bytes:
            result.skipped_large.append(c.path)
            continue
        data = c.read()
        if b"\0" in data[:_BINARY_SNIFF]:
            result.skipped_binary += 1
            continue
        result.files_scanned += 1
        result.findings.extend(scan_text(c.path, data.decode("utf-8", "replace"), settings, result))
    result.findings.sort(key=Finding.sort_key)
    return result
