"""Render scan results. Nothing here has access to matched text, only locations."""

from __future__ import annotations

import hashlib
import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TextIO

from secret_scan import __version__
from secret_scan.config import Settings
from secret_scan.history import HistoryFinding, HistoryResult
from secret_scan.rules import CONTENT_RULES, PATH_RULES, Rule
from secret_scan.scanner import Finding, ScanResult

TOOL_URL = "https://github.com/W3fix/secret-scan"


def _location(f: Finding) -> str:
    if f.line is None:
        return f.path
    return f"{f.path}:{f.line}:{f.column}"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _marks(out: TextIO) -> tuple[str, str]:
    """Pass and fail marks the stream can actually encode.

    Windows pipes and consoles often use a legacy code page without ✓ or ✗.
    """
    try:
        "✓✗".encode(getattr(out, "encoding", None) or "utf-8")
    except (UnicodeEncodeError, LookupError):
        return "OK", "X"
    return "✓", "✗"


def _measure(f: Finding) -> str:
    return "file name" if f.line is None else f"{f.length} chars"


class _Style:
    def __init__(self, color: bool) -> None:
        self.color = color

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)


def _committed(f: HistoryFinding) -> str:
    where = "still in HEAD" if f.in_head else "no longer in HEAD, but still in history"
    return f"Committed in {f.commit[:12]} on {f.date[:10]}; {where}."


def write_text(
    result: ScanResult, settings: Settings, out: TextIO, *, color: bool, quiet: bool
) -> None:
    s = _Style(color)
    for f in result.findings:
        out.write(f"{s.bold(_location(f))}  {s.red(f.rule)}  ({_measure(f)})\n")
        out.write(f"    {s.dim(settings.rule_why(f.rule))}\n")
        if isinstance(f, HistoryFinding):
            # Committed means it has left the machine, so what to do applies now.
            out.write(f"    {_committed(f)}\n")
            if fix := settings.rule_fix(f.rule):
                out.write(f"    {s.dim('What to do: ' + fix)}\n")
        if f.note:
            out.write(f"    {s.yellow(f.note)}\n")
    for path in result.skipped_large:
        out.write(s.yellow(f"skipped (larger than {settings.max_file_bytes} bytes): {path}") + "\n")
    if isinstance(result, HistoryResult):
        _write_history_summary(result, s, out, quiet=quiet)
        return
    if quiet and not result.findings:
        return
    passed, failed = _marks(out)
    files = len({f.path for f in result.findings})
    scanned = _plural(result.files_scanned, "file") + " scanned"
    if result.findings:
        out.write(
            "\n"
            + s.red(
                f"{failed} {_plural(len(result.findings), 'finding')} in {_plural(files, 'file')}"
            )
            + f" ({scanned}). Values withheld.\n"
        )
    else:
        out.write(s.green(f"{passed} No findings") + f" ({scanned}).\n")


def _write_history_summary(result: HistoryResult, s: _Style, out: TextIO, *, quiet: bool) -> None:
    if result.shallow:
        out.write(
            s.yellow(
                "Shallow clone: older commits weren't fetched, and the oldest one here appears "
                "to add every file it has. Run git fetch --unshallow to scan the full history."
            )
            + "\n"
        )
    if quiet and not result.findings:
        return
    passed, failed = _marks(out)
    scanned = _plural(result.commits, "commit") + " scanned"
    if result.findings:
        in_head = sum(1 for f in result.findings if isinstance(f, HistoryFinding) and f.in_head)
        found = _plural(len(result.findings), "finding")
        out.write(
            "\n"
            + s.red(f"{failed} {found} in history")
            + f" ({scanned}), {in_head} still in HEAD. Values withheld.\n"
        )
    else:
        out.write(s.green(f"{passed} No findings in history") + f" ({scanned}).\n")


def _gh_escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _gh_escape_prop(text: str) -> str:
    return _gh_escape_data(text).replace(":", "%3A").replace(",", "%2C")


def write_github_annotations(result: ScanResult, settings: Settings, out: TextIO) -> None:
    """Workflow commands that surface findings as annotations on the PR diff."""
    for f in result.findings:
        props = [f"file={_gh_escape_prop(f.path)}"]
        if f.line is not None:
            props += [f"line={f.line}", f"col={f.column}"]
        props.append(f"title={_gh_escape_prop('secret-scan: ' + f.rule)}")
        message = f"{settings.rule_why(f.rule)} ({_measure(f)}; value withheld)"
        out.write(f"::error {','.join(props)}::{_gh_escape_data(message)}\n")


def exceptions_register(result: ScanResult, settings: Settings) -> list[dict[str, Any]]:
    """Every exception in effect, with its reason and how often it applied.

    ``applied`` counts skipped matches for allow entries and skipped files for
    ignore entries. Disable entries have no count: what a disabled rule would
    have matched is unknown. Each inline entry is one skipped match.
    """
    entries: list[dict[str, Any]] = []
    for e in settings.exemptions:
        entry: dict[str, Any] = {"kind": e.kind, "source": e.source}
        if e.rule:
            entry["rule"] = e.rule
        if e.path:
            entry["path"] = e.path
        if e.pins_value:
            entry["value"] = "withheld"
        entry["reason"] = e.reason
        if e.kind != "disable":
            entry["applied"] = result.applied[e.source]
        entries.append(entry)
    for a in sorted(result.inline_allows, key=lambda a: (a.path, a.line, a.rule)):
        entry = {"kind": "inline", "source": f"{a.path}:{a.line}", "rule": a.rule}
        if a.commit:
            entry["commit"] = a.commit
        entries.append({**entry, "reason": a.reason})
    return entries


def _history_fields(f: Finding) -> dict[str, Any]:
    if not isinstance(f, HistoryFinding):
        return {}
    return {"commit": f.commit, "date": f.date, "inHead": f.in_head}


def to_json(result: ScanResult, settings: Settings) -> dict[str, Any]:
    history: dict[str, Any] = {}
    if isinstance(result, HistoryResult):
        history = {
            "history": {"head": result.head, "commits": result.commits, "shallow": result.shallow}
        }
    return {
        "version": 1,
        "tool": {"name": "secret-scan", "version": __version__},
        **history,
        "findings": [
            {
                "path": f.path,
                "line": f.line,
                "column": f.column,
                "rule": f.rule,
                "why": settings.rule_why(f.rule),
                **({"fix": fix} if (fix := settings.rule_fix(f.rule)) else {}),
                "length": f.length,
                **_history_fields(f),
                **({"note": f.note} if f.note else {}),
            }
            for f in result.findings
        ],
        "exceptions": exceptions_register(result, settings),
        "summary": {
            "findings": len(result.findings),
            "filesScanned": result.files_scanned,
            "skippedBinary": result.skipped_binary,
            "skippedLarge": result.skipped_large,
            "ignored": result.ignored,
        },
    }


def write_json(result: ScanResult, settings: Settings, out: TextIO) -> None:
    json.dump(to_json(result, settings), out, indent=2)
    out.write("\n")


def to_sarif(result: ScanResult, settings: Settings) -> dict[str, Any]:
    """SARIF 2.1.0 for GitHub code scanning. No snippets, by design."""
    rules = settings.all_rules
    index = {r.id: i for i, r in enumerate(rules)}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-scan",
                        "version": __version__,
                        "informationUri": TOOL_URL,
                        "rules": [
                            {
                                "id": r.id,
                                "shortDescription": {"text": r.why},
                                **({"help": {"text": r.fix}} if r.fix else {}),
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": ["security", "secrets"]},
                            }
                            for r in rules
                        ],
                    }
                },
                "results": [_sarif_result(f, settings, index) for f in result.findings],
            }
        ],
    }


def _sarif_result(f: Finding, settings: Settings, index: dict[str, int]) -> dict[str, Any]:
    location: dict[str, Any] = {"artifactLocation": {"uri": f.path}}
    if f.line is not None and f.column is not None:
        location["region"] = {
            "startLine": f.line,
            "startColumn": f.column,
            "endColumn": f.column + f.length,
        }
    out: dict[str, Any] = {
        "ruleId": f.rule,
        "level": "error",
        "message": {"text": f"{settings.rule_why(f.rule)} ({_measure(f)}; value withheld)"},
        "locations": [{"physicalLocation": location}],
    }
    if f.rule in index:
        out["ruleIndex"] = index[f.rule]
    return out


# --- Markdown audit report ---------------------------------------------------


@dataclass(frozen=True)
class ReportContext:
    """What a report says about the scan itself. The CLI gathers it."""

    #: ``tracked``, ``staged``, ``since``, ``paths`` or ``directory``.
    mode: str
    #: The repository's (or directory's) name; never its full local path.
    root_name: str
    commit: str | None = None
    uncommitted: bool = False
    since_ref: str | None = None
    since_commit: str | None = None
    paths: tuple[str, ...] = ()
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def rule_set_fingerprint(settings: Settings) -> str:
    """A short hash of the active rules, so two reports can show they used the same set.

    Private rules are left out: a hash of someone's private terms could be
    used to confirm a guess at them.
    """
    h = hashlib.sha256()
    for r in sorted(settings.all_rules, key=lambda r: r.id):
        if r.origin == "private":
            continue
        parts = [r.id, r.origin, r.pattern.pattern, str(r.pattern.flags)]
        if isinstance(r, Rule):
            parts += [
                str(r.generic),
                str(r.check_placeholder),
                repr(r.min_entropy),
                r.line_requires.pattern if r.line_requires else "",
                r.well_formed.__name__ if r.well_formed else "",
            ]
        h.update("\0".join(parts).encode() + b"\n")
    return "sha256:" + h.hexdigest()[:16]


def _code(text: str) -> str:
    """Inline code, whatever backticks the text contains."""
    text = text.replace("\r", " ").replace("\n", " ")
    fence = "``" if "`" in text else "`"
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _prose(text: str) -> str:
    """Free text from config or code: shown as written, never as markup."""
    return html.escape(text.replace("\r", " ").replace("\n", " "), quote=False)


def _cell(markdown: str) -> str:
    # A pipe ends a table cell, even inside a code span.
    return markdown.replace("|", "\\|")


def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _scope(c: ReportContext) -> str:
    if c.mode == "staged":
        return "staged changes (what the next commit will contain)"
    if c.mode == "since":
        ref = _code(c.since_ref or "")
        return f"files changed since {ref}" + (
            f" ({_code(c.since_commit)})" if c.since_commit else ""
        )
    if c.mode == "paths":
        shown = ", ".join(_code(p) for p in c.paths[:10])
        more = len(c.paths) - 10
        return f"the paths {shown}" + (f" and {more} more" if more > 0 else "")
    if c.mode == "directory":
        return "every file in the directory (not a git repository)"
    return "every file tracked by git"


def _commit(c: ReportContext) -> str | None:
    if c.mode in {"directory", "paths"} and c.commit is None:
        return None
    if c.commit is None:
        return "none yet (no commits)"
    if c.mode == "staged":
        return f"{_code(c.commit)}, plus the staged changes"
    if c.uncommitted:
        return f"{_code(c.commit)}, plus uncommitted changes in the working tree"
    return _code(c.commit)


def _rules_line(settings: Settings) -> str:
    builtin = sum(1 for r in settings.all_rules if r.origin == "builtin")
    custom = sum(1 for r in settings.all_rules if r.origin == "config")
    line = f"{builtin} of {len(CONTENT_RULES) + len(PATH_RULES)} built-in"
    if custom:
        line += f", {custom} custom"
    if settings.private_sources:
        n = len(settings.private_sources)
        line += f", private terms from {_count(n, 'source', 'sources')} (not listed)"
    return line


def _coverage_line(result: ScanResult, settings: Settings) -> str:
    parts = [f"{_count(result.files_scanned, 'file', 'files')} scanned"]
    if result.skipped_binary:
        parts.append(
            f"{_count(result.skipped_binary, 'binary file', 'binary files')} checked by name only"
        )
    if result.skipped_large:
        large = _count(len(result.skipped_large), "file", "files")
        parts.append(f"{large} over {settings.max_file_bytes:,} bytes checked by name only")
    if result.ignored:
        parts.append(f"{_count(result.ignored, 'file', 'files')} excluded by `ignore` entries")
    return "; ".join(parts)


def _applies_to(e: dict[str, Any]) -> str:
    if e["kind"] == "disable":
        return f"rule {_code(e['rule'])}, everywhere"
    if e["kind"] == "ignore":
        return f"paths matching {_code(e['path'])}"
    if e["kind"] == "inline":
        return f"rule {_code(e['rule'])} on that line"
    parts = []
    if "rule" in e:
        parts.append(f"rule {_code(e['rule'])}")
    if "path" in e:
        parts.append(f"in {_code(e['path'])}")
    if "value" in e:
        parts.append("one exact value (withheld)")
    return " ".join(parts)


def _skipped(e: dict[str, Any]) -> str:
    if e["kind"] == "disable":
        return "n/a"
    if e["kind"] == "inline":
        return "1 match"
    n = e["applied"]
    if n == 0:
        return "0 (unused)"
    return _count(n, "file", "files") if e["kind"] == "ignore" else _count(n, "match", "matches")


_METHOD = """\
## Method and limits

- **Values are withheld.** This report gives the location, rule and length of each
  match, never the matched text, so it can be shared without spreading what it describes.
- **Offline.** The scan made no network calls, so no credential was tested. Treat every
  finding as live until it has been rotated.
- **Current files, not history.** A secret removed from the files can still be in git
  history and in every clone. Rotating it is the fix; rewriting history doesn't
  replace that.
- **Patterns, not proof.** Rules match credentials in their usual forms. Encoded or
  deliberately split values aren't detected, and a finding can be test data: the
  exceptions register shows what was excused, and why.
"""


def write_markdown(
    result: ScanResult, settings: Settings, context: ReportContext, out: TextIO
) -> None:
    """An audit report to hand to a client: scope, findings with fixes, exceptions."""
    w = out.write
    files = len({f.path for f in result.findings})
    w(f"# Secret scan report: {_code(context.root_name)}\n\n")
    if result.findings:
        found = _count(len(result.findings), "finding", "findings")
        w(f"**{found} in {_count(files, 'file', 'files')}.**")
    else:
        w("**No findings.**")
    w(" Values are withheld: this report shows where each finding is and which rule\n")
    w("it matched, never the matched text.\n\n")

    w("## Scan\n\n")
    w(f"- **Scope:** {_scope(context)}\n")
    commit = _commit(context)
    if commit is not None:
        w(f"- **Commit:** {commit}\n")
    w(f"- **Scanned:** {context.scanned_at.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC\n")
    w(f"- **Tool:** secret-scan {__version__}, rule set {_code(rule_set_fingerprint(settings))}\n")
    w(f"- **Rules:** {_rules_line(settings)}\n")
    w(f"- **Coverage:** {_coverage_line(result, settings)}\n\n")

    if result.findings:
        by_rule: dict[str, list[Finding]] = {}
        for f in result.findings:
            by_rule.setdefault(f.rule, []).append(f)
        order = sorted(by_rule, key=lambda r: (-len(by_rule[r]), r))
        w("## Findings by rule\n\n| Rule | Findings | Files |\n|---|---:|---:|\n")
        for rule in order:
            fs = by_rule[rule]
            w(f"| {_cell(_code(rule))} | {len(fs)} | {len({f.path for f in fs})} |\n")
        w("\n## Findings\n")
        for rule in order:
            fs = by_rule[rule]
            w(f"\n### {_code(rule)}\n\n")
            w(f"**Why it matters.** {_prose(settings.rule_why(rule))}\n\n")
            fix = settings.rule_fix(rule)
            if fix:
                w(f"**What to do.** {_prose(fix)}\n\n")
            notes = any(f.note for f in fs)
            w("| Location | Match |" + (" Note |" if notes else "") + "\n")
            w("|---|---|" + ("---|" if notes else "") + "\n")
            for f in fs:
                row = f"| {_cell(_code(_location(f)))} | {_measure(f)} |"
                if notes:
                    row += f" {_cell(_prose(f.note))} |"
                w(row + "\n")
        w("\n")

    w("## Exceptions register\n\n")
    register = exceptions_register(result, settings)
    if register:
        w("Every exception in effect for this scan, with the reason given for it.\n")
        if any(e.get("applied") == 0 for e in register):
            w("Entries marked unused skipped nothing and can be removed.\n")
        w("\n| Kind | Declared in | Applies to | Reason | Skipped |\n|---|---|---|---|---:|\n")
        for e in register:
            w(
                f"| {e['kind']} | {_cell(_code(e['source']))} | {_cell(_applies_to(e))} "
                f"| {_cell(_prose(e['reason']))} | {_skipped(e)} |\n"
            )
        w("\n")
    else:
        w("None. No allow, ignore, disable or inline allow entries were in effect.\n\n")

    if result.skipped_large:
        w("## Checked by name only\n\n")
        w(f"Larger than {settings.max_file_bytes:,} bytes, so content rules didn't run:\n\n")
        for path in result.skipped_large[:50]:
            w(f"- {_code(path)}\n")
        if len(result.skipped_large) > 50:
            w(f"- and {len(result.skipped_large) - 50} more\n")
        w("\n")

    w(_METHOD)
    w(f"\n---\n\nGenerated by [secret-scan]({TOOL_URL}) {__version__}.\n")
