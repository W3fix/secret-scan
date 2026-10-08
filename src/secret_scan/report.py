"""Render scan results. Nothing here has access to matched text, only locations."""

from __future__ import annotations

import json
from typing import Any, TextIO

from secret_scan import __version__
from secret_scan.config import Settings
from secret_scan.scanner import Finding, ScanResult

TOOL_URL = "https://github.com/W3fix/secret-scan"


def _location(f: Finding) -> str:
    if f.line is None:
        return f.path
    return f"{f.path}:{f.line}:{f.column}"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


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


def write_text(
    result: ScanResult, settings: Settings, out: TextIO, *, color: bool, quiet: bool
) -> None:
    s = _Style(color)
    for f in result.findings:
        out.write(f"{s.bold(_location(f))}  {s.red(f.rule)}  ({_measure(f)})\n")
        out.write(f"    {s.dim(settings.rule_why(f.rule))}\n")
        if f.note:
            out.write(f"    {s.yellow(f.note)}\n")
    for path in result.skipped_large:
        out.write(s.yellow(f"skipped (larger than {settings.max_file_bytes} bytes): {path}") + "\n")
    if quiet and not result.findings:
        return
    files = len({f.path for f in result.findings})
    scanned = _plural(result.files_scanned, "file") + " scanned"
    if result.findings:
        out.write(
            "\n"
            + s.red(f"✗ {_plural(len(result.findings), 'finding')} in {_plural(files, 'file')}")
            + f" ({scanned}). Values withheld.\n"
        )
    else:
        out.write(s.green("✓ No findings") + f" ({scanned}).\n")


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


def to_json(result: ScanResult, settings: Settings) -> dict[str, Any]:
    return {
        "version": 1,
        "tool": {"name": "secret-scan", "version": __version__},
        "findings": [
            {
                "path": f.path,
                "line": f.line,
                "column": f.column,
                "rule": f.rule,
                "why": settings.rule_why(f.rule),
                "length": f.length,
                **({"note": f.note} if f.note else {}),
            }
            for f in result.findings
        ],
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
