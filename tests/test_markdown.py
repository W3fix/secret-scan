"""The Markdown audit report: what it says about the scan, and that free text can't break it."""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from secret_scan.cli import main
from secret_scan.config import PRIVATE_ENV, Settings, load_settings
from secret_scan.report import ReportContext, rule_set_fingerprint, write_markdown
from secret_scan.scanner import Finding, ScanResult
from tests.conftest import GitRun

COMMIT = "0" * 40


def settings_for(
    root: Path, config: Mapping[str, object] | None = None, env: dict[str, str] | None = None
) -> Settings:
    if config is not None:
        (root / ".secret-scan.json").write_text(json.dumps(config))
    return load_settings(root, use_user_file=False, environ=env or {})


def render(settings: Settings, context: ReportContext, result: ScanResult | None = None) -> str:
    out = io.StringIO()
    write_markdown(result or ScanResult(), settings, context, out)
    return out.getvalue()


def line(report: str, label: str) -> str | None:
    prefix = f"- **{label}:** "
    return next((ln[len(prefix) :] for ln in report.splitlines() if ln.startswith(prefix)), None)


@pytest.mark.parametrize(
    ("context", "scope", "commit"),
    [
        (
            ReportContext("tracked", "r", commit=COMMIT),
            "every file tracked by git",
            f"`{COMMIT}`",
        ),
        (
            ReportContext("tracked", "r", commit=COMMIT, uncommitted=True),
            "every file tracked by git",
            f"`{COMMIT}`, plus uncommitted changes in the working tree",
        ),
        (ReportContext("tracked", "r"), "every file tracked by git", "none yet (no commits)"),
        (
            ReportContext("staged", "r", commit=COMMIT, uncommitted=True),
            "staged changes (what the next commit will contain)",
            f"`{COMMIT}`, plus the staged changes",
        ),
        (
            ReportContext("since", "r", commit=COMMIT, since_ref="main", since_commit="1" * 40),
            f"files changed since `main` (`{'1' * 40}`)",
            f"`{COMMIT}`",
        ),
        (
            ReportContext("paths", "r", paths=tuple(f"p{i}" for i in range(12))),
            "the paths " + ", ".join(f"`p{i}`" for i in range(10)) + " and 2 more",
            None,
        ),
        (
            ReportContext("directory", "r"),
            "every file in the directory (not a git repository)",
            None,
        ),
    ],
)
def test_scope_and_commit(
    tmp_path: Path, context: ReportContext, scope: str, commit: str | None
) -> None:
    report = render(settings_for(tmp_path), context)
    assert line(report, "Scope") == scope
    assert line(report, "Commit") == commit


def test_free_text_cant_break_the_report(tmp_path: Path) -> None:
    settings = settings_for(
        tmp_path,
        {"ignore": [{"path": "gen|out/", "reason": "<script>x</script> | built\nfiles"}]},
    )
    result = ScanResult(findings=[Finding("dir/a|b`c.py", 3, 5, "github-token", 40)])
    report = render(settings, ReportContext("tracked", "r", commit=COMMIT), result)
    assert "| ``dir/a\\|b`c.py:3:5`` | 40 chars |" in report
    assert "| paths matching `gen\\|out/` | &lt;script&gt;x&lt;/script&gt; \\| built files |" in (
        report
    )
    assert "<script>" not in report


def test_unused_exceptions_are_marked(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, {"ignore": [{"path": "nothing/", "reason": "old"}]})
    report = render(settings, ReportContext("tracked", "r", commit=COMMIT))
    assert "| 0 (unused) |" in report
    assert "Entries marked unused skipped nothing and can be removed." in report


def test_no_findings(tmp_path: Path) -> None:
    report = render(settings_for(tmp_path), ReportContext("tracked", "r", commit=COMMIT))
    assert report.startswith("# Secret scan report: `r`\n\n**No findings.**")
    assert "## Findings" not in report
    assert "None. No allow, ignore, disable or inline allow entries were in effect." in report


def test_fingerprint_tracks_rules_but_not_private_terms(tmp_path: Path) -> None:
    base = rule_set_fingerprint(settings_for(tmp_path))
    assert base == rule_set_fingerprint(settings_for(tmp_path))
    with_terms = settings_for(tmp_path, env={PRIVATE_ENV: "Northwind Traders"})
    assert rule_set_fingerprint(with_terms) == base
    custom = {"rules": [{"id": "my-rule", "why": "w", "pattern": "zz+"}]}
    assert rule_set_fingerprint(settings_for(tmp_path, custom)) != base
    disabled = {"disable": [{"rule": "github-token", "reason": "covered elsewhere"}]}
    assert rule_set_fingerprint(settings_for(tmp_path, disabled)) != base


def test_cli_resolves_since_and_names_only_the_directory(
    repo: Path, git: GitRun, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "a.py").write_text("x = 1\n")
    git("add", ".")
    git("commit", "-q", "-m", "one")
    head = git("rev-parse", "HEAD").strip()
    assert main(["--format", "markdown", "--since", "HEAD"]) == 0
    report = capsys.readouterr().out
    assert line(report, "Scope") == f"files changed since `HEAD` (`{head}`)"
    assert line(report, "Commit") == f"`{head}`"
    assert report.startswith("# Secret scan report: `repo`")
    assert str(repo.parent) not in report


def test_cli_outside_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "a.txt").write_text("hello\n")
    monkeypatch.chdir(plain)
    assert main(["--format", "markdown"]) == 0
    report = capsys.readouterr().out
    assert line(report, "Scope") == "every file in the directory (not a git repository)"
    assert line(report, "Commit") is None
