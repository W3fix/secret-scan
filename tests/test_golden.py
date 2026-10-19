"""Every output format, byte for byte, against a checked-in copy.

GitHub code scanning reads the SARIF, CI scripts parse the JSON, and people
read the text. Any change to what they receive should be a decision someone
reviews in a diff, not a side effect. After a deliberate change, regenerate:

    UPDATE_GOLDEN=1 uv run pytest tests/test_golden.py
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from secret_scan import __version__
from secret_scan.cli import main
from tests import fakes
from tests.conftest import GitRun, leaky_settings
from tests.test_history import commit

GOLDEN = Path(__file__).parent / "golden"


def _normalise(text: str, commit: str = "") -> str:
    # The version changes on every release and commit ids with every run. The
    # rule-set fingerprint changes with any rule; tests/test_markdown.py covers it.
    text = text.replace(__version__, "<version>")
    if commit:
        text = text.replace(commit, "<commit>")
    return re.sub(r"sha256:[0-9a-f]{16}", "sha256:<rule-set>", text)


def _check(name: str, actual: str, commit: str = "") -> None:
    # Explicit UTF-8: Windows reads files in its legacy code page by default.
    path = GOLDEN / name
    actual = _normalise(actual, commit)
    if os.environ.get("UPDATE_GOLDEN"):
        path.parent.mkdir(exist_ok=True)
        path.write_text(actual, encoding="utf-8")
    assert path.exists(), f"missing {path.name}; run with UPDATE_GOLDEN=1"
    assert actual == path.read_text(encoding="utf-8"), (
        f"{path.name} changed; review, then UPDATE_GOLDEN=1"
    )


def test_text(leaky_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 1
    _check("text.txt", capsys.readouterr().out)


def test_json(leaky_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--format", "json"]) == 1
    _check("findings.json", capsys.readouterr().out)


def test_sarif(leaky_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sarif = leaky_repo.parent / "out.sarif"
    assert main(["--quiet", "--sarif", str(sarif)]) == 1
    _check("findings.sarif.json", sarif.read_text(encoding="utf-8"))


def test_github_annotations(
    leaky_repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert main([]) == 1
    _check("github-annotations.txt", capsys.readouterr().out)


def test_list_rules(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--list-rules"]) == 0
    _check("list-rules.txt", capsys.readouterr().out)


def test_markdown_report(
    excepted_repo: Path,
    git: GitRun,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Everything a report can show: findings with fixes, every kind of
    # exception, a file too large to read, and uncommitted changes on a commit.
    config_file = excepted_repo / ".secret-scan.json"
    config = json.loads(config_file.read_text())
    config_file.write_text(json.dumps({**config, "maxFileBytes": 4096}, indent=2))
    (excepted_repo / "assets").mkdir()
    (excepted_repo / "assets" / "big.txt").write_text("a" * 5000)
    (excepted_repo / "settings.py").write_text(leaky_settings())
    git("add", ".")
    git("commit", "-q", "-m", "fixture")
    (excepted_repo / "settings.py").write_text(leaky_settings() + "# edited\n")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")  # 2026-01-01 00:00 UTC
    assert main(["--format", "markdown"]) == 1
    _check("report.md", capsys.readouterr().out, commit=git("rev-parse", "HEAD").strip())


@pytest.fixture
def history_repo(repo: Path, git: GitRun, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """A secret removed, one still there, a dotenv file, and one inline allow."""
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2026-03-01T09:00:00Z")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-03-01T09:00:00Z")
    return [
        commit(git, {"settings.py": leaky_settings(), ".env": "DEBUG=1\n"}),
        commit(git, {"settings.py": "# moved to the vault\n"}, remove=(".env",)),
        commit(
            git,
            {
                "deploy.sh": f"export SLACK='{fakes.slack_token()}'\n",
                "test_api.py": f"KEY = '{fakes.stripe_live()}'  # secret-scan:allow test mode\n",
            },
        ),
    ]


def _commits(text: str, commits: list[str]) -> str:
    # Commit ids depend on line endings and git's object format; number them.
    for n, sha in enumerate(commits, 1):
        text = text.replace(sha, f"<commit-{n}>").replace(sha[:12], f"<commit-{n}>")
    return text


def test_history_text(history_repo: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--history"]) == 1
    _check("history.txt", _commits(capsys.readouterr().out, history_repo))


def test_history_json(history_repo: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--history", "--format", "json"]) == 1
    _check("history.json", _commits(capsys.readouterr().out, history_repo))
