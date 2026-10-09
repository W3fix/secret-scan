"""Every output format, byte for byte, against a checked-in copy.

GitHub code scanning reads the SARIF, CI scripts parse the JSON, and people
read the text. Any change to what they receive should be a decision someone
reviews in a diff, not a side effect. After a deliberate change, regenerate:

    UPDATE_GOLDEN=1 uv run pytest tests/test_golden.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from secret_scan import __version__
from secret_scan.cli import main

GOLDEN = Path(__file__).parent / "golden"


def _normalise(text: str) -> str:
    # The version changes on every release; nothing else may.
    return text.replace(__version__, "<version>")


def _check(name: str, actual: str) -> None:
    path = GOLDEN / name
    actual = _normalise(actual)
    if os.environ.get("UPDATE_GOLDEN"):
        path.parent.mkdir(exist_ok=True)
        path.write_text(actual)
    assert path.exists(), f"missing {path.name}; run with UPDATE_GOLDEN=1"
    assert actual == path.read_text(), f"{path.name} changed; review, then UPDATE_GOLDEN=1"


def test_text(leaky_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 1
    _check("text.txt", capsys.readouterr().out)


def test_json(leaky_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--format", "json"]) == 1
    _check("findings.json", capsys.readouterr().out)


def test_sarif(leaky_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sarif = leaky_repo.parent / "out.sarif"
    assert main(["--quiet", "--sarif", str(sarif)]) == 1
    _check("findings.sarif", sarif.read_text())


def test_github_annotations(
    leaky_repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert main([]) == 1
    _check("github-annotations.txt", capsys.readouterr().out)


def test_list_rules(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--list-rules"]) == 0
    _check("list-rules.txt", capsys.readouterr().out)
