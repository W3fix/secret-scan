from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from tests import fakes

GitRun = Callable[..., str]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep the developer's own private terms and git config out of every test."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SECRET_SCAN_PRIVATE_TERMS", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
    monkeypatch.chdir(root)
    yield root


@pytest.fixture
def git(repo: Path) -> GitRun:
    def run(*args: str) -> str:
        return subprocess.run(
            ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    return run


@pytest.fixture
def leaky_repo(repo: Path, git: GitRun) -> Path:
    lines = [
        f"GITHUB = '{fakes.github_token()}'",
        f"AWS = '{fakes.aws_key_id()}'",
        f"CONN = 'AccountName=demo;AccountKey={fakes.storage_key()}'",
        f"ENTRA = '{fakes.entra_secret()}'",
        f"DB = 'Server=db;User Id=svc;Password={fakes.password()};'",
        f"CLAUDE = '{fakes.anthropic_key()}'",
        "OWNER = 'Contoso Pharmaceuticals'",
    ]
    (repo / "settings.py").write_text("\n".join(lines) + "\n")
    git("add", ".")
    return repo
