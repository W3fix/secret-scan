from __future__ import annotations

import json
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


def leaky_settings() -> str:
    """A settings file with six fake credentials and a client name."""
    lines = [
        f"GITHUB = '{fakes.github_token()}'",
        f"AWS = '{fakes.aws_key_id()}'",
        f"CONN = 'AccountName=demo;AccountKey={fakes.storage_key()}'",
        f"ENTRA = '{fakes.entra_secret()}'",
        f"DB = 'Server=db;User Id=svc;Password={fakes.password()};'",
        f"CLAUDE = '{fakes.anthropic_key()}'",
        "OWNER = 'Contoso Pharmaceuticals'",
    ]
    return "\n".join(lines) + "\n"


@pytest.fixture
def leaky_repo(repo: Path, git: GitRun) -> Path:
    (repo / "settings.py").write_text(leaky_settings())
    git("add", ".")
    return repo


#: The private term configured in ``excepted_repo``.
EXCEPTED_TERM = "Northwind Traders"


@pytest.fixture
def excepted_repo(repo: Path, git: GitRun, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SECRET_SCAN_PRIVATE_TERMS", EXCEPTED_TERM)
    config = {
        "disable": [
            {"rule": "url-embedded-credentials", "reason": f"{EXCEPTED_TERM} fixtures only"}
        ],
        "ignore": [{"path": "vendor/", "reason": "third-party code"}],
        "allow": [
            {"rule": "github-token", "path": "docs/**", "reason": "revoked examples"},
            {"value": fakes.generic_value(), "reason": "unit-test key"},
            {"rule": "dotenv-file", "path": "examples/.env", "reason": "names only, no values"},
        ],
    }
    files = {
        ".secret-scan.json": json.dumps(config, indent=2),
        "docs/a.md": f"token: {fakes.github_token()}\ntoken: {fakes.github_token()}\n",
        "vendor/a.js": f"t = '{fakes.github_token()}'\n",
        "vendor/b.js": f"t = '{fakes.slack_token()}'\n",
        "src/util.py": f'api_key = "{fakes.generic_value()}"\n',
        "examples/.env": "API_URL=\n",
        "src/app.py": "\n".join(
            [
                f'KEY = "{fakes.aws_key_id()}"  # secret-scan:allow documented format, test only',
                # Also an assignment the generic rule matches: still one entry.
                f'access_token = "{fakes.github_token()}"  # secret-scan:allow fixture',
                # The reason runs over the value it excuses.
                f'x = "secret-scan:allow quoting {fakes.stripe_live()}"',
                # The reason names a private term.
                f"# secret-scan:allow belongs to {EXCEPTED_TERM}",
                f'SLACK = "{fakes.slack_token()}"',
            ]
        )
        + "\n",
    }
    for name, content in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(content)
    git("add", ".")
    return repo
