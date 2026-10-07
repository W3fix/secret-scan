from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from secret_scan.cli import main
from tests import fakes
from tests.conftest import GitRun

ALL_SECRETS = [
    fakes.github_token(),
    fakes.aws_key_id(),
    fakes.storage_key(),
    fakes.entra_secret(),
    fakes.password(),
    fakes.anthropic_key(),
]


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


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


def test_clean_repo_exits_zero(repo: Path, git: GitRun, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "a.py").write_text("print('hello')\n")
    git("add", ".")
    code, out, _ = run(capsys)
    assert code == 0 and "No findings" in out


def test_quiet_clean_prints_nothing(
    repo: Path, git: GitRun, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "a.py").write_text("x = 1\n")
    git("add", ".")
    assert run(capsys, "-q") == (0, "", "")


@pytest.mark.parametrize("github_actions", [False, True])
@pytest.mark.parametrize("fmt", ["text", "json"])
def test_no_output_ever_contains_a_matched_value(
    leaky_repo: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    fmt: str,
    github_actions: bool,
) -> None:
    if github_actions:
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("SECRET_SCAN_PRIVATE_TERMS", "Contoso Pharmaceuticals")
    sarif = leaky_repo.parent / "out.sarif"
    code, out, err = run(capsys, "--format", fmt, "--sarif", str(sarif))
    assert code == 1
    everything = out + err + sarif.read_text()
    for secret in [*ALL_SECRETS, "Contoso Pharmaceuticals"]:
        assert secret not in everything
        assert secret.casefold() not in everything.casefold()


def test_text_output_shape(leaky_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys)
    assert code == 1
    assert "settings.py:1:11  github-token  (40 chars)" in out
    assert "6 findings in 1 file" in out


def test_json_output(leaky_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(capsys, "--format", "json")
    data = json.loads(out)
    rules = [f["rule"] for f in data["findings"]]
    assert rules == [
        "github-token",
        "aws-access-key-id",
        "azure-storage-account-key",
        "azure-entra-client-secret",
        "connection-string-password",
        "anthropic-api-key",
    ]
    assert data["summary"]["findings"] == 6
    assert all("value" not in f for f in data["findings"])


def test_sarif_is_valid_shape(leaky_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sarif = leaky_repo.parent / "out.sarif"
    run(capsys, "--sarif", str(sarif))
    doc = json.loads(sarif.read_text())
    run_ = doc["runs"][0]
    ids = [r["id"] for r in run_["tool"]["driver"]["rules"]]
    for result in run_["results"]:
        assert ids[result["ruleIndex"]] == result["ruleId"]
        assert "snippet" not in json.dumps(result)


def test_github_annotations(
    leaky_repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    _, out, _ = run(capsys)
    assert "::error file=settings.py,line=1,col=11,title=secret-scan%3A github-token::" in out


def test_config_error_exits_two(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / ".secret-scan.json").write_text('{"allow": [{"value": "x"}]}')
    code, _, err = run(capsys)
    assert code == 2 and "secret-scan: error:" in err and "reason" in err


def test_paths_and_staged_conflict(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "--staged", ".")
    assert code == 2 and "can't be combined" in err


def test_outside_git_walks_cwd(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    d = tmp_path / "plain"
    d.mkdir()
    (d / "a.txt").write_text(fakes.github_token())
    monkeypatch.chdir(d)
    code, out, _ = run(capsys)
    assert code == 1 and "a.txt:1:1" in out


def test_staged_needs_git(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    code, _, err = run(capsys, "--staged")
    assert code == 2 and "need a git repository" in err


def test_list_rules(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "--list-rules")
    assert code == 0 and "terraform-state" in out and "path" in out


def test_install_hook_blocks_a_leaky_commit(repo: Path, git: GitRun) -> None:
    assert main(["--install-hook"]) == 0
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert os.access(hook, os.X_OK)
    assert sys.executable in hook.read_text()

    (repo / "leak.py").write_text(f"t = '{fakes.github_token()}'\n")
    git("add", ".")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
    proc = subprocess.run(
        ["git", "-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-qm", "leak"],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode != 0
    assert "github-token" in proc.stdout + proc.stderr
    assert fakes.github_token() not in proc.stdout + proc.stderr


def test_install_hook_refuses_to_overwrite(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho mine\n")
    code, _, err = run(capsys, "--install-hook")
    assert code == 2 and "--force" in err
    assert "mine" in hook.read_text()
    assert run(capsys, "--install-hook", "--force")[0] == 0
