from __future__ import annotations

from pathlib import Path

import pytest

from secret_scan.errors import SecretScanError
from secret_scan.sources import (
    changed_since,
    ensure_local_file_untracked,
    staged_files,
    tracked_files,
    walk_paths,
)
from tests import fakes
from tests.conftest import GitRun


def contents(cands: object) -> dict[str, bytes]:
    return {c.path: c.read() for c in cands}  # type: ignore[attr-defined]


def test_tracked_files_skip_untracked(repo: Path, git: GitRun) -> None:
    (repo / "a.txt").write_text("a")
    (repo / "untracked.txt").write_text("u")
    git("add", "a.txt")
    assert set(contents(tracked_files(repo))) == {"a.txt"}


def test_staged_reads_the_index_not_the_working_tree(repo: Path, git: GitRun) -> None:
    f = repo / "config.py"
    f.write_text(f"token = '{fakes.github_token()}'\n")
    git("add", "config.py")
    f.write_text("token = None\n")  # cleaned on disk, but the secret is still staged
    staged = contents(staged_files(repo))
    assert fakes.github_token().encode() in staged["config.py"]


def test_staged_ignores_unstaged_changes(repo: Path, git: GitRun) -> None:
    (repo / "a.txt").write_text("clean\n")
    git("add", "a.txt")
    git("commit", "-qm", "init")
    (repo / "a.txt").write_text(fakes.github_token())
    assert contents(staged_files(repo)) == {}


def test_changed_since(repo: Path, git: GitRun) -> None:
    (repo / "old.txt").write_text("old")
    git("add", ".")
    git("commit", "-qm", "one")
    base = git("rev-parse", "HEAD").strip()
    (repo / "new.txt").write_text("new")
    git("add", ".")
    git("commit", "-qm", "two")
    assert set(contents(changed_since(repo, base))) == {"new.txt"}


def test_changed_since_rejects_option_injection(repo: Path) -> None:
    with pytest.raises(SecretScanError, match="git ref"):
        list(changed_since(repo, "--output=/tmp/x"))


def test_bad_ref_is_a_clean_error(repo: Path, git: GitRun) -> None:
    (repo / "a").write_text("a")
    git("add", ".")
    git("commit", "-qm", "init")
    with pytest.raises(SecretScanError, match="git diff failed"):
        list(changed_since(repo, "no-such-ref"))


def test_tracked_local_file_is_refused(repo: Path, git: GitRun) -> None:
    sub = repo / "sub"
    sub.mkdir()
    (sub / ".secret-scan.local.json").write_text("{}")
    git("add", ".")
    with pytest.raises(SecretScanError, match="must never be committed"):
        ensure_local_file_untracked(repo)


def test_walk_skips_tool_directories(tmp_path: Path) -> None:
    for rel in [
        "src/a.py",
        "node_modules/x/i.js",
        ".git/config",
        ".terraform/providers/p",
        ".terraform/modules/m/main.tf",
    ]:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    found = set(contents(walk_paths([tmp_path], tmp_path)))
    assert found == {"src/a.py", ".terraform/modules/m/main.tf"}


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    root = tmp_path / "root"
    root.mkdir()
    (root / "real.txt").write_text("y")
    try:
        (root / "link.txt").symlink_to(outside / "secret.txt")
        (root / "linkdir").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("this platform can't create symlinks without privileges")
    assert set(contents(walk_paths([root], root))) == {"real.txt"}
    assert contents(walk_paths([root / "link.txt"], root)) == {}


def test_walk_missing_path(tmp_path: Path) -> None:
    with pytest.raises(SecretScanError, match="no such file"):
        list(walk_paths([tmp_path / "nope"], tmp_path))
