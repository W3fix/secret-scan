"""Which files to scan, and how to read them.

The pre-commit mode reads content from the git index, not the working tree.
What gets committed is what's staged. Scanning the working tree would miss a
secret that's staged but since edited away, and would flag one that's
present on disk but not staged.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from secret_scan.config import LOCAL_FILE
from secret_scan.errors import SecretScanError

#: Directory names never descended into when walking a filesystem tree.
WALK_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
    }
)


@dataclass(frozen=True)
class Candidate:
    #: POSIX path, relative to the scan root, as reported in findings.
    path: str
    size: int
    read: Callable[[], bytes]


def _git(root: Path, *args: str) -> bytes:
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    except FileNotFoundError:
        raise SecretScanError("git is not installed or not on PATH") from None
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise SecretScanError(f"git {args[0]} failed: {detail[-1] if detail else 'unknown error'}")
    return proc.stdout


def git_root(start: Path) -> Path | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    return Path(proc.stdout.decode().strip())


def _split_z(out: bytes) -> list[str]:
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def ensure_local_file_untracked(root: Path) -> None:
    """Refuse to run if a private terms file has been committed.

    The file's whole purpose is to keep personal details out of the
    repository. If it's tracked, that has already failed. Say so loudly
    rather than scan around it.
    """
    tracked = _split_z(_git(root, "ls-files", "-z", "--", f":(glob)**/{LOCAL_FILE}"))
    if tracked:
        raise SecretScanError(
            f"{tracked[0]} is tracked by git. It holds private terms and must never be "
            f"committed. Run `git rm --cached {tracked[0]}`, keep it in .gitignore, and "
            "remove it from history if it was ever pushed."
        )


def _from_worktree(root: Path, rel: str) -> Candidate | None:
    full = root / rel
    try:
        if not full.is_file() or full.is_symlink():
            return None
        size = full.stat().st_size
    except OSError:
        return None
    return Candidate(rel, size, full.read_bytes)


def tracked_files(root: Path) -> Iterator[Candidate]:
    for rel in _split_z(_git(root, "ls-files", "-z")):
        c = _from_worktree(root, rel)
        if c is not None:
            yield c


def changed_since(root: Path, ref: str) -> Iterator[Candidate]:
    """Files added or modified relative to ``ref``, read from the working tree.

    A direct diff of ``ref`` against the working tree rather than
    ``ref...HEAD``: it needs only that commit, not a merge base, so it works on
    shallow CI checkouts where the base commit has been fetched.
    """
    if ref.startswith("-"):
        raise SecretScanError("--since needs a git ref, not an option")
    out = _git(root, "diff", "--name-only", "-z", "--diff-filter=ACMR", ref, "--")
    for rel in _split_z(out):
        c = _from_worktree(root, rel)
        if c is not None:
            yield c


def staged_files(root: Path) -> Iterator[Candidate]:
    out = _git(root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    for rel in _split_z(out):
        spec = f":{rel}"
        try:
            size = int(_git(root, "cat-file", "-s", spec).strip() or 0)
        except (SecretScanError, ValueError):
            continue  # e.g. a submodule entry, which has no blob
        yield Candidate(rel, size, partial(_git, root, "cat-file", "blob", spec))


def walk_paths(paths: list[Path], base: Path) -> Iterator[Candidate]:
    """Explicit files and directories, outside git's view of the tree."""
    for start in paths:
        if not start.exists():
            raise SecretScanError(f"{start}: no such file or directory")
        if start.is_file():
            c = _from_worktree(base, _rel(start, base))
            if c is not None:
                yield c
            continue
        for dirpath, dirnames, filenames in os.walk(start):
            here = Path(dirpath)
            dirnames[:] = sorted(
                d
                for d in dirnames
                # Provider binaries: large, numerous, and not ours.
                if d not in WALK_SKIP_DIRS and not (here.name == ".terraform" and d == "providers")
            )
            for name in sorted(filenames):
                c = _from_worktree(base, _rel(here / name, base))
                if c is not None:
                    yield c


def _rel(path: Path, base: Path) -> str:
    # Resolve the directory but not the name itself: resolving a symlink would
    # swap it for its target, which then gets scanned as if it were a file here.
    resolved = path.parent.resolve() / path.name
    try:
        return resolved.relative_to(base.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()
