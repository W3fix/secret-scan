"""Scan git history: every line any commit added, offline.

The unit is a change: one file in one commit. ``git log -p`` gives the lines
each commit added, with three lines of context so a ``secret-scan:allow``
marker on the line above still counts, and only matches that touch an added
line are kept. A secret is found at the commit that added it, not again at
every later commit that edits the lines around it.

To tell whether two matches are the same secret, each matched value gets a
key: a hash under a random key made for this run and never stored. That makes
a secret copied into a second file one finding rather than two, and shows
whether ``HEAD`` still has it. No value is kept, and once the run ends a key
can't be checked against a guess.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, TypeAlias, cast

from secret_scan.config import LOCAL_FILE, Settings
from secret_scan.errors import SecretScanError
from secret_scan.scanner import Finding, ScanResult, scan_path_rules, scan_text
from secret_scan.sources import git_output, head_commit, is_partial_clone, is_shallow

#: Bytes inspected for a NUL to decide content is binary, as for current files.
_BINARY_SNIFF = 8000

#: Symlinks and submodules: neither is a file whose content is in the repository.
_NOT_FILES = frozenset({"120000", "160000"})

# Repository and user config can change every part of this output (colour,
# path prefixes, context lines, merge diffs, external diff drivers), so each
# is pinned. Attributes can mark text as binary (``-diff``); those changes
# arrive as "Binary files differ" and are read from the object store instead.
_LOG_OPTIONS = (
    # Parents before children, so the first commit seen to add a value is where it entered.
    "--topo-order",
    "--reverse",
    "--format=%x00%H %ct",
    "--patch",
    "--unified=3",
    "--root",
    "--full-index",
    "--find-renames",
    # A merge's own changes: lines in none of its parents, such as a conflict resolution.
    "--diff-merges=dense-combined",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-relative",
    "--no-show-signature",
    "--submodule=short",
    "--src-prefix=a/",
    "--dst-prefix=b/",
)
_LOG_CONFIG = ("-c", "core.quotePath=false", "-c", "diff.suppressBlankEmpty=false")

_HUNK = re.compile(rb"(@@+) (?:-\d+(?:,\d+)? )+\+(\d+)(?:,\d+)? @@")
_ESCAPES = {ord(c): ord(v) for c, v in zip("abtnvfr", "\a\b\t\n\v\f\r", strict=True)}


@dataclass(frozen=True)
class HistoryFinding(Finding):
    """Where a value was first committed, and whether ``HEAD`` still has it."""

    commit: str = ""
    #: The commit's committer date: UTC, ISO 8601.
    date: str = ""
    in_head: bool = False


@dataclass
class HistoryResult(ScanResult):
    """In history, a scanned or skipped file is a change: one file in one commit.

    ``skipped_large`` entries are ``<commit>:<path>``, as ``git show`` takes them.
    """

    head: str = ""
    commits: int = 0
    #: In a shallow clone, the oldest commit fetched appears to add everything it has.
    shallow: bool = False


def revisions(head: str) -> tuple[str, ...]:
    """Every branch, tag and remote-tracking branch, and ``HEAD`` when it's detached."""
    return ("--branches", "--tags", "--remotes", head, "--")


def _env() -> dict[str, str]:
    # A backstop: partial clones are refused before anything runs.
    return {**os.environ, "GIT_NO_LAZY_FETCH": "1"}


# --- reading git log -p ---------------------------------------------------------


@dataclass
class _Hunk:
    #: The new file's line number for ``lines[0]``.
    start: int
    #: The new side: context and added lines, in order.
    lines: list[str] = field(default_factory=list)
    #: Line numbers of the added ones.
    added: set[int] = field(default_factory=set)


@dataclass
class _Change:
    commit: str
    time: int
    path: str | None
    mode: str = ""
    deleted: bool = False
    #: Shown as "Binary files differ": read ``blob`` and decide for ourselves.
    binary: bool = False
    blob: str = ""
    size: int = 0
    too_large: bool = False
    hunks: list[_Hunk] = field(default_factory=list)


def _unquote_at(s: bytes, i: int) -> tuple[bytes, int]:
    """Undo git's C-style quoting of the path starting at ``s[i]``; also return where it ends."""
    out = bytearray()
    i += 1
    while i < len(s) and s[i] != ord('"'):
        if s[i] == ord("\\") and i + 1 < len(s):
            if s[i + 1 : i + 2].isdigit():
                out.append(int(s[i + 1 : i + 4], 8) & 0xFF)
                i += 4
            else:
                out.append(_ESCAPES.get(s[i + 1], s[i + 1]))
                i += 2
            continue
        out.append(s[i])
        i += 1
    return bytes(out), i + 1


def _path(raw: bytes) -> bytes:
    return _unquote_at(raw, 0)[0] if raw.startswith(b'"') else raw


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", "surrogateescape")


def _diff_path(raw: bytes) -> str | None:
    """The path in a ``diff --git a/P b/P`` or ``diff --cc P`` line.

    A rename's two sides differ, so its new path comes from ``rename to``.
    """
    if not raw.startswith(b"diff --git "):
        return _decode(_path(raw.split(b" ", 2)[2]))
    rest = raw[len(b"diff --git ") :]
    if rest.startswith(b'"'):
        end = _unquote_at(rest, 0)[1]
        new = _path(rest[end + 1 :])
        return _decode(new[2:]) if new.startswith(b"b/") else None
    half = len(rest) // 2
    if len(rest) % 2 and rest[half + 1 : half + 3] == b"b/" and rest[2:half] == rest[half + 3 :]:
        return _decode(rest[half + 3 :])
    return None


def _header_line(change: _Change, raw: bytes) -> None:
    if raw.startswith(b"+++ "):
        # Git appends a tab when the path has a space; a real tab would be quoted.
        new = raw[4:].rstrip(b"\t")
        if new == b"/dev/null":
            change.deleted = True
        else:
            change.path = _decode(_path(new)[2:])
    elif raw.startswith((b"rename to ", b"copy to ")):
        change.path = _decode(_path(raw.split(b" ", 2)[2]))
    elif raw.startswith((b"new file mode ", b"new mode ")):
        change.mode = raw.rsplit(b" ", 1)[1].decode()
    elif raw.startswith(b"deleted file mode "):
        change.deleted = True
    elif raw.startswith(b"index "):
        ids, _, mode = raw[6:].partition(b" ")
        change.blob = ids.rpartition(b"..")[2].decode()
        if mode:
            change.mode = mode.decode()
    elif raw.startswith(b"mode "):  # a merge's: "mode <parents>..<result>"
        change.mode = raw.rpartition(b"..")[2].decode()
    elif raw.startswith(b"Binary files "):
        change.binary = True


def _lines(stream: IO[bytes], cap: int) -> Iterator[bytes]:
    """Lines without their newline. A line longer than ``cap`` is cut short, so a
    huge one-line file in history can't fill memory; its change is too large anyway."""
    while line := stream.readline(cap):
        if line.endswith(b"\n"):
            yield line[:-1]
            continue
        rest = line
        while rest and not rest.endswith(b"\n"):
            rest = stream.readline(cap)
        yield line


def _parse(stream: IO[bytes], max_bytes: int, result: HistoryResult) -> Iterator[_Change]:
    """Changes in ``git log -p`` output, each with the lines it added."""
    change: _Change | None = None
    hunk: _Hunk | None = None
    header = False
    columns, line_no = 1, 0
    commit, time = "", 0
    # Room for any path in a header line, whatever the size limit.
    for raw in _lines(stream, max(max_bytes, 1 << 16) + 2):
        if raw.startswith(b"\0"):
            if change is not None:
                yield change
            change = hunk = None
            sha, _, stamp = raw[1:].partition(b" ")
            commit, time = sha.decode(), int(stamp)
            result.commits += 1
            continue
        if raw.startswith(b"diff --"):
            if change is not None:
                yield change
            change, hunk, header = _Change(commit, time, _diff_path(raw)), None, True
            continue
        if change is None:
            continue
        if header and not raw.startswith(b"@@"):
            _header_line(change, raw)
            continue
        header = False
        if raw.startswith(b"@@"):
            m = _HUNK.match(raw)
            hunk = None
            if m is not None and not change.too_large:
                # One prefix column per parent: a merge has two or more.
                columns, line_no = len(m.group(1)) - 1, int(m.group(2))
                hunk = _Hunk(line_no)
                change.hunks.append(hunk)
            continue
        prefix = raw[:columns]
        # Skip removed lines, "\ No newline at end of file", and anything unrecognised.
        if hunk is None or len(prefix) < columns or prefix.strip(b" +"):
            continue
        change.size += len(raw) - columns
        if change.size > max_bytes:
            change.too_large, change.hunks, hunk = True, [], None
            continue
        hunk.lines.append(raw[columns:].decode("utf-8", "replace"))
        if prefix == b"+" * columns:
            hunk.added.add(line_no)
        line_no += 1
    if change is not None:
        yield change


def _log(root: Path, head: str, max_bytes: int, result: HistoryResult) -> Iterator[_Change]:
    # stderr goes to a file: a pipe nobody reads while stdout streams could fill and deadlock.
    with tempfile.TemporaryFile() as errors:
        proc = subprocess.Popen(
            ["git", "-C", str(root), *_LOG_CONFIG, "log", *_LOG_OPTIONS, *revisions(head)],
            stdout=subprocess.PIPE,
            stderr=errors,
            env=_env(),
        )
        stdout = cast(IO[bytes], proc.stdout)
        try:
            yield from _parse(stdout, max_bytes, result)
        finally:
            stdout.close()
            code = proc.wait()
        if code != 0:
            errors.seek(0)
            detail = errors.read().decode("utf-8", "replace").strip().splitlines()
            raise SecretScanError(f"git log failed: {detail[-1] if detail else 'unknown error'}")


class _Blobs:
    """Object sizes and contents from two long-running ``git cat-file`` processes."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._procs: dict[str, subprocess.Popen[bytes]] = {}

    def _ask(self, mode: str, oid: str) -> tuple[IO[bytes], int | None]:
        if mode not in self._procs:
            self._procs[mode] = subprocess.Popen(
                ["git", "-C", str(self._root), "cat-file", mode],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_env(),
            )
        stdin, stdout = (
            cast(IO[bytes], self._procs[mode].stdin),
            cast(IO[bytes], self._procs[mode].stdout),
        )
        stdin.write(oid.encode() + b"\n")
        stdin.flush()
        header = stdout.readline().split()
        # "<oid> <type> <size>", or "<oid> missing".
        return stdout, int(header[2]) if len(header) == 3 else None

    def size(self, oid: str) -> int | None:
        return self._ask("--batch-check", oid)[1]

    def read(self, oid: str) -> bytes:
        out, size = self._ask("--batch", oid)
        if size is None:
            return b""
        data = out.read(size)
        out.read(1)  # the newline after the content
        return data

    def __enter__(self) -> _Blobs:
        return self

    def __exit__(self, *exc: object) -> None:
        for proc in self._procs.values():
            cast(IO[bytes], proc.stdin).close()
            proc.wait()


# --- scanning ----------------------------------------------------------------


class _Keys:
    """Keys for matched values: equal for equal values, meaningless after the run."""

    def __init__(self, settings: Settings) -> None:
        self._key = secrets.token_bytes(32)
        self._rules = {r.id: r for r in settings.content_rules}

    def __call__(self, text: str, first_line: int, findings: list[Finding]) -> list[bytes]:
        starts = [0] + [m.end() for m in re.finditer("\n", text)]
        keys = []
        for f in findings:
            # Content findings always have a line and column.
            start = starts[cast(int, f.line) - first_line] + cast(int, f.column) - 1
            end = self._rules[f.rule].secret_end(text, start + f.length)
            value = text[start:end].encode("utf-8", "surrogatepass")
            keys.append(hashlib.blake2b(value, key=self._key, digest_size=16).digest())
        return keys


#: A value's key, or (rule, path) for a file-name rule.
_Key: TypeAlias = "bytes | tuple[str, str]"


def _touching(added: set[int]) -> Callable[[int, int], bool]:
    return lambda first, last: any(n in added for n in range(first, last + 1))


def _blob_text(change: _Change, settings: Settings, result: HistoryResult, blobs: _Blobs) -> str:
    size = blobs.size(change.blob)
    if size is not None and size > settings.max_file_bytes:
        result.skipped_large.append(f"{change.commit}:{change.path}")
        return ""
    data = blobs.read(change.blob)
    if b"\0" in data[:_BINARY_SNIFF]:
        result.skipped_binary += 1
        return ""
    return data.decode("utf-8", "replace")


def _scan_change(
    change: _Change, settings: Settings, result: HistoryResult, keys: _Keys, blobs: _Blobs
) -> Iterator[tuple[_Key, Finding]]:
    path = change.path
    if path is None or change.deleted or change.mode in _NOT_FILES:
        return
    ignored_by = settings.ignored_by(path)
    if ignored_by is not None:
        result.ignored += 1
        result.applied[ignored_by] += 1
        return
    for f in scan_path_rules(path, settings, result):
        yield (f.rule, path), f
    if change.too_large:
        result.skipped_large.append(f"{change.commit}:{path}")
        return
    excerpts: list[tuple[str, int, Callable[[int, int], bool] | None]] = []
    if change.binary:
        text = _blob_text(change, settings, result, blobs)
        if not text:
            return
        excerpts.append((text, 1, None))
    for h in change.hunks:
        if h.added:
            excerpts.append(("\n".join(h.lines) + "\n", h.start, _touching(h.added)))
    if not excerpts:
        return
    result.files_scanned += 1
    for text, first, in_scope in excerpts:
        before = len(result.inline_allows)
        found = scan_text(path, text, settings, result, first_line=first, in_scope=in_scope)
        result.inline_allows[before:] = [
            replace(a, commit=change.commit) for a in result.inline_allows[before:]
        ]
        yield from zip(keys(text, first, found), found, strict=True)


def _in_head(
    root: Path, head: str, settings: Settings, keys: _Keys, blobs: _Blobs
) -> tuple[set[bytes], set[str]]:
    """Every value a rule matches in ``HEAD``, excused or not, and every path.

    Exceptions don't apply: an excused value is still there, and so still exposed.
    """
    values: set[bytes] = set()
    paths: set[str] = set()
    for entry in git_output(root, "ls-tree", "-r", "-l", "-z", "--full-tree", head).split(b"\0"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        mode, kind, oid, size = meta.split()
        if kind != b"blob" or mode.decode() in _NOT_FILES:
            continue
        path = _decode(raw_path)
        paths.add(path)
        if int(size) > settings.max_file_bytes:
            continue
        data = blobs.read(oid.decode())
        if b"\0" in data[:_BINARY_SNIFF]:
            continue
        text = data.decode("utf-8", "replace")
        values.update(keys(text, 1, scan_text(path, text, settings, exceptions=False)))
    return values, paths


def _date(time: int) -> str:
    return datetime.fromtimestamp(time, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scan_history(root: Path, settings: Settings) -> HistoryResult:
    """Every secret any commit added, once each, with whether ``HEAD`` still has it."""
    head = head_commit(root)
    if head is None:
        raise SecretScanError("--history needs a commit to start from, and there are none yet")
    if is_partial_clone(root):
        raise SecretScanError(
            "this is a partial clone (cloned with --filter), so reading its history would "
            "download the missing files. secret-scan makes no network calls: clone the "
            "repository again without --filter, then re-run"
        )
    # Commits that added the file, newest first: name the first.
    added = git_output(
        root, "log", "--format=%H", "--diff-filter=A", *revisions(head), f":(glob)**/{LOCAL_FILE}"
    ).split()
    if added:
        raise SecretScanError(
            f"{LOCAL_FILE} was committed in {added[-1][:12].decode()}. It holds private terms, "
            "so they're in this repository's history. Remove it from history, and treat the "
            "terms as exposed if it was ever pushed"
        )
    result = HistoryResult(head=head, shallow=is_shallow(root))
    keys = _Keys(settings)
    first: dict[_Key, HistoryFinding] = {}
    with _Blobs(root) as blobs:
        for change in _log(root, head, settings.max_file_bytes, result):
            for key, f in _scan_change(change, settings, result, keys, blobs):
                if key not in first:
                    first[key] = HistoryFinding(
                        **asdict(f), commit=change.commit, date=_date(change.time)
                    )
        values, paths = _in_head(root, head, settings, keys, blobs)
    result.findings = [
        replace(f, in_head=key in values if isinstance(key, bytes) else f.path in paths)
        for key, f in first.items()
    ]
    return result
