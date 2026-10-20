"""History mode: what every commit added, once each, and whether HEAD still has it."""

from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path

import pytest

from secret_scan.cli import main
from secret_scan.config import LOCAL_FILE, load_settings
from secret_scan.errors import SecretScanError
from secret_scan.history import HistoryFinding, HistoryResult, scan_history
from secret_scan.report import exceptions_register
from tests import fakes
from tests.conftest import GitRun, leaky_settings
from tests.test_cli import ALL_SECRETS

TOKEN = fakes.github_token()

Found = tuple[str, int | None, str, str, bool]


@pytest.fixture(autouse=True)
def _fixed_dates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2026-03-01T09:00:00Z")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-03-01T09:00:00Z")


def commit(
    git: GitRun, files: dict[str, str] | None = None, *, remove: tuple[str, ...] = ()
) -> str:
    root = Path.cwd()
    for name, content in (files or {}).items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        # newline="\n": the same blobs, and commit ids, on Windows.
        (root / name).write_text(content, encoding="utf-8", newline="\n")
    for name in remove:
        git("rm", "-q", name)
    git("add", "-A")
    git("commit", "-q", "--allow-empty", "-m", "change")
    return git("rev-parse", "HEAD").strip()


def stage_path(git: GitRun, path: str, content: str, mode: str = "100644") -> None:
    """Add ``path`` to the index without creating it: for names no file system allows."""
    blob = (
        subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            input=content.encode(),
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )
    git(
        "-c",
        "core.protectNTFS=false",
        "update-index",
        "--add",
        "--cacheinfo",
        f"{mode},{blob},{path}",
    )


def history(root: Path) -> HistoryResult:
    return scan_history(root, load_settings(root, use_user_file=False))


def found(result: HistoryResult) -> list[Found]:
    out: list[Found] = []
    for f in result.findings:
        assert isinstance(f, HistoryFinding)
        out.append((f.path, f.line, f.rule, f.commit, f.in_head))
    return out


def token(seed: int) -> str:
    """A distinct, well-formed GitHub token for each seed."""
    random_part = fakes.chars(fakes.ALNUM, 30, seed=seed)
    return "gh" + "p_" + random_part + fakes.github_checksum(random_part)


def key_block(seed: int) -> str:
    body = "\n".join(fakes.chars(fakes.B64, 64, seed=seed + i) for i in range(4))
    footer = "-----END " + "RSA " + "PRIVATE KEY-----"
    return f"{fakes.private_key_header()}\n{body}\n{footer}\n"


# --- what counts, and where -------------------------------------------------------


def test_a_removed_secret_is_reported_where_it_was_added(repo: Path, git: GitRun) -> None:
    added = commit(git, {"app.py": "x = 1\n" * 4 + f"T = '{TOKEN}'\n"})
    commit(git, {"app.py": "x = 1\n" * 4 + "T = None\n"})
    result = history(repo)
    assert found(result) == [("app.py", 5, "github-token", added, False)]
    assert result.commits == 2 and result.head == git("rev-parse", "HEAD").strip()
    finding = result.findings[0]
    assert isinstance(finding, HistoryFinding)
    assert (finding.column, finding.length, finding.date) == (6, 40, "2026-03-01T09:00:00Z")


def test_each_secret_once_however_often_it_is_committed(repo: Path, git: GitRun) -> None:
    added = commit(git, {"a.py": f"A = 1\nT = '{TOKEN}'\n"})
    commit(git, {"a.py": f"A = 2\nT = '{TOKEN}'\n"})  # a nearby edit: the line is context
    commit(git, {"a.py": f"A = 2\nT = '{TOKEN}'  # moved\n"})  # the line itself, again
    commit(git, {"b.py": f"COPY = '{TOKEN}'\n"})  # copied elsewhere
    commit(git, {"a.py": "A = 2\n"})
    assert found(history(repo)) == [("a.py", 2, "github-token", added, True)]


def test_line_numbers_are_the_commits_own(repo: Path, git: GitRun) -> None:
    commit(git, {"a.py": "".join(f"line{i} = {i}\n" for i in range(10))})
    lines = [f"line{i} = {i}\n" for i in range(10)]
    lines.insert(5, f"T = '{TOKEN}'\n")
    added = commit(git, {"a.py": "".join(lines) + "end = 1\n"})
    assert found(history(repo)) == [("a.py", 6, "github-token", added, True)]


def test_every_branch_tag_and_detached_head(repo: Path, git: GitRun) -> None:
    commit(git, {"a.txt": "a\n"})
    git("switch", "-q", "-c", "side")
    on_branch = commit(git, {"side.py": f"T = '{TOKEN}'\n"})
    git("switch", "-q", "--orphan", "tagged")
    on_tag = commit(git, {"tag.py": f"K = '{fakes.aws_key_id()}'\n"})
    git("tag", "v1")
    git("switch", "-q", "--detach", "main")
    git("branch", "-q", "-D", "tagged")
    detached = commit(git, {"head.py": f"S = '{fakes.slack_token()}'\n"})
    # Unrelated lines of history have no order between them.
    assert sorted(found(history(repo))) == [
        ("head.py", 1, "slack-token", detached, True),
        ("side.py", 1, "github-token", on_branch, False),
        ("tag.py", 1, "aws-access-key-id", on_tag, False),
    ]


def test_clock_skew_cant_move_where_a_secret_entered(
    repo: Path, git: GitRun, monkeypatch: pytest.MonkeyPatch
) -> None:
    def dated(day: int) -> None:
        for var in ("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"):
            monkeypatch.setenv(var, f"2026-03-{day:02d}T09:00:00Z")

    dated(10)
    added = commit(git, {"a.py": f"T = '{TOKEN}'\n"})
    git("switch", "-q", "-c", "other")
    dated(20)
    commit(git, {"b.txt": "b\n"})
    git("switch", "-q", "-c", "skewed", "main")
    dated(5)  # a child dated before its parent: date order would show it first
    commit(git, {"a.py": f"T = '{TOKEN}'  # reworded\n"})
    assert found(history(repo)) == [("a.py", 1, "github-token", added, True)]


def test_a_merge_is_scanned_for_what_it_adds_itself(repo: Path, git: GitRun) -> None:
    commit(git, {"f.txt": "a\nb\nc\n"})
    git("switch", "-q", "-c", "side")
    from_branch = commit(git, {"f.txt": "a\nb\nSIDE\n", "s.py": f"T = '{TOKEN}'\n"})
    git("switch", "-q", "main")
    commit(git, {"f.txt": "a\nb\nMAIN\n"})
    with pytest.raises(subprocess.CalledProcessError):
        git("merge", "-q", "side")  # conflicts in f.txt
    resolved = commit(git, {"f.txt": f"a\nb\nK = '{fakes.aws_key_id()}'\n"})
    assert found(history(repo)) == [
        ("s.py", 1, "github-token", from_branch, True),
        ("f.txt", 3, "aws-access-key-id", resolved, True),
    ]


def test_a_rename_is_not_a_new_secret(repo: Path, git: GitRun) -> None:
    added = commit(git, {"old name.py": f"T = '{TOKEN}'\n"})
    git("mv", "old name.py", "new name.py")
    commit(git)
    assert found(history(repo)) == [("old name.py", 1, "github-token", added, True)]


def test_file_name_rules(repo: Path, git: GitRun) -> None:
    added = commit(git, {".env": ""})  # empty: a diff with no hunks
    commit(git, remove=(".env",))
    assert found(history(repo)) == [(".env", None, "dotenv-file", added, False)]


def test_symlinks_and_submodules_are_not_files(repo: Path, git: GitRun) -> None:
    base = commit(git, {"a.txt": "a\n"})
    stage_path(git, ".env", f"T = '{TOKEN}'", mode="120000")
    git("update-index", "--add", "--cacheinfo", f"160000,{base},vendor/lib")
    git("commit", "-q", "-m", "links")
    assert found(history(repo)) == []


def test_private_keys_are_told_apart_by_their_body(repo: Path, git: GitRun) -> None:
    first = commit(git, {"one.pem": key_block(100)})
    second = commit(git, {"two.pem": key_block(200)})  # same header, different key
    commit(git, {"copy.pem": key_block(100)}, remove=("one.pem",))
    commit(git, remove=("two.pem",))
    assert found(history(repo)) == [
        ("one.pem", 1, "private-key", first, True),
        ("two.pem", 1, "private-key", second, False),
    ]


def test_a_key_body_pasted_under_an_existing_header(repo: Path, git: GitRun) -> None:
    footer = "-----END " + "RSA " + "PRIVATE KEY-----"
    commit(git, {"k.pem": f"{fakes.private_key_header()}\npaste the key here\n{footer}\n"})
    pasted = commit(git, {"k.pem": key_block(300)})  # the header line is unchanged context
    assert found(history(repo)) == [("k.pem", 1, "private-key", pasted, True)]


# --- exceptions -----------------------------------------------------------------


def test_an_inline_allow_counts_where_it_was_present(repo: Path, git: GitRun) -> None:
    excused = commit(git, {"t.py": f"T = '{TOKEN}'  # secret-scan:allow fixture for the parser\n"})
    unexcused = commit(git, {"t.py": f"T = '{TOKEN}'\n"})
    result = history(repo)
    assert found(result) == [("t.py", 1, "github-token", unexcused, True)]
    assert [(a.path, a.line, a.reason, a.commit) for a in result.inline_allows] == [
        ("t.py", 1, "fixture for the parser", excused)
    ]


def test_a_marker_on_the_line_above_is_read_from_context(repo: Path, git: GitRun) -> None:
    commit(git, {"t.py": "# secret-scan:allow fake token for tests\nT = None\n"})
    commit(git, {"t.py": f"# secret-scan:allow fake token for tests\nT = '{TOKEN}'\n"})
    assert found(history(repo)) == []


def test_the_current_config_applies_to_every_commit(repo: Path, git: GitRun) -> None:
    commit(git, {"vendor/x.js": f"t = '{TOKEN}'\n", "docs/a.md": f"{fakes.aws_key_id()}\n"})
    config = {
        "ignore": [{"path": "vendor/", "reason": "third-party code"}],
        "allow": [{"rule": "aws-access-key-id", "path": "docs/**", "reason": "documented"}],
    }
    commit(git, {".secret-scan.json": json.dumps(config)})  # added after the fact
    settings = load_settings(repo, use_user_file=False)
    result = scan_history(repo, settings)
    assert found(result) == []
    assert result.ignored == 1
    assert [e["applied"] for e in exceptions_register(result, settings)] == [1, 1]


def test_values_excused_in_head_are_still_in_head(repo: Path, git: GitRun) -> None:
    added = commit(git, {"t.py": f"T = '{TOKEN}'\n"})
    commit(git, {"t.py": f"T = '{TOKEN}'  # secret-scan:allow revoked, kept for a test\n"})
    assert found(history(repo)) == [("t.py", 1, "github-token", added, True)]


# --- what git shows, and what it can be made to hide ---------------------------


def test_attributes_cant_hide_a_text_file(repo: Path, git: GitRun) -> None:
    added = commit(
        git,
        {
            ".gitattributes": "*.py -diff\n",
            "hidden.py": f"T = '{TOKEN}'\n",
            "real.bin": "\0" + f"T = '{TOKEN}'\n",
        },
    )
    result = history(repo)
    assert found(result) == [("hidden.py", 1, "github-token", added, True)]
    assert result.skipped_binary == 1


def test_large_changes_are_listed_not_scanned(repo: Path, git: GitRun) -> None:
    config = json.dumps({"maxFileBytes": 100})
    # Longer than any line is read in one piece, too.
    long_line = f"T = '{TOKEN}'" + "x" * 70_000 + "\n"
    added = commit(
        git,
        {
            ".secret-scan.json": config,
            ".gitattributes": "*.blob -diff\n",
            "big.txt": long_line,
            "big.blob": long_line,
        },
    )
    result = history(repo)
    assert found(result) == []
    assert sorted(result.skipped_large) == [f"{added}:big.blob", f"{added}:big.txt"]


def test_paths_git_has_to_quote(repo: Path, git: GitRun) -> None:
    names = ["café.py", "my file.py", "a b/c b/d.py", 'quo"te.py', "tab\there.py", "ctrl\x01.py"]
    for seed, name in enumerate(names):
        stage_path(git, name, f"T = '{token(seed)}'\n")
    git("commit", "-q", "-m", "odd names")
    added = git("rev-parse", "HEAD").strip()
    # A rename with no edits has no diff: its new name comes from "rename to".
    blob = git("rev-parse", 'HEAD:quo"te.py').strip()
    git("update-index", "--force-remove", 'quo"te.py')
    git(
        "-c",
        "core.protectNTFS=false",
        "update-index",
        "--add",
        "--cacheinfo",
        f'100644,{blob},.env.quo"te',
    )
    git("commit", "-q", "-m", "rename")
    renamed = git("rev-parse", "HEAD").strip()
    assert sorted(found(history(repo))) == sorted(
        # The renamed file still holds its token, so every one is in HEAD.
        [(name, 1, "github-token", added, True) for name in names]
        + [('.env.quo"te', None, "dotenv-file", renamed, True)]
    )


def test_content_that_looks_like_diff_headers(repo: Path, git: GitRun) -> None:
    fake_headers = "++ b/x\ndiff --git a/y b/y\n@@ -1 +1 @@\n-- a/z\n"
    added = commit(git, {"notes.txt": fake_headers + f"T = '{TOKEN}'\n"})
    assert found(history(repo)) == [("notes.txt", 5, "github-token", added, True)]


def test_repository_config_cant_change_what_is_read(repo: Path, git: GitRun) -> None:
    # A secret in the root commit, an empty file (named only in the diff header),
    # a marker read from context, a change below empty context lines, and a name
    # git would quote.
    marker = "# secret-scan:allow fake token for tests\n"
    commit(
        git,
        {
            "root.py": f"K = '{fakes.aws_key_id()}'\n",
            ".env": "",
            "a.py": f"{marker}T = None\n",
            # Inert until config defines the driver; then it would replace content.
            ".gitattributes": "*.py diff=hide\n",
        },
    )
    commit(git, {"a.py": f"{marker}T = '{TOKEN}'\n", "b.py": "\n\n\nx = 1\n"})
    commit(git, {"b.py": f"\n\n\nS = '{fakes.slack_token()}'\n", "café.py": f"{token(1)}\n"})
    baseline = found(history(repo))
    assert [(path, line) for path, line, *_ in baseline] == [
        (".env", None),
        ("root.py", 1),
        ("b.py", 4),
        ("café.py", 1),
    ]
    hostile = {
        "color.ui": "always",
        "color.diff": "always",
        "core.quotePath": "true",
        "diff.noprefix": "true",
        "diff.mnemonicPrefix": "true",
        "diff.srcPrefix": "x/",
        "diff.dstPrefix": "y/",
        "diff.suppressBlankEmpty": "true",
        "diff.context": "0",
        "diff.renames": "false",
        "diff.external": "false",
        "diff.submodule": "log",
        "log.diffMerges": "first-parent",
        "log.showSignature": "true",
        "log.showRoot": "false",
        "diff.hide.textconv": "true",
        "diff.hide.command": "true",
    }
    for key, value in hostile.items():
        git("config", key, value)
    assert found(history(repo)) == baseline


# --- a range: what a pull request brings in -----------------------------------


@pytest.fixture
def pull_request(repo: Path, git: GitRun) -> tuple[str, str]:
    """main has a secret of its own; the branch adds one and removes it again."""
    commit(git, {"old.py": f"K = '{fakes.aws_key_id()}'\n"})
    base = git("rev-parse", "HEAD").strip()
    git("switch", "-q", "-c", "feature")
    added = commit(git, {"app.py": f"T = '{TOKEN}'\n"})
    commit(git, {"app.py": "T = None\n"})
    return base, added


def test_since_scans_only_what_the_branch_adds(
    repo: Path, pull_request: tuple[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    base, added = pull_request
    result = scan_history(repo, load_settings(repo, use_user_file=False), "main")
    assert found(result) == [("app.py", 1, "github-token", added, False)]
    assert (result.since, result.commits) == (base, 2)
    # The end state is clean, so a scan of what changed sees nothing.
    assert main(["--since", "main"]) == 0
    assert main(["--history", "--since", "main"]) == 1
    out = capsys.readouterr().out
    assert f"(2 commits scanned, since {base[:12]}), 0 still in HEAD." in out


def test_since_in_json_and_the_report(
    repo: Path, pull_request: tuple[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    base, _ = pull_request
    assert main(["--history", "--since", "main", "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["history"]["since"] == base
    assert main(["--history", "--since", "main", "--format", "markdown"]) == 1
    assert f"- **Scope:** the 2 commits since `main` (`{base}`)\n" in capsys.readouterr().out


# --- refusals and warnings -----------------------------------------------------


def test_needs_a_commit(repo: Path) -> None:
    with pytest.raises(SecretScanError, match="needs a commit"):
        history(repo)


@pytest.mark.parametrize(
    "config", [("extensions.partialClone", "origin"), ("remote.origin.promisor", "true")]
)
def test_a_partial_clone_is_refused(repo: Path, git: GitRun, config: tuple[str, str]) -> None:
    commit(git, {"a.txt": "a\n"})
    git("config", *config)
    with pytest.raises(SecretScanError, match="partial clone"):
        history(repo)


def test_a_committed_private_terms_file_is_an_error(repo: Path, git: GitRun) -> None:
    added = commit(git, {LOCAL_FILE: '{"terms": ["Northwind Traders"]}'})
    git("rm", "-q", "--cached", LOCAL_FILE)
    git("commit", "-q", "-m", "untrack")
    with pytest.raises(SecretScanError, match=f"committed in {added[:12]}"):
        history(repo)


def test_git_failing_partway_is_an_error(repo: Path, git: GitRun) -> None:
    commit(git, {"a.py": "x = 1\n"})
    blob = git("rev-parse", "HEAD:a.py").strip()
    loose = repo / ".git" / "objects" / blob[:2] / blob[2:]
    loose.chmod(stat.S_IWRITE)  # git makes objects read-only, which Windows won't delete
    loose.unlink()  # a corrupt repository
    with pytest.raises(SecretScanError, match="git log failed"):
        history(repo)


def test_a_shallow_clone_says_so(
    repo: Path,
    git: GitRun,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    commit(git, {"a.py": f"T = '{TOKEN}'\n"})
    commit(git, {"a.py": "T = None\n", "b.txt": "b\n"})
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", repo.as_uri(), str(clone)],
        check=True,
        capture_output=True,
    )
    result = history(clone)
    assert result.shallow and result.commits == 1 and found(result) == []
    monkeypatch.chdir(clone)
    assert main(["--history"]) == 0
    assert "Shallow clone" in capsys.readouterr().out
    # A range that stops short of the oldest commit fetched is complete.
    fetched = git("-C", str(clone), "rev-parse", "HEAD").strip()
    git("-C", str(clone), "commit", "-q", "--allow-empty", "-m", "on top")
    result = scan_history(clone, load_settings(clone, use_user_file=False), fetched)
    assert not result.shallow and result.commits == 1


# --- the command line ----------------------------------------------------------


def test_text_output(repo: Path, git: GitRun, capsys: pytest.CaptureFixture[str]) -> None:
    added = commit(git, {"app.py": f"T = '{TOKEN}'\n"})
    commit(git, {"app.py": "T = None\n"})
    assert main(["--history"]) == 1
    out = capsys.readouterr().out
    assert "app.py:1:6  github-token  (40 chars)" in out
    assert (
        f"Committed in {added[:12]} on 2026-03-01; no longer in HEAD, but still in history." in out
    )
    assert "What to do: Revoke the token" in out
    assert "1 finding in history (2 commits scanned), 0 still in HEAD. Values withheld." in out


def test_clean_history(repo: Path, git: GitRun, capsys: pytest.CaptureFixture[str]) -> None:
    commit(git, {"a.py": "x = 1\n"})
    assert main(["--history"]) == 0
    assert "No findings in history (1 commit scanned)." in capsys.readouterr().out
    assert main(["--history", "-q"]) == 0
    assert capsys.readouterr().out == ""


def test_json_output(repo: Path, git: GitRun, capsys: pytest.CaptureFixture[str]) -> None:
    added = commit(git, {"app.py": f"T = '{TOKEN}'\n"})
    assert main(["--history", "--format", "json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["history"] == {"head": added, "commits": 1, "shallow": False}
    (finding,) = doc["findings"]
    assert {k: finding[k] for k in ("path", "line", "commit", "date", "inHead")} == {
        "path": "app.py",
        "line": 1,
        "commit": added,
        "date": "2026-03-01T09:00:00Z",
        "inHead": True,
    }


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--history", "src"], "PATH arguments"),
        (["--history", "--sarif", "out.sarif"], "--sarif can't be combined"),
        (["--history", "--staged"], "can't be combined with --staged"),
        (["--history", "--since=--output=x"], "needs a git ref, not an option"),
        (["--history", "--since", "no-such-ref"], "no such commit here"),
    ],
)
def test_options_history_refuses(
    repo: Path,
    git: GitRun,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    message: str,
) -> None:
    commit(git, {"a.py": "x = 1\n"})
    assert main(argv) == 2
    assert message in capsys.readouterr().err


def test_outside_a_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["--history"]) == 2
    assert "--history needs a git repository" in capsys.readouterr().err


@pytest.mark.parametrize("fmt", ["text", "json", "markdown"])
def test_history_never_prints_a_matched_value(
    repo: Path,
    git: GitRun,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    fmt: str,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("SECRET_SCAN_PRIVATE_TERMS", "Contoso Pharmaceuticals")
    commit(git, {"settings.py": leaky_settings()})
    commit(git, {"settings.py": "# moved to the vault\n"})
    assert main(["--history", "--format", fmt]) == 1
    out, err = capsys.readouterr()
    assert "::error" not in out  # annotations point at current lines; not for history
    for secret in [*ALL_SECRETS, "Contoso Pharmaceuticals"]:
        assert secret.casefold() not in (out + err).casefold()
