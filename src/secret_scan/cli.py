"""Command-line interface.

Exit codes: 0 no findings, 1 findings, 2 usage or configuration error.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TextIO

from secret_scan import __version__
from secret_scan.config import CONFIG_FILE, LOCAL_FILE, PRIVATE_ENV, load_settings
from secret_scan.errors import SecretScanError
from secret_scan.report import to_sarif, write_github_annotations, write_json, write_text
from secret_scan.rules import PathRule
from secret_scan.scanner import scan
from secret_scan.sources import (
    Candidate,
    changed_since,
    ensure_local_file_untracked,
    git_root,
    staged_files,
    tracked_files,
    walk_paths,
)

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

_DESCRIPTION = """\
Scan files for credentials and personal data. Reports where, never what:
output gives the file, line, rule and length, and never the matched value.

With no PATH, scans every file tracked by git (or the current directory,
outside a repository)."""

_EPILOG = f"""\
configuration:
  {CONFIG_FILE}           committed: allow-list, ignored paths, extra rules
  {LOCAL_FILE}     git-ignored: private terms for this repository
  ~/.config/secret-scan/private.json
                               private terms for every repository
  ${PRIVATE_ENV}  private terms, one per line (for CI secrets)

exit status: 0 clean, 1 findings, 2 error
"""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secret-scan",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="*", type=Path, metavar="PATH", help="files or directories")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--staged", action="store_true", help="scan staged content (for pre-commit hooks)"
    )
    mode.add_argument("--since", metavar="REF", help="scan only files changed since a git ref")
    p.add_argument("--format", choices=("text", "json"), default="text", help="stdout format")
    p.add_argument("--sarif", type=Path, metavar="FILE", help="also write SARIF 2.1.0 to FILE")
    p.add_argument(
        "--config", type=Path, metavar="FILE", help=f"repo config (default {CONFIG_FILE})"
    )
    p.add_argument(
        "--private", type=Path, metavar="FILE", help=f"private terms (default {LOCAL_FILE})"
    )
    p.add_argument(
        "--no-user-config", action="store_true", help="ignore ~/.config/secret-scan/private.json"
    )
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-q", "--quiet", action="store_true", help="print nothing when clean")
    p.add_argument("--list-rules", action="store_true", help="list active rules and exit")
    p.add_argument(
        "--install-hook",
        action="store_true",
        help="install a git pre-commit hook in this repository and exit",
    )
    p.add_argument("--force", action="store_true", help="with --install-hook: replace a hook")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _use_color(stream: TextIO, disabled: bool) -> bool:
    if disabled or os.environ.get("NO_COLOR"):
        return False
    return os.environ.get("FORCE_COLOR") is not None or stream.isatty()


def _candidates(args: argparse.Namespace, root: Path, in_git: bool) -> Iterable[Candidate]:
    if args.paths:
        if args.staged or args.since:
            raise SecretScanError("PATH arguments can't be combined with --staged or --since")
        return walk_paths(args.paths, Path.cwd())
    if args.staged or args.since:
        if not in_git:
            raise SecretScanError("--staged and --since need a git repository")
        return staged_files(root) if args.staged else changed_since(root, args.since)
    return tracked_files(root) if in_git else walk_paths([Path.cwd()], Path.cwd())


_HOOK = """\
#!/bin/sh
# Installed by secret-scan {version}: scans staged content before each commit.
# Findings block the commit. To bypass once (think first): git commit --no-verify
exec "{python}" -m secret_scan --staged
"""


def install_hook(root: Path, force: bool, out: TextIO) -> int:
    hooks = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--git-path", "hooks"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    hook = (root / hooks / "pre-commit").resolve()
    if hook.exists() and not force:
        raise SecretScanError(
            f"{hook} already exists. Re-run with --force to replace it, or call "
            "`python -m secret_scan --staged` from your existing hook"
        )
    hook.parent.mkdir(parents=True, exist_ok=True)
    # The absolute interpreter path keeps the hook working when the tool was
    # installed with pipx and isn't on the PATH that git gives hooks.
    hook.write_text(_HOOK.format(version=__version__, python=sys.executable), encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    out.write(f"Installed pre-commit hook: {hook}\n")
    return EXIT_CLEAN


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    out, err = sys.stdout, sys.stderr
    try:
        cwd = Path.cwd()
        found = git_root(cwd)
        in_git = found is not None
        root = found if found is not None else cwd

        if args.install_hook:
            if not in_git:
                raise SecretScanError("--install-hook must be run inside a git repository")
            return install_hook(root, args.force, out)

        settings = load_settings(
            root,
            config_path=args.config,
            local_path=args.private,
            use_user_file=not args.no_user_config,
        )

        if args.list_rules:
            for r in settings.all_rules:
                kind = "path" if isinstance(r, PathRule) else "content"
                out.write(f"{r.id:<28} {kind:<8} {r.origin:<8} {r.why}\n")
            return EXIT_CLEAN

        if in_git:
            ensure_local_file_untracked(root)

        result = scan(_candidates(args, root, in_git), settings)

        if args.sarif:
            args.sarif.write_text(json.dumps(to_sarif(result, settings), indent=2) + "\n")
        if args.format == "json":
            write_json(result, settings, out)
        else:
            write_text(
                result, settings, out, color=_use_color(out, args.no_color), quiet=args.quiet
            )
            if os.environ.get("GITHUB_ACTIONS") == "true":
                write_github_annotations(result, settings, out)
        return EXIT_FINDINGS if result.findings else EXIT_CLEAN
    except SecretScanError as e:
        err.write(f"secret-scan: error: {e}\n")
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130
