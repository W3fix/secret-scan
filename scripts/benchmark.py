#!/usr/bin/env python3
"""Scan pinned public corpora and compare the findings with the recorded ones.

Each corpus in ``benchmarks/corpora.json`` is a public repository at a fixed
commit, and ``benchmarks/<name>.expected`` lists every finding it should
produce as ``path:line rule``. Any difference fails: a new finding is usually a
false positive, and a missing one means a rule got narrower. Fix the rule, or
run with ``--update`` and let the reviewer see the change in the diff.

Only locations and rule ids are compared or printed, never matched values.

    scripts/benchmark.py              # fetch missing corpora, scan, compare
    scripts/benchmark.py --update     # rewrite the expected files
    scripts/benchmark.py cpython-lib  # one corpus
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmarks"
CACHE = ROOT / ".benchmarks"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def fetch(corpus: dict[str, object], dest: Path) -> None:
    """Shallow, sparse checkout of exactly the pinned commit."""
    commit = str(corpus["commit"])
    if (dest / ".git").is_dir() and git(dest, "rev-parse", "HEAD") == commit:
        return
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    git(dest, "init", "-q")
    git(dest, "remote", "add", "origin", str(corpus["repo"]))
    paths = [str(p) for p in corpus["paths"]]  # type: ignore[attr-defined]
    if paths != ["."]:
        git(dest, "sparse-checkout", "set", "--no-cone", *(f"/{p}/" for p in paths))
    git(dest, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit)
    git(dest, "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD")


def scan(corpus: dict[str, object], dest: Path) -> Counter[str]:
    # Nothing from the caller's environment may change the result: no private
    # terms, no user config, no GitHub annotations.
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"SECRET_SCAN_PRIVATE_TERMS", "GITHUB_ACTIONS"}
    }
    env["PYTHONPATH"] = str(ROOT / "src")
    proc = subprocess.run(
        [sys.executable, "-m", "secret_scan", "--format", "json", "--no-user-config"]
        + [str(p) for p in corpus["paths"]],  # type: ignore[attr-defined]
        cwd=dest,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        sys.exit(f"{corpus['name']}: scan failed (exit {proc.returncode}): {proc.stderr.strip()}")
    findings = json.loads(proc.stdout)["findings"]
    return Counter(f"{f['path']}:{f['line']} {f['rule']}" for f in findings)


def read_expected(path: Path) -> Counter[str]:
    if not path.exists():
        return Counter()
    lines = path.read_text().splitlines()
    return Counter(line for line in lines if line and not line.startswith("#"))


def write_expected(path: Path, corpus: dict[str, object], found: Counter[str]) -> None:
    header = f"# {corpus['name']} @ {corpus['commit']}. Written by scripts/benchmark.py --update.\n"
    path.write_text(header + "".join(f"{line}\n" for line in sorted(found.elements())))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("names", nargs="*", help="corpora to run (default: all)")
    parser.add_argument("--update", action="store_true", help="rewrite the expected files")
    args = parser.parse_args()

    corpora = json.loads((BENCH / "corpora.json").read_text())
    unknown = set(args.names) - {c["name"] for c in corpora}
    if unknown:
        parser.error(f"unknown corpus: {', '.join(sorted(unknown))}")

    failed = False
    for corpus in corpora:
        if args.names and corpus["name"] not in args.names:
            continue
        dest = CACHE / corpus["name"]
        fetch(corpus, dest)
        found = scan(corpus, dest)
        expected_file = BENCH / f"{corpus['name']}.expected"
        if args.update:
            write_expected(expected_file, corpus, found)
            print(f"{corpus['name']}: {sum(found.values())} findings recorded")
            continue
        expected = read_expected(expected_file)
        new, gone = found - expected, expected - found
        if not new and not gone:
            print(f"{corpus['name']}: {sum(found.values())} findings, as expected")
            continue
        failed = True
        print(f"{corpus['name']}: {sum(new.values())} new, {sum(gone.values())} missing")
        for line in sorted(new.elements()):
            print(f"  + {line}")
        for line in sorted(gone.elements()):
            print(f"  - {line}")
    if failed:
        print("\nFix the rule, or run with --update if the change is deliberate.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
