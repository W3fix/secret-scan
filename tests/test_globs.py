"""Path globs decide what `allow` and `ignore` entries cover.

A glob that matches too much silently hides real findings, so each behaviour
is pinned in both directions: what must match and what must not.
"""

from __future__ import annotations

import pytest

from secret_scan.globs import compile_glob

CASES: list[tuple[str, list[str], list[str]]] = [
    # (glob, paths that match, paths that don't)
    ("*.pem", ["a.pem", "certs/a.pem", "x/y/z.pem"], ["a.pem.bak", "pem", "a.pemx"]),
    ("secrets.txt", ["secrets.txt", "a/b/secrets.txt"], ["mysecrets.txt", "secrets.txt.old"]),
    ("docs/**", ["docs/a.md", "docs/x/y.md"], ["docs", "mydocs/a.md", "src/docs/a.md"]),
    # A trailing slash covers the directory's contents, anchored at the scan root.
    ("vendor/", ["vendor/a.js", "vendor/x/y.js"], ["vendor", "src/vendor/a.js", "vendored/a.js"]),
    ("/build/out.txt", ["build/out.txt"], ["x/build/out.txt"]),
    ("**/test/*.py", ["test/a.py", "x/test/a.py"], ["test/sub/a.py", "test/a.pyc"]),
    ("docs/**/*.md", ["docs/a.md", "docs/x/y/a.md"], ["docs/a.txt", "a.md"]),
    ("src/*.py", ["src/a.py"], ["src/x/a.py", "a.py", "lib/src/a.py"]),
    ("file?.txt", ["file1.txt", "d/fileA.txt"], ["file.txt", "file12.txt", "file/.txt"]),
    ("key[abc].pem", ["keya.pem", "keyc.pem"], ["keyd.pem", "key.pem"]),
    ("key[!abc].pem", ["keyd.pem", "key1.pem"], ["keya.pem", "key.pem"]),
    ("key[0-9].pem", ["key0.pem", "key9.pem"], ["keya.pem"]),
    # Regular-expression characters are literal.
    ("a+b(1).txt", ["a+b(1).txt"], ["aab1.txt", "a+b1.txt"]),
    ("v1.0/*", ["v1.0/a"], ["v1x0/a"]),
    # An unclosed bracket is literal, not an error.
    ("weird[.txt", ["weird[.txt"], ["weirdx.txt"]),
    ("**", ["a", "a/b/c"], []),
]


@pytest.mark.parametrize(("glob", "hits", "misses"), CASES, ids=[c[0] for c in CASES])
def test_glob(glob: str, hits: list[str], misses: list[str]) -> None:
    pattern = compile_glob(glob)
    for path in hits:
        assert pattern.match(path), f"{glob!r} should match {path!r}"
    for path in misses:
        assert not pattern.match(path), f"{glob!r} should not match {path!r}"


def test_surrounding_whitespace_is_ignored() -> None:
    assert compile_glob("  *.pem \n").match("a.pem")


@pytest.mark.parametrize("glob", ["", "   "])
def test_empty_glob_is_an_error(glob: str) -> None:
    with pytest.raises(ValueError, match="empty glob"):
        compile_glob(glob)
