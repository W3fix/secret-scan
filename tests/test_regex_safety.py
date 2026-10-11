"""Every built-in rule must run in roughly linear time on hostile input.

Python's regex engine backtracks, so a pattern with nested or overlapping
quantifiers can take exponential time on text crafted (or accidentally shaped)
to almost match. A scanner that hangs on one minified file is a commit gate
people switch off. Each rule runs against inputs built to stress the usual
failure shapes; the budget is generous so a slow CI runner can't flake it, and
a catastrophic pattern still blows through it by orders of magnitude.
"""

from __future__ import annotations

import time

import pytest

from secret_scan.rules import CONTENT_RULES, Rule
from tests import fakes

N = 20_000
BUDGET_SECONDS = 1.0

HOSTILE: dict[str, str] = {
    "letters": "a" * N,
    "upper": "A" * N,
    "digits": "0" * N,
    "spaces": " " * N,
    "base64": fakes.chars(fakes.B64, N, seed=3),
    "colons": "a:" * (N // 2),
    "header-like lines": "-----BEGIN RSA PRIVATE KEY-----\n" + "x: a: a: a: a: a: a: a:\n" * 2000,
    "header-like one line": "-----BEGIN PRIVATE KEY-----\n" + "a: " * (N // 3),
    "repeated headers": "-----BEGIN PRIVATE KEY-----\n" * (N // 28),
    "url prefixes": "a://" * (N // 4),
    "url credentials": "https://u:" * (N // 10),
    "at signs": "a:bbbbbb@" * (N // 9),
    "assignments": "password=" * (N // 9),
    "quoted assignments": 'api_key = "' * (N // 11),
    "connection strings": "Password=;" * (N // 10),
    "key prefixes": "AKIA" * (N // 4),
    "token prefixes": "ghp_" * (N // 4),
    "escaped newlines": "\\n" * (N // 2),
    "equals": "=" * N,
}


@pytest.mark.parametrize("rule", CONTENT_RULES, ids=[r.id for r in CONTENT_RULES])
def test_rule_runs_in_linear_time(rule: Rule) -> None:
    slow: list[str] = []
    for name, text in HOSTILE.items():
        start = time.perf_counter()
        for _ in rule.pattern.finditer(text):
            pass
        elapsed = time.perf_counter() - start
        if elapsed > BUDGET_SECONDS:
            slow.append(f"{name}: {elapsed:.1f}s")
    assert not slow, f"{rule.id} is too slow on: {', '.join(slow)}"
