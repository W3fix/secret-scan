"""The exceptions register: every exception in effect, why, and how often it applied."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secret_scan.cli import main
from secret_scan.config import WITHHELD_REASON
from tests import fakes


def test_register_lists_every_exception(
    excepted_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["--format", "json"])
    out = capsys.readouterr().out
    assert json.loads(out)["exceptions"] == [
        {
            "kind": "disable",
            "source": ".secret-scan.json: disable[0]",
            "rule": "url-embedded-credentials",
            "reason": WITHHELD_REASON,
        },
        {
            "kind": "ignore",
            "source": ".secret-scan.json: ignore[0]",
            "path": "vendor/",
            "reason": "third-party code",
            "applied": 2,
        },
        {
            "kind": "allow",
            "source": ".secret-scan.json: allow[0]",
            "rule": "github-token",
            "path": "docs/**",
            "reason": "revoked examples",
            "applied": 2,
        },
        {
            "kind": "allow",
            "source": ".secret-scan.json: allow[1]",
            "value": "withheld",
            "reason": "unit-test key",
            "applied": 1,
        },
        {
            "kind": "allow",
            "source": ".secret-scan.json: allow[2]",
            "rule": "dotenv-file",
            "path": "examples/.env",
            "reason": "names only, no values",
            "applied": 1,
        },
        {
            "kind": "inline",
            "source": "src/app.py:1",
            "rule": "aws-access-key-id",
            "reason": "documented format, test only",
        },
        {"kind": "inline", "source": "src/app.py:2", "rule": "github-token", "reason": "fixture"},
        {
            "kind": "inline",
            "source": "src/app.py:3",
            "rule": "stripe-live-key",
            "reason": WITHHELD_REASON,
        },
        {
            "kind": "inline",
            "source": "src/app.py:4",
            "rule": "private-term",
            "reason": WITHHELD_REASON,
        },
        {
            "kind": "inline",
            "source": "src/app.py:5",
            "rule": "slack-token",
            "reason": WITHHELD_REASON,
        },
    ]
    for value in (fakes.github_token(), fakes.generic_value(), fakes.stripe_live(), "Northwind"):
        assert value not in out


def test_no_exceptions_is_an_empty_register(
    leaky_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["--format", "json"])
    assert json.loads(capsys.readouterr().out)["exceptions"] == []
