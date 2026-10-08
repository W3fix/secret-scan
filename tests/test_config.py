from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from secret_scan.config import load_settings
from secret_scan.errors import SecretScanError
from secret_scan.scanner import scan_text
from tests import fakes


def write_config(root: Path, data: dict[str, Any]) -> None:
    (root / ".secret-scan.json").write_text(json.dumps(data))


def load(root: Path, **kw: Any) -> Any:
    kw.setdefault("environ", {})
    kw.setdefault("use_user_file", False)
    return load_settings(root, **kw)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"allow": [{"value": "x"}]}, "'reason' is required"),
        ({"allow": [{"rule": "github-token", "reason": "r"}]}, "use 'disable'"),
        ({"allow": [{"path": "docs/**", "reason": "r"}]}, "use 'ignore'"),
        ({"allow": [{"rule": "nope", "path": "a", "reason": "r"}]}, "unknown rule 'nope'"),
        ({"disable": [{"rule": "github-token"}]}, "'reason' is required"),
        ({"ignore": [{"path": "dist/"}]}, "'reason' is required"),
        ({"rules": [{"id": "x", "why": "w", "pattern": "a"}]}, "rule id must be"),
        ({"rules": [{"id": "github-token", "why": "w", "pattern": "a"}]}, "already in use"),
        ({"rules": [{"id": "my-rule", "why": "w", "pattern": "("}]}, "invalid pattern"),
        ({"allowList": []}, "unknown key(s) allowList"),
        ({"maxFileBytes": 0}, "positive integer"),
    ],
)
def test_invalid_config_is_rejected(tmp_path: Path, data: dict[str, Any], message: str) -> None:
    write_config(tmp_path, data)
    with pytest.raises(SecretScanError, match=None) as exc:
        load(tmp_path)
    assert message in str(exc.value)


def test_invalid_json_reports_line(tmp_path: Path) -> None:
    (tmp_path / ".secret-scan.json").write_text("{\n  'single': 1\n}")
    with pytest.raises(SecretScanError, match="line 2"):
        load(tmp_path)


def test_explicit_missing_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(SecretScanError, match="not found"):
        load(tmp_path, config_path=tmp_path / "nope.json")


def test_allow_by_value(tmp_path: Path) -> None:
    token = fakes.github_token()
    write_config(tmp_path, {"allow": [{"value": token, "reason": "revoked; used in docs"}]})
    assert scan_text("a", token, load(tmp_path)) == []


def test_allow_by_rule_and_path(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        {"allow": [{"rule": "github-token", "path": "docs/**", "reason": "revoked examples"}]},
    )
    s = load(tmp_path)
    token = fakes.github_token()
    assert scan_text("docs/guide/setup.md", token, s) == []
    assert len(scan_text("src/app.py", token, s)) == 1


def test_disable_and_ignore(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        {
            "disable": [{"rule": "github-token", "reason": "GitHub push protection covers it"}],
            "ignore": [{"path": "vendor/", "reason": "third-party code"}],
        },
    )
    s = load(tmp_path)
    assert all(r.id != "github-token" for r in s.content_rules)
    assert s.is_ignored("vendor/lib/x.js") and not s.is_ignored("src/vendor.js")


def test_custom_rule(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        {
            "rules": [
                {
                    "id": "internal-host",
                    "why": "Internal hostnames reveal network layout.",
                    "pattern": r"\b[a-z0-9-]+\.corp\.contoso\.com\b",
                    "ignoreCase": True,
                }
            ]
        },
    )
    [f] = scan_text("a", "connect to DB01.CORP.CONTOSO.COM now", load(tmp_path))
    assert f.rule == "internal-host"


def test_private_terms_from_all_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    user_file = tmp_path / "xdg" / "secret-scan" / "private.json"
    user_file.parent.mkdir(parents=True)
    user_file.write_text(json.dumps({"terms": ["Fabrikam"]}))
    (tmp_path / ".secret-scan.local.json").write_text(
        json.dumps(
            {
                "terms": ["Northwind Traders"],
                "patterns": [
                    {"id": "my-phone", "why": "Personal phone.", "pattern": r"555[ .-]?0142"}
                ],
            }
        )
    )
    s = load(tmp_path, use_user_file=True, environ={"SECRET_SCAN_PRIVATE_TERMS": "Tailspin\n\n"})
    text = "fabrikam\nnorthwind traders\ntailspin\ncall 555-0142\nfabrikamish\n"
    rules = [f.rule for f in scan_text("a", text, s)]
    assert rules == ["private-term", "private-term", "private-term", "my-phone"]
    assert len(s.private_sources) == 3
    assert all("Fabrikam" not in src for src in s.private_sources)


def test_private_term_minimum_length(tmp_path: Path) -> None:
    (tmp_path / ".secret-scan.local.json").write_text(json.dumps({"terms": ["ab"]}))
    with pytest.raises(SecretScanError, match="at least 3"):
        load(tmp_path)


def test_disabling_a_private_pattern_is_allowed(tmp_path: Path) -> None:
    (tmp_path / ".secret-scan.local.json").write_text(
        json.dumps({"patterns": [{"id": "my-phone", "why": "w", "pattern": "555"}]})
    )
    write_config(tmp_path, {"disable": [{"rule": "my-phone", "reason": "noisy here"}]})
    assert all(r.id != "my-phone" for r in load(tmp_path).content_rules)
