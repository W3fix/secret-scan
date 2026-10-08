from __future__ import annotations

from pathlib import Path

from secret_scan.config import Settings, load_settings
from secret_scan.scanner import Finding, scan, scan_text
from secret_scan.sources import Candidate
from tests import fakes


def settings(tmp_path: Path) -> Settings:
    return load_settings(tmp_path, use_user_file=False, environ={})


def test_location_and_length(tmp_path: Path) -> None:
    token = fakes.github_token()
    text = "line one\n\n  x = " + token + "\n"
    [f] = scan_text("a.py", text, settings(tmp_path))
    assert (f.line, f.column, f.length) == (3, 7, len(token))


def test_finding_has_no_value_field() -> None:
    # The guarantee that output can't leak a secret starts here.
    assert set(Finding.__dataclass_fields__) == {"path", "line", "column", "rule", "length", "note"}


def test_inline_allow_with_reason(tmp_path: Path) -> None:
    text = f"t = '{fakes.github_token()}'  # secret-scan:allow revoked test token, kept for docs\n"
    assert scan_text("a.py", text, settings(tmp_path)) == []


def test_inline_allow_on_line_above(tmp_path: Path) -> None:
    text = f"# secret-scan:allow fixture for parser tests\nt = '{fakes.github_token()}'\n"
    assert scan_text("a.py", text, settings(tmp_path)) == []


def test_inline_allow_above_must_be_its_own_line(tmp_path: Path) -> None:
    text = f"x = 1  # secret-scan:allow unrelated\nt = '{fakes.github_token()}'\n"
    assert len(scan_text("a.py", text, settings(tmp_path))) == 1


def test_inline_allow_without_reason_is_reported(tmp_path: Path) -> None:
    text = f"t = '{fakes.github_token()}'  # secret-scan:allow\n"
    [f] = scan_text("a.py", text, settings(tmp_path))
    assert "reason" in f.note


def _candidate(path: str, data: bytes) -> Candidate:
    return Candidate(path, len(data), lambda: data)


def test_binary_files_skip_content_rules(tmp_path: Path) -> None:
    data = b"\0\1\2" + fakes.github_token().encode()
    result = scan([_candidate("blob.bin", data)], settings(tmp_path))
    assert result.findings == [] and result.skipped_binary == 1


def test_path_rules_apply_to_binary_files(tmp_path: Path) -> None:
    result = scan([_candidate("cert.pfx", b"\0\1\2")], settings(tmp_path))
    assert [f.rule for f in result.findings] == ["key-material-file"]


def test_large_files_are_listed_not_scanned(tmp_path: Path) -> None:
    s = settings(tmp_path)
    s.max_file_bytes = 10
    result = scan([_candidate("big.txt", fakes.github_token().encode())], s)
    assert result.findings == [] and result.skipped_large == ["big.txt"]


def test_local_private_file_is_never_scanned(tmp_path: Path) -> None:
    data = fakes.github_token().encode()
    result = scan([_candidate("sub/.secret-scan.local.json", data)], settings(tmp_path))
    assert result.findings == [] and result.files_scanned == 0


def test_findings_sorted_with_path_findings_first(tmp_path: Path) -> None:
    data = f"a\n{fakes.github_token()}\n".encode()
    result = scan([_candidate(".env", data)], settings(tmp_path))
    found = [(f.rule, f.line) for f in result.findings]
    assert found == [("dotenv-file", None), ("github-token", 2)]
