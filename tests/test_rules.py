"""Each built-in rule fires on a realistic value and stays quiet on look-alikes."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from secret_scan.config import load_settings
from secret_scan.rules import CONTENT_RULES, looks_like_placeholder, shannon_entropy
from secret_scan.scanner import scan_text
from tests import fakes


def rules_hit(text: str, tmp_path: Path) -> list[str]:
    settings = load_settings(tmp_path, use_user_file=False, environ={})
    return [f.rule for f in scan_text("f.txt", text, settings)]


POSITIVES: list[tuple[str, Callable[[], str]]] = [
    ("private-key", lambda: f"{fakes.private_key_header()}\n{fakes.private_key_body()}\n"),
    ("private-key", lambda: f"{fakes.private_key_header()}\r\n{fakes.private_key_body()}\r\n"),
    # Escaped newlines, as in a cloud service-account JSON file.
    (
        "private-key",
        lambda: f'"private_key": "{fakes.private_key_header("")}\\n{fakes.private_key_body()}\\n"',
    ),
    # Encrypted PEM and PGP put headers before the body.
    (
        "private-key",
        lambda: (
            f"{fakes.private_key_header()}\nProc-Type: 4,ENCRYPTED\n"
            f"DEK-Info: AES-128-CBC,0000\n\n{fakes.private_key_body()}\n"
        ),
    ),
    (
        "private-key",
        lambda: (
            f"{fakes.private_key_header('PGP ')}\nVersion: GnuPG v2\n\n{fakes.private_key_body()}\n"
        ),
    ),
    (
        "private-key",
        lambda: f"{fakes.private_key_header('OPENSSH ')}\n    {fakes.private_key_body()}\n",
    ),
    ("aws-access-key-id", lambda: f"key = {fakes.aws_key_id()}"),
    ("aws-secret-access-key", lambda: f"aws_secret_access_key = {fakes.aws_secret()}"),
    (
        "azure-storage-account-key",
        lambda: f"DefaultEndpointsProtocol=https;AccountName=demo;AccountKey={fakes.storage_key()}",
    ),
    (
        "azure-sas-token",
        lambda: f"https://demo.blob.core.windows.net/c?sv=2024-11-04&sp=r&sig={fakes.sas_sig()}",
    ),
    ("azure-entra-client-secret", lambda: f"secret: {fakes.entra_secret()}"),
    (
        "connection-string-password",
        lambda: f"Server=db.internal;Database=app;User Id=svc;Password={fakes.password()};",
    ),
    ("url-embedded-credentials", lambda: f"postgres://svc:{fakes.password()}@db.internal/app"),
    # Short default credentials; TruffleHog's canary repo has one this rule used to miss.
    ("url-embedded-credentials", lambda: "https://" + "admin:" + "admin@db.internal/"),
    # Look-alikes of documentation domains are real hosts.
    ("url-embedded-credentials", lambda: f"https://svc:{fakes.password()}@notexample.com/"),
    (
        "url-embedded-credentials",
        lambda: f"https://svc:{fakes.password()}@example.com.contoso.net/",
    ),
    (
        "aws-access-key-id",
        lambda: f"Credential={fakes.aws_key_id()}/20240101/us-east-1/s3/aws4_request",
    ),
    ("github-token", lambda: f"token: {fakes.github_token()}"),
    ("github-token", lambda: fakes.github_fine_grained()),
    ("gitlab-token", lambda: fakes.gitlab_token()),
    ("slack-token", lambda: fakes.slack_token()),
    ("slack-webhook", lambda: fakes.slack_webhook()),
    ("stripe-live-key", lambda: fakes.stripe_live()),
    ("google-api-key", lambda: f'"{fakes.google_api_key()}"'),
    ("npm-token", lambda: f"//registry.npmjs.org/:_authToken={fakes.npm_token()}"),
    ("anthropic-api-key", lambda: fakes.anthropic_key()),
    ("openai-api-key", lambda: fakes.openai_key()),
    ("generic-assigned-secret", lambda: f'api_key = "{fakes.generic_value()}"'),
    ("generic-assigned-secret", lambda: f'"client_secret": "{fakes.generic_value()}"'),
]


@pytest.mark.parametrize(("rule", "make"), POSITIVES, ids=[r for r, _ in POSITIVES])
def test_rule_fires(rule: str, make: Callable[[], str], tmp_path: Path) -> None:
    assert rule in rules_hit(make(), tmp_path)


def test_every_content_rule_has_a_positive_case() -> None:
    covered = {r for r, _ in POSITIVES}
    assert {r.id for r in CONTENT_RULES} <= covered


@pytest.mark.parametrize(
    "text",
    [
        "AKIAIOSFODNN7EXAMPLE",  # AWS's documented example key
        'password = "your-password-here"',
        'api_key = "${API_KEY}"',
        "api_key = '<insert key>'",
        'secret = "aaaaaaaaaaaaaaaaaaaa"',  # long but no entropy
        "connect(host=h, password=db_password_value)",  # kwargs, not a connection string
        "https://user:${PASSWORD}@example.com",
        "https://user:password@db.internal/",  # documentation stand-in
        "ssh://git@github.com:22/org/repo.git",  # user and port, no password
        "new URL('http://abc:xyz@example.com')",  # documentation domains (RFC 2606)
        "https://theuser:thepwd@www.example.org:81/foo",
        "postgres://app:hunter22@db.example/orders",
        "https://a:b@db.internal/",  # one-character syntax example
        "Password=${DB_PASSWORD};Server=db;",
        "-----BEGIN PUBLIC KEY-----",
        'conn = f"Server=db;User Id=app;Password={settings.db_password};"',  # f-string
        'string.Format("Server=db;User Id=app;Password={0};", pw)',  # .NET format item
        "export CONN='Server=db;User Id=app;Password=$DB_PASSWORD;'",  # shell variable
        'url = f"postgres://app:{password}@db.internal/orders"',
        "-----BEGIN CERTIFICATE-----",
        # An AWS-shaped run inside a base64 blob.
        "data:application/wasm;base64,Ym9v" + fakes.aws_key_id() + "dGVz",
        "AGFzbQEA+" + fakes.aws_key_id() + "+AAAB",
        # A private-key header with no key material after it.
        fakes.private_key_header(),
        fakes.private_key_header() + "\nMIIE...\n",  # truncated documentation example
        fakes.private_key_header() + "\nBad Key, though the cert should be OK\n",
    ],
)
def test_look_alikes_stay_quiet(text: str, tmp_path: Path) -> None:
    assert rules_hit(text, tmp_path) == []


def test_specific_rule_wins_over_generic(tmp_path: Path) -> None:
    hits = rules_hit(f'access_token = "{fakes.github_token()}"', tmp_path)
    assert hits == ["github-token"]


def test_entropy() -> None:
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy(fakes.generic_value()) > 4


def test_placeholder_detection() -> None:
    assert looks_like_placeholder("REPLACE_ME")
    assert looks_like_placeholder("{{ secrets.TOKEN }}")
    assert not looks_like_placeholder(fakes.generic_value())


@pytest.mark.parametrize(
    ("name", "rule"),
    [
        (".env", "dotenv-file"),
        ("api/.env.production", "dotenv-file"),
        ("infra/terraform.tfstate", "terraform-state"),
        ("terraform.tfstate.1700000000.backup", "terraform-state"),
        ("certs/site.pfx", "key-material-file"),
        ("home/id_ed25519", "key-material-file"),
    ],
)
def test_path_rules_fire(name: str, rule: str, tmp_path: Path) -> None:
    from secret_scan.scanner import scan_path_rules

    settings = load_settings(tmp_path, use_user_file=False, environ={})
    assert [f.rule for f in scan_path_rules(name, settings)] == [rule]


@pytest.mark.parametrize(
    "name", [".env.example", ".env.sample", ".envrc", "id_rsa.pub", "main.tf", "variables.tfvars"]
)
def test_path_rules_quiet(name: str, tmp_path: Path) -> None:
    from secret_scan.scanner import scan_path_rules

    settings = load_settings(tmp_path, use_user_file=False, environ={})
    assert scan_path_rules(name, settings) == []
