"""Each built-in rule fires on a realistic value and stays quiet on look-alikes."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from secret_scan.config import load_settings
from secret_scan.rules import (
    CONTENT_RULES,
    PATH_RULES,
    PathRule,
    Rule,
    github_checksum_ok,
    looks_like_placeholder,
    shannon_entropy,
)
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
    # Longer than the documented layout: no checksum to check, so it still counts.
    ("github-token", lambda: "gh" + "s_" + fakes.chars(fakes.ALNUM, 40, seed=101)),
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
    # Deliberately caught, though both come from documentation: a descriptive value
    # looks exactly like a weak real password, and missing one of those is worse
    # than a reviewed exception. Decided 2026-10-08; see README Limitations.
    ("generic-assigned-secret", lambda: "'X-TOKEN-SECRET': '" + "Super" + "SecretToken'"),
    (
        "generic-assigned-secret",
        lambda: "password = '" + "a_password_having" + "_at_least_32_chars'",
    ),
]


# Rules for one file format: (rule, path, content).
SCOPED_POSITIVES: list[tuple[str, str, Callable[[], str]]] = [
    (
        "kubeconfig-client-key",
        "anywhere.yaml",
        lambda: f"    client-key-data: {fakes.kube_client_key()}\n",
    ),
    ("kubeconfig-token", "kubeconfig", lambda: f"    token: {fakes.bearer_token()}\n"),
    ("kubeconfig-token", "ops/.kube/config", lambda: f"    password: {fakes.password()}\n"),
    (
        "kubeconfig-token",
        "clusters/prod-kubeconfig.yaml",
        lambda: f"      id-token: {fakes.bearer_token()}\n",
    ),
    (
        "npmrc-auth",
        "web/.npmrc",
        lambda: f"//registry.example.org/:_authToken={fakes.generic_value()}\n",
    ),
    ("npmrc-auth", ".npmrc", lambda: f"_auth = {fakes.docker_auth()}\n"),
    (
        "pypirc-password",
        ".pypirc",
        lambda: f"[pypi]\nusername = __token__\npassword = {fakes.generic_value()}\n",
    ),
    (
        "docker-config-auth",
        "ci/.docker/config.json",
        lambda: '{"auths": {"registry.example.org": {"auth": "' + fakes.docker_auth() + '"}}}',
    ),
    (
        "docker-config-auth",
        "deploy/pull.dockerconfigjson",
        lambda: '{"auths": {"r": {"identitytoken": "' + fakes.bearer_token() + '"}}}',
    ),
]


@pytest.mark.parametrize(("rule", "make"), POSITIVES, ids=[r for r, _ in POSITIVES])
def test_rule_fires(rule: str, make: Callable[[], str], tmp_path: Path) -> None:
    assert rule in rules_hit(make(), tmp_path)


def test_every_builtin_rule_says_what_to_do() -> None:
    rules: list[Rule | PathRule] = [*CONTENT_RULES, *PATH_RULES]
    for rule in rules:
        assert rule.fix.endswith("."), rule.id
        assert rule.fix != rule.why, rule.id


def test_every_content_rule_has_a_positive_case() -> None:
    covered = {r for r, _ in POSITIVES} | {r for r, _, _ in SCOPED_POSITIVES}
    assert {r.id for r in CONTENT_RULES} <= covered


def rules_hit_in(path: str, text: str, tmp_path: Path) -> list[str]:
    settings = load_settings(tmp_path, use_user_file=False, environ={})
    return [f.rule for f in scan_text(path, text, settings)]


@pytest.mark.parametrize(
    ("rule", "path", "make"), SCOPED_POSITIVES, ids=[f"{r}:{p}" for r, p, _ in SCOPED_POSITIVES]
)
def test_scoped_rule_fires(rule: str, path: str, make: Callable[[], str], tmp_path: Path) -> None:
    assert rules_hit_in(path, make(), tmp_path) == [rule]


@pytest.mark.parametrize(
    ("rule", "path", "make"),
    [p for p in SCOPED_POSITIVES if p[0] != "kubeconfig-client-key"],
    ids=[f"{r}:{p}" for r, p, _ in SCOPED_POSITIVES if r != "kubeconfig-client-key"],
)
def test_scoped_rule_quiet_in_other_files(
    rule: str, path: str, make: Callable[[], str], tmp_path: Path
) -> None:
    for other in ("README.md", "values.yaml", "src/kubeconfig.go", "npmrc.md", "config.json"):
        assert rule not in rules_hit_in(other, make(), tmp_path), other


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("kubeconfig", "    token: REDACTED\n"),  # kubectl config view
        ("kubeconfig", "    client-key-data: DATA+OMITTED\n"),
        ("kubeconfig", "    token: ${KUBE_TOKEN}\n"),
        ("kubeconfig", "    token-file: /var/run/secrets/token\n"),  # a path, not a token
        ("kubeconfig", "      command: kubelogin\n"),
        (".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"),
        (".npmrc", "@contoso:registry=https://npm.example.org/\n"),
        (".npmrc", "always-auth=true\n"),
        (".pypirc", "[pypi]\nusername = __token__\n"),
        (".pypirc", "password = <your token>\n"),
        (".docker/config.json", '{"credsStore": "desktop", "auths": {"r": {}}}'),
        (".docker/config.json", '{"auths": {"r": {"auth": ""}}}'),
    ],
)
def test_credential_file_look_alikes_stay_quiet(path: str, text: str, tmp_path: Path) -> None:
    assert rules_hit_in(path, text, tmp_path) == []


def test_provider_rule_wins_in_a_credential_file(tmp_path: Path) -> None:
    text = f"//registry.npmjs.org/:_authToken={fakes.npm_token()}\n"
    assert rules_hit_in(".npmrc", text, tmp_path) == ["npm-token"]


def test_credential_file_rule_wins_over_generic(tmp_path: Path) -> None:
    text = f'    password: "{fakes.generic_value()}"\n'
    assert rules_hit_in("f.yaml", text, tmp_path) == ["generic-assigned-secret"]
    assert rules_hit_in("kubeconfig", text, tmp_path) == ["kubeconfig-token"]


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
        # GitHub-token shape whose checksum doesn't hold: not issued by GitHub.
        f"token: {fakes.github_token(valid_checksum=False)}",
    ],
)
def test_look_alikes_stay_quiet(text: str, tmp_path: Path) -> None:
    assert rules_hit(text, tmp_path) == []


def test_specific_rule_wins_over_generic(tmp_path: Path) -> None:
    hits = rules_hit(f'access_token = "{fakes.github_token()}"', tmp_path)
    assert hits == ["github-token"]


def test_github_checksum() -> None:
    assert github_checksum_ok(fakes.github_token())
    assert not github_checksum_ok(fakes.github_token(valid_checksum=False))
    # Every random part, including ones whose checksum has leading zeros.
    for seed in range(200):
        random_part = fakes.chars(fakes.ALNUM, 30, seed=seed)
        assert github_checksum_ok("gh" + "o_" + random_part + fakes.github_checksum(random_part))
    assert github_checksum_ok(fakes.github_fine_grained())  # layout undocumented: unchecked


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
        (".git-credentials", "credential-store-file"),
        ("home/.netrc", "credential-store-file"),
        ("_netrc", "credential-store-file"),
    ],
)
def test_path_rules_fire(name: str, rule: str, tmp_path: Path) -> None:
    from secret_scan.scanner import scan_path_rules

    settings = load_settings(tmp_path, use_user_file=False, environ={})
    assert [f.rule for f in scan_path_rules(name, settings)] == [rule]


@pytest.mark.parametrize(
    "name",
    [
        ".env.example",
        ".env.sample",
        ".envrc",
        "id_rsa.pub",
        "main.tf",
        "variables.tfvars",
        "netrc.py",
        ".git-credentials.example",
        ".gitconfig",
    ],
)
def test_path_rules_quiet(name: str, tmp_path: Path) -> None:
    from secret_scan.scanner import scan_path_rules

    settings = load_settings(tmp_path, use_user_file=False, environ={})
    assert scan_path_rules(name, settings) == []
