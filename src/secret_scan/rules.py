"""Detection rules.

Every rule carries a ``why``. If the reason a pattern matters can't be written
down, the rule is probably noise, and noisy rules get ignored the first time
they fire.

Patterns mark the sensitive part of a match with a named group ``secret``.
Only that span is measured, compared against allow-listed values, or checked
for placeholders. The text itself is never reported.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """A pattern matched against file content."""

    id: str
    why: str
    pattern: re.Pattern[str]
    #: Broad heuristic. Dropped when a specific rule matches the same span.
    generic: bool = False
    #: Skip matches that look like documentation placeholders.
    check_placeholder: bool = True
    #: Minimum Shannon entropy (bits per character) of the secret span.
    min_entropy: float = 0.0
    #: When set, the line containing the match must also match this.
    line_requires: re.Pattern[str] | None = None
    #: ``builtin``, ``config`` (repository config) or ``private`` (personal terms).
    origin: str = "builtin"

    def secret_span(self, match: re.Match[str]) -> tuple[int, int]:
        if "secret" in match.re.groupindex and match.group("secret") is not None:
            return match.span("secret")
        return match.span()


@dataclass(frozen=True)
class PathRule:
    """A pattern matched against a file's name, whatever its content.

    These catch files that are sensitive by nature and often binary, so
    content rules can't see inside them.
    """

    id: str
    why: str
    pattern: re.Pattern[str]
    origin: str = "builtin"


# Values that are obviously stand-ins: documentation, templates, interpolation.
_PLACEHOLDER = re.compile(
    r"example|sample|placeholder|dummy|your[_-]?|change[_-]?me|redacted|replace[_-]?me"
    r"|x{4,}|\*{3,}|\.\.\.|[<>]|\$\{|\$\(|\{\{|%\("
    # The whole value is an interpolation: f"{expr}", "{0}", $VAR, %s.
    r"|\A(?:\{[^{}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[sd])\Z"
    # The whole value is the word for what belongs there: user:password@host.
    r"|\A(?:pass(?:word)?|pwd|secret|token)\Z",
    re.IGNORECASE,
)


def looks_like_placeholder(value: str) -> bool:
    return _PLACEHOLDER.search(value) is not None


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _rule(
    rule_id: str,
    why: str,
    pattern: str,
    *,
    generic: bool = False,
    check_placeholder: bool = True,
    min_entropy: float = 0.0,
    line_requires: re.Pattern[str] | None = None,
) -> Rule:
    return Rule(
        rule_id,
        why,
        re.compile(pattern),
        generic=generic,
        check_placeholder=check_placeholder,
        min_entropy=min_entropy,
        line_requires=line_requires,
    )


# Hosts reserved for documentation (RFC 2606): example.com/.net/.org and the
# .example and .invalid TLDs. Credentials pointing there are illustrations.
# .test and .localhost are left out: those name real development hosts.
_DOC_HOST = (
    r"(?:[a-z0-9-]+\.)*(?:example\.(?:com|net|org)|[a-z0-9-]+\.(?:example|invalid))"
    r"(?![a-z0-9-]|\.[a-z0-9])"
)


CONTENT_RULES: tuple[Rule, ...] = (
    _rule(
        "private-key",
        "Private key material must never be in source control. Deleting it later "
        "doesn't remove it from history.",
        r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?"
        r"PRIVATE KEY(?: BLOCK)?-----)"
        # Only when key material follows: a header alone is documentation or a
        # truncated example. Newlines may be real or escaped (JSON, .env), and PEM
        # and PGP headers such as Proc-Type: or Version: may come first. Each
        # header runs to the end of its line, so a line splits into headers only
        # one way; letting a header end at any space backtracks exponentially.
        r"(?=(?:\s|\\[rn])+(?:[A-Za-z-]+:[^\n\\]*(?:\n|\\n)(?:\s|\\[rn])*)*[A-Za-z0-9+/]{40})",
        check_placeholder=False,
    ),
    _rule(
        "aws-access-key-id",
        "An AWS access key ID is half of a usable credential and names the account it belongs to.",
        # Bounded by anything but base64, so a matching run inside an encoded blob
        # (inlined WASM, images) doesn't count. A trailing / is allowed: SigV4
        # credential scopes put one right after the key ID.
        r"(?<![A-Za-z0-9+/])(?P<secret>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})(?![A-Za-z0-9+])",
    ),
    _rule(
        "aws-secret-access-key",
        "An AWS secret access key grants everything its user or role can do.",
        r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?"
        r"(?P<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])",
    ),
    _rule(
        "azure-storage-account-key",
        "A storage account shared key grants full control of the account and can't be scoped.",
        r"(?i)AccountKey=(?P<secret>[A-Za-z0-9+/]{86}==)",
    ),
    _rule(
        "azure-sas-token",
        "A SAS token is a bearer credential. Anyone holding the URL has its access "
        "until it expires.",
        r"[?&]sig=(?P<secret>[A-Za-z0-9%+/=]{30,})",
    ),
    _rule(
        "azure-entra-client-secret",
        "An Entra ID client secret lets anyone authenticate as the application.",
        r"(?<![A-Za-z0-9_~.-])(?P<secret>[A-Za-z0-9_~.-]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34})"
        r"(?![A-Za-z0-9_~.-])",
    ),
    _rule(
        "connection-string-password",
        "A password inside a connection string is a live database credential.",
        r"(?i)(?<![A-Za-z0-9_])(?:password|pwd)\s*=\s*(?P<secret>[^;'\"\s]{8,})",
        # Only in `key=value;` connection strings, not `f(password=var)` calls.
        line_requires=re.compile(
            r"(?i)(?:server|data source|host|user id|uid|initial catalog|database)\s*=[^;]*;"
        ),
    ),
    _rule(
        "url-embedded-credentials",
        "Credentials inside a URL leak into logs, shell history and error messages.",
        # Three characters is enough for short defaults such as admin:admin, the
        # credentials most worth catching; shorter ones are syntax examples (a:b).
        r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'\"]{1,64}:(?P<secret>[^\s:/@'\"]{3,128})"
        rf"@(?!{_DOC_HOST})[A-Za-z0-9.-]+",
    ),
    _rule(
        "github-token",
        "A GitHub token can read or write repositories and act as its owner.",
        r"(?<![A-Za-z0-9_])(?P<secret>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,251}"
        r"|github_pat_[A-Za-z0-9_]{60,251})(?![A-Za-z0-9_])",
    ),
    _rule(
        "gitlab-token",
        "A GitLab personal access token acts as its owner across the instance.",
        r"(?<![A-Za-z0-9_-])(?P<secret>glpat-[A-Za-z0-9_-]{20,})",
    ),
    _rule(
        "slack-token",
        "A Slack token grants workspace access as a bot or user.",
        r"(?<![A-Za-z0-9_-])(?P<secret>xox[abposr]-[A-Za-z0-9-]{10,})",
    ),
    _rule(
        "slack-webhook",
        "A Slack webhook URL lets anyone post into the channel as the integration.",
        r"(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})",
    ),
    _rule(
        "stripe-live-key",
        "A live Stripe secret or restricted key can move real money.",
        r"(?<![A-Za-z0-9_])(?P<secret>(?:sk|rk)_live_[A-Za-z0-9]{20,})",
    ),
    _rule(
        "google-api-key",
        "A Google API key is billed to its project and often has no usage restrictions.",
        r"(?<![A-Za-z0-9_-])(?P<secret>AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])",
    ),
    _rule(
        "npm-token",
        "An npm token can publish packages as its owner: a direct supply-chain risk.",
        r"(?<![A-Za-z0-9_])(?P<secret>npm_[A-Za-z0-9]{36})(?![A-Za-z0-9_])",
    ),
    _rule(
        "anthropic-api-key",
        "An Anthropic API key is billed to its organization and can read its workspace data.",
        r"(?<![A-Za-z0-9_-])(?P<secret>sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,})",
    ),
    _rule(
        "openai-api-key",
        "An OpenAI API key is billed to its organization and can read its project data.",
        r"(?<![A-Za-z0-9_-])(?P<secret>sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}"
        r"|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})",
    ),
    _rule(
        "generic-assigned-secret",
        "A secret assigned inline as a literal is almost always a real one pasted in.",
        r"(?i)(?<![A-Za-z0-9])(?:api[_-]?key|secret|password|passwd|client[_-]?secret"
        r"|access[_-]?token|auth[_-]?token)['\"]?\s*[:=]\s*['\"]"
        r"(?P<secret>[A-Za-z0-9+/_.~=-]{16,})['\"]",
        generic=True,
        min_entropy=3.0,
    ),
)


PATH_RULES: tuple[PathRule, ...] = (
    PathRule(
        "dotenv-file",
        "Dotenv files hold real environment secrets. Commit a .env.example with "
        "placeholders instead.",
        re.compile(r"\.env(?:\.(?!(?:example|sample|template|dist|defaults)\Z)[^/]+)?\Z"),
    ),
    PathRule(
        "terraform-state",
        "Terraform state stores resource attributes in plain text, including generated "
        "passwords and keys. Use a remote backend.",
        re.compile(r"[^/]*\.tfstate(?:\.[0-9]+)?(?:\.backup)?\Z"),
    ),
    PathRule(
        "key-material-file",
        "Key stores, certificate bundles and SSH identity files usually contain private keys.",
        re.compile(r"(?:id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:pfx|p12|jks|keystore|kdbx))\Z"),
    ),
)


def builtin_rule_ids() -> set[str]:
    return {r.id for r in CONTENT_RULES} | {r.id for r in PATH_RULES}
