"""Detection rules.

Every rule carries a ``why``. If the reason a pattern matters can't be written
down, the rule is probably noise, and noisy rules get ignored the first time
they fire. Built-in rules also carry a ``fix``: what to do once a match has
been committed, for audit reports.

Patterns mark the sensitive part of a match with a named group ``secret``.
Only that span is measured, compared against allow-listed values, or checked
for placeholders. The text itself is never reported.
"""

from __future__ import annotations

import math
import re
import string
import zlib
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """A pattern matched against file content."""

    id: str
    why: str
    pattern: re.Pattern[str]
    #: What to do about a committed match, for audit reports. Custom rules may
    #: leave it empty.
    fix: str = ""
    #: Broad heuristic. Dropped when a specific rule matches the same span.
    generic: bool = False
    #: Skip matches that look like documentation placeholders.
    check_placeholder: bool = True
    #: Minimum Shannon entropy (bits per character) of the secret span.
    min_entropy: float = 0.0
    #: When set, the line containing the match must also match this.
    line_requires: re.Pattern[str] | None = None
    #: When set, the secret span must pass this structural check, such as a checksum.
    well_formed: Callable[[str], bool] | None = None
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
    fix: str = ""
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
    fix: str,
    pattern: str,
    *,
    generic: bool = False,
    check_placeholder: bool = True,
    min_entropy: float = 0.0,
    line_requires: re.Pattern[str] | None = None,
    well_formed: Callable[[str], bool] | None = None,
) -> Rule:
    return Rule(
        rule_id,
        why,
        re.compile(pattern),
        fix=fix,
        generic=generic,
        check_placeholder=check_placeholder,
        min_entropy=min_entropy,
        line_requires=line_requires,
        well_formed=well_formed,
    )


_BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase


def _base62(n: int, width: int) -> str:
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = _BASE62[r] + out
    return out.rjust(width, _BASE62[0])


def github_checksum_ok(token: str) -> bool:
    """Whether a classic-format GitHub token's built-in checksum holds.

    These tokens are a prefix, 30 random characters and a 6-character base62
    CRC32 of the random part. A random string of the same shape fails it, so
    test data and minified code stop matching. Layouts GitHub doesn't document
    (longer tokens, ``github_pat_``) pass unchecked rather than risk a miss.
    """
    prefix, _, body = token.partition("_")
    if prefix not in {"ghp", "gho", "ghu", "ghs", "ghr"} or len(body) != 36:
        return True
    return _base62(zlib.crc32(body[:30].encode()), 6) == body[30:]


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
        "Treat the key as compromised: generate a new pair, install the new public key or "
        "certificate wherever the old one is trusted, then remove the old one. Keep private "
        "keys in a secret manager or key vault.",
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
        "Deactivate, then delete, the access key in IAM and check CloudTrail for its use. "
        "Prefer short-lived credentials: IAM roles, or OIDC federation from CI.",
        # Bounded by anything but base64, so a matching run inside an encoded blob
        # (inlined WASM, images) doesn't count. A trailing / is allowed: SigV4
        # credential scopes put one right after the key ID.
        r"(?<![A-Za-z0-9+/])(?P<secret>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})(?![A-Za-z0-9+])",
    ),
    _rule(
        "aws-secret-access-key",
        "An AWS secret access key grants everything its user or role can do.",
        "Deactivate, then delete, the access key in IAM and check CloudTrail for its use. "
        "Prefer short-lived credentials: IAM roles, or OIDC federation from CI.",
        r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?"
        r"(?P<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])",
    ),
    _rule(
        "azure-storage-account-key",
        "A storage account shared key grants full control of the account and can't be scoped.",
        "Regenerate the key on the storage account (the two keys can be rotated one at a time "
        "without downtime) and update its consumers. Prefer Microsoft Entra ID authorization, "
        "and disable shared key access where nothing needs it.",
        r"(?i)AccountKey=(?P<secret>[A-Za-z0-9+/]{86}==)",
    ),
    _rule(
        "azure-sas-token",
        "A SAS token is a bearer credential. Anyone holding the URL has its access "
        "until it expires.",
        "Revoke it: delete or change the stored access policy it uses, or rotate the account "
        "key that signed it. Prefer short-lived user delegation SAS issued at run time.",
        r"[?&]sig=(?P<secret>[A-Za-z0-9%+/=]{30,})",
    ),
    _rule(
        "azure-entra-client-secret",
        "An Entra ID client secret lets anyone authenticate as the application.",
        "Delete the secret from the app registration, check the service principal's sign-in "
        "logs, and move to a managed identity or workload identity federation where possible.",
        r"(?<![A-Za-z0-9_~.-])(?P<secret>[A-Za-z0-9_~.-]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34})"
        r"(?![A-Za-z0-9_~.-])",
    ),
    _rule(
        "connection-string-password",
        "A password inside a connection string is a live database credential.",
        "Change the password on the database, then load the connection string from "
        "configuration (a Key Vault reference, an environment variable) or use managed "
        "identity authentication.",
        r"(?i)(?<![A-Za-z0-9_])(?:password|pwd)\s*=\s*(?P<secret>[^;'\"\s]{8,})",
        # Only in `key=value;` connection strings, not `f(password=var)` calls.
        line_requires=re.compile(
            r"(?i)(?:server|data source|host|user id|uid|initial catalog|database)\s*=[^;]*;"
        ),
    ),
    _rule(
        "url-embedded-credentials",
        "Credentials inside a URL leak into logs, shell history and error messages.",
        "Change the password, and pass credentials separately from the URL: an environment "
        "variable, a secret store or a credential helper.",
        # Three characters is enough for short defaults such as admin:admin, the
        # credentials most worth catching; shorter ones are syntax examples (a:b).
        r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'\"]{1,64}:(?P<secret>[^\s:/@'\"]{3,128})"
        rf"@(?!{_DOC_HOST})[A-Za-z0-9.-]+",
    ),
    _rule(
        "github-token",
        "A GitHub token can read or write repositories and act as its owner.",
        "Revoke the token (the owner's developer settings, or the organization's token "
        "settings), review the audit log for its use, and replace it with a GitHub App or the "
        "workflow's GITHUB_TOKEN where possible.",
        r"(?<![A-Za-z0-9_])(?P<secret>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,251}"
        r"|github_pat_[A-Za-z0-9_]{60,251})(?![A-Za-z0-9_])",
        well_formed=github_checksum_ok,
    ),
    _rule(
        "gitlab-token",
        "A GitLab personal access token acts as its owner across the instance.",
        "Revoke it in the owner's access token settings, review the audit events, and replace "
        "it with a project or group token that has an expiry date.",
        r"(?<![A-Za-z0-9_-])(?P<secret>glpat-[A-Za-z0-9_-]{20,})",
    ),
    _rule(
        "slack-token",
        "A Slack token grants workspace access as a bot or user.",
        "Revoke it (Slack's auth.revoke method, or the app's OAuth settings) and keep the "
        "replacement in a secret store.",
        r"(?<![A-Za-z0-9_-])(?P<secret>xox[abposr]-[A-Za-z0-9-]{10,})",
    ),
    _rule(
        "slack-webhook",
        "A Slack webhook URL lets anyone post into the channel as the integration.",
        "Remove the webhook in the Slack app's Incoming Webhooks settings, create a new one, "
        "and keep it in a secret store.",
        r"(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})",
    ),
    _rule(
        "stripe-live-key",
        "A live Stripe secret or restricted key can move real money.",
        "Roll the key in the Stripe Dashboard, review the API request logs for its use, and "
        "prefer restricted keys with only the permissions needed.",
        r"(?<![A-Za-z0-9_])(?P<secret>(?:sk|rk)_live_[A-Za-z0-9]{20,})",
    ),
    _rule(
        "google-api-key",
        "A Google API key is billed to its project and often has no usage restrictions.",
        "Delete or regenerate the key on the Google Cloud console's Credentials page, and "
        "restrict its replacement to the APIs and applications that need it.",
        r"(?<![A-Za-z0-9_-])(?P<secret>AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])",
    ),
    _rule(
        "npm-token",
        "An npm token can publish packages as its owner: a direct supply-chain risk.",
        "Revoke it (npm token revoke, or the Access Tokens page), check recent versions of "
        "the owner's packages, and publish from CI with trusted publishing or a granular "
        "token.",
        r"(?<![A-Za-z0-9_])(?P<secret>npm_[A-Za-z0-9]{36})(?![A-Za-z0-9_])",
    ),
    _rule(
        "anthropic-api-key",
        "An Anthropic API key is billed to its organization and can read its workspace data.",
        "Delete the key in the Anthropic console, check the workspace's usage for activity "
        "you don't expect, and issue a replacement held in a secret store.",
        r"(?<![A-Za-z0-9_-])(?P<secret>sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,})",
    ),
    _rule(
        "openai-api-key",
        "An OpenAI API key is billed to its organization and can read its project data.",
        "Delete the key on the OpenAI platform's API keys page, check usage for activity you "
        "don't expect, and issue a replacement held in a secret store.",
        r"(?<![A-Za-z0-9_-])(?P<secret>sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}"
        r"|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})",
    ),
    _rule(
        "generic-assigned-secret",
        "A secret assigned inline as a literal is almost always a real one pasted in.",
        "If it's a real credential, rotate it where it was issued and load it from the "
        "environment or a secret store. If it's test or example data, add an allow entry with "
        "the reason.",
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
        fix="Stop tracking it (git rm --cached), add it to .gitignore, rotate every secret it "
        "held, and commit a .env.example with placeholders instead.",
    ),
    PathRule(
        "terraform-state",
        "Terraform state stores resource attributes in plain text, including generated "
        "passwords and keys. Use a remote backend.",
        re.compile(r"[^/]*\.tfstate(?:\.[0-9]+)?(?:\.backup)?\Z"),
        fix="Stop tracking it, rotate the secrets it contains, and move state to a remote "
        "backend with encryption and restricted access.",
    ),
    PathRule(
        "key-material-file",
        "Key stores, certificate bundles and SSH identity files usually contain private keys.",
        re.compile(r"(?:id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:pfx|p12|jks|keystore|kdbx))\Z"),
        fix="Stop tracking it, replace the keys it holds, and keep key stores in a secret "
        "manager or key vault.",
    ),
)


def builtin_rule_ids() -> set[str]:
    return {r.id for r in CONTENT_RULES} | {r.id for r in PATH_RULES}
