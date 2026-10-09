"""Secret-shaped test values, built at runtime.

Never write a realistic credential as a literal in this repository: it would
fail this tool's own scan and trip every other scanner that looks at it. Each
value here is assembled from a fixed prefix and seeded random characters, so
it's stable across runs and contains no placeholder words.
"""

from __future__ import annotations

import random
import string

ALNUM = string.ascii_letters + string.digits
UPPER_ALNUM = string.ascii_uppercase + string.digits
B64 = ALNUM + "+/"


def chars(alphabet: str, n: int, seed: int = 7) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(n))


def aws_key_id() -> str:
    return "AK" + "IA" + chars(UPPER_ALNUM, 16)


def aws_secret() -> str:
    return chars(B64, 40, seed=11)


def storage_key() -> str:
    return chars(B64, 86, seed=13) + "=="


def sas_sig() -> str:
    return chars(ALNUM, 43, seed=17) + "%3D"


def entra_secret() -> str:
    return chars(ALNUM, 3, seed=19) + "8" + "Q~" + chars(ALNUM + "_~.-", 34, seed=23)


def github_token() -> str:
    return "gh" + "p_" + chars(ALNUM, 36, seed=29)


def github_fine_grained() -> str:
    return "github" + "_pat_" + chars(ALNUM + "_", 82, seed=31)


def gitlab_token() -> str:
    return "gl" + "pat-" + chars(ALNUM, 20, seed=37)


def slack_token() -> str:
    return "xo" + "xb-" + chars("0123456789", 12, seed=41) + "-" + chars(ALNUM, 24, seed=43)


def slack_webhook() -> str:
    return (
        "https://hooks.slack.com/services/T"
        + chars(UPPER_ALNUM, 8, 47)
        + "/B"
        + chars(UPPER_ALNUM, 8, 53)
        + "/"
        + chars(ALNUM, 24, 59)
    )


def stripe_live() -> str:
    return "sk" + "_live_" + chars(ALNUM, 24, seed=61)


def google_api_key() -> str:
    return "AI" + "za" + chars(ALNUM + "_-", 35, seed=67)


def npm_token() -> str:
    return "np" + "m_" + chars(ALNUM, 36, seed=71)


def anthropic_key() -> str:
    return "sk-" + "ant-api03-" + chars(ALNUM + "_-", 93, seed=73)


def openai_key() -> str:
    return "sk-" + "proj-" + chars(ALNUM + "_-", 48, seed=79)


def private_key_header(kind: str = "RSA ") -> str:
    return "-----BEGIN " + kind + "PRIVATE KEY" + ("" if kind != "PGP " else " BLOCK") + "-----"


def private_key_body() -> str:
    """One line of PEM body: 64 base64 characters."""
    return chars(B64, 64, seed=97)


def generic_value() -> str:
    return chars(ALNUM, 32, seed=83)


def password() -> str:
    return "Tr0ub4dor" + chars(ALNUM, 6, seed=89)
