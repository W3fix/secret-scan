# Secret scan report: `repo`

**7 findings in 2 files.** Values are withheld: this report shows where each finding is and which rule
it matched, never the matched text.

## Scan

- **Scope:** every file tracked by git
- **Commit:** `<commit>`, plus uncommitted changes in the working tree
- **Scanned:** 2026-01-01 00:00 UTC
- **Tool:** secret-scan <version>, rule set `sha256:<rule-set>`
- **Rules:** 26 of 27 built-in, private terms from 1 source (not listed)
- **Coverage:** 6 files scanned; 1 file over 4,096 bytes checked by name only; 2 files excluded by `ignore` entries

## Findings by rule

| Rule | Findings | Files |
|---|---:|---:|
| `anthropic-api-key` | 1 | 1 |
| `aws-access-key-id` | 1 | 1 |
| `azure-entra-client-secret` | 1 | 1 |
| `azure-storage-account-key` | 1 | 1 |
| `connection-string-password` | 1 | 1 |
| `github-token` | 1 | 1 |
| `private-term` | 1 | 1 |

## Findings

### `anthropic-api-key`

**Why it matters.** An Anthropic API key is billed to its organization and can read its workspace data.

**What to do.** Delete the key in the Anthropic console, check the workspace's usage for activity you don't expect, and issue a replacement held in a secret store.

| Location | Match |
|---|---|
| `settings.py:6:11` | 106 chars |

### `aws-access-key-id`

**Why it matters.** An AWS access key ID is half of a usable credential and names the account it belongs to.

**What to do.** Deactivate, then delete, the access key in IAM and check CloudTrail for its use. Prefer short-lived credentials: IAM roles, or OIDC federation from CI.

| Location | Match |
|---|---|
| `settings.py:2:8` | 20 chars |

### `azure-entra-client-secret`

**Why it matters.** An Entra ID client secret lets anyone authenticate as the application.

**What to do.** Delete the secret from the app registration, check the service principal's sign-in logs, and move to a managed identity or workload identity federation where possible.

| Location | Match |
|---|---|
| `settings.py:4:10` | 40 chars |

### `azure-storage-account-key`

**Why it matters.** A storage account shared key grants full control of the account and can't be scoped.

**What to do.** Regenerate the key on the storage account (the two keys can be rotated one at a time without downtime) and update its consumers. Prefer Microsoft Entra ID authorization, and disable shared key access where nothing needs it.

| Location | Match |
|---|---|
| `settings.py:3:37` | 88 chars |

### `connection-string-password`

**Why it matters.** A password inside a connection string is a live database credential.

**What to do.** Change the password on the database, then load the connection string from configuration (a Key Vault reference, an environment variable) or use managed identity authentication.

| Location | Match |
|---|---|
| `settings.py:5:38` | 15 chars |

### `github-token`

**Why it matters.** A GitHub token can read or write repositories and act as its owner.

**What to do.** Revoke the token (the owner's developer settings, or the organization's token settings), review the audit log for its use, and replace it with a GitHub App or the workflow's GITHUB_TOKEN where possible.

| Location | Match |
|---|---|
| `settings.py:1:11` | 40 chars |

### `private-term`

**Why it matters.** Matches an entry in your private terms list.

**What to do.** Remove the personal or client detail, or replace it with a generic name.

| Location | Match |
|---|---|
| `.secret-scan.json:5:18` | 17 chars |

## Exceptions register

Every exception in effect for this scan, with the reason given for it.

| Kind | Declared in | Applies to | Reason | Skipped |
|---|---|---|---|---:|
| disable | `.secret-scan.json: disable[0]` | rule `url-embedded-credentials`, everywhere | (reason withheld: it contains text a rule matches) | n/a |
| ignore | `.secret-scan.json: ignore[0]` | paths matching `vendor/` | third-party code | 2 files |
| allow | `.secret-scan.json: allow[0]` | rule `github-token` in `docs/**` | revoked examples | 2 matches |
| allow | `.secret-scan.json: allow[1]` | one exact value (withheld) | unit-test key | 1 match |
| allow | `.secret-scan.json: allow[2]` | rule `dotenv-file` in `examples/.env` | names only, no values | 1 match |
| inline | `src/app.py:1` | rule `aws-access-key-id` on that line | documented format, test only | 1 match |
| inline | `src/app.py:2` | rule `github-token` on that line | fixture | 1 match |
| inline | `src/app.py:3` | rule `stripe-live-key` on that line | (reason withheld: it contains text a rule matches) | 1 match |
| inline | `src/app.py:4` | rule `private-term` on that line | (reason withheld: it contains text a rule matches) | 1 match |
| inline | `src/app.py:5` | rule `slack-token` on that line | (reason withheld: it contains text a rule matches) | 1 match |

## Checked by name only

Larger than 4,096 bytes, so content rules didn't run:

- `assets/big.txt`

## Method and limits

- **Values are withheld.** This report gives the location, rule and length of each
  match, never the matched text, so it can be shared without spreading what it describes.
- **Offline.** The scan made no network calls, so no credential was tested. Treat every
  finding as live until it has been rotated.
- **Current files, not history.** A secret removed from the files can still be in git
  history and in every clone. Rotating it is the fix; rewriting history doesn't
  replace that.
- **Patterns, not proof.** Rules match credentials in their usual forms. Encoded or
  deliberately split values aren't detected, and a finding can be test data: the
  exceptions register shows what was excused, and why.

---

Generated by [secret-scan](https://github.com/W3fix/secret-scan) <version>.
