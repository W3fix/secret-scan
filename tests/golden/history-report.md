# Secret scan report: `repo`

**8 findings in history, 1 still in HEAD.** Values are withheld: this report shows where each finding is and which rule
it matched, never the matched text.

## Scan

- **Scope:** every commit on every branch, tag and remote-tracking branch (3 commits)
- **Commit:** `<commit-3>` (HEAD)
- **Scanned:** 2026-01-01 00:00 UTC
- **Tool:** secret-scan <version>, rule set `sha256:<rule-set>`
- **Rules:** 27 of 27 built-in
- **Coverage:** 5 changes scanned

## Findings by rule

| Rule | Findings | Still in HEAD |
|---|---:|---:|
| `slack-token` | 1 | 1 |
| `anthropic-api-key` | 1 | 0 |
| `aws-access-key-id` | 1 | 0 |
| `azure-entra-client-secret` | 1 | 0 |
| `azure-storage-account-key` | 1 | 0 |
| `connection-string-password` | 1 | 0 |
| `dotenv-file` | 1 | 0 |
| `github-token` | 1 | 0 |

## Findings

### `slack-token`

**Why it matters.** A Slack token grants workspace access as a bot or user.

**What to do.** Revoke it (Slack's auth.revoke method, or the app's OAuth settings) and keep the replacement in a secret store.

| Added at | Commit | Date | Still in HEAD | Match |
|---|---|---|---|---|
| `deploy.sh:1:15` | `<commit-3>` | 2026-03-01 | yes | 42 chars |

### `anthropic-api-key`

**Why it matters.** An Anthropic API key is billed to its organization and can read its workspace data.

**What to do.** Delete the key in the Anthropic console, check the workspace's usage for activity you don't expect, and issue a replacement held in a secret store.

| Added at | Commit | Date | Still in HEAD | Match |
|---|---|---|---|---|
| `settings.py:6:11` | `<commit-1>` | 2026-03-01 | no | 106 chars |

### `aws-access-key-id`

**Why it matters.** An AWS access key ID is half of a usable credential and names the account it belongs to.

**What to do.** Deactivate, then delete, the access key in IAM and check CloudTrail for its use. Prefer short-lived credentials: IAM roles, or OIDC federation from CI.

| Added at | Commit | Date | Still in HEAD | Match |
|---|---|---|---|---|
| `settings.py:2:8` | `<commit-1>` | 2026-03-01 | no | 20 chars |

### `azure-entra-client-secret`

**Why it matters.** An Entra ID client secret lets anyone authenticate as the application.

**What to do.** Delete the secret from the app registration, check the service principal's sign-in logs, and move to a managed identity or workload identity federation where possible.

| Added at | Commit | Date | Still in HEAD | Match |
|---|---|---|---|---|
| `settings.py:4:10` | `<commit-1>` | 2026-03-01 | no | 40 chars |

### `azure-storage-account-key`

**Why it matters.** A storage account shared key grants full control of the account and can't be scoped.

**What to do.** Regenerate the key on the storage account (the two keys can be rotated one at a time without downtime) and update its consumers. Prefer Microsoft Entra ID authorization, and disable shared key access where nothing needs it.

| Added at | Commit | Date | Still in HEAD | Match |
|---|---|---|---|---|
| `settings.py:3:37` | `<commit-1>` | 2026-03-01 | no | 88 chars |

### `connection-string-password`

**Why it matters.** A password inside a connection string is a live database credential.

**What to do.** Change the password on the database, then load the connection string from configuration (a Key Vault reference, an environment variable) or use managed identity authentication.

| Added at | Commit | Date | Still in HEAD | Match |
|---|---|---|---|---|
| `settings.py:5:38` | `<commit-1>` | 2026-03-01 | no | 15 chars |

### `dotenv-file`

**Why it matters.** Dotenv files hold real environment secrets. Commit a .env.example with placeholders instead.

**What to do.** Stop tracking it (git rm --cached), add it to .gitignore, rotate every secret it held, and commit a .env.example with placeholders instead.

| Added at | Commit | Date | Still in HEAD | Match |
|---|---|---|---|---|
| `.env` | `<commit-1>` | 2026-03-01 | no | file name |

### `github-token`

**Why it matters.** A GitHub token can read or write repositories and act as its owner.

**What to do.** Revoke the token (the owner's developer settings, or the organization's token settings), review the audit log for its use, and replace it with a GitHub App or the workflow's GITHUB_TOKEN where possible.

| Added at | Commit | Date | Still in HEAD | Match |
|---|---|---|---|---|
| `settings.py:1:11` | `<commit-1>` | 2026-03-01 | no | 40 chars |

## Exceptions register

Every exception in effect for this scan, with the reason given for it.

| Kind | Declared in | Applies to | Reason | Skipped |
|---|---|---|---|---:|
| inline | `test_api.py:1` in `<commit-3>` | rule `stripe-live-key` on that line | test mode | 1 match |

## Method and limits

- **Values are withheld.** This report gives the location, rule and length of each
  match, never the matched text, so it can be shared without spreading what it describes.
- **Offline.** The scan made no network calls, so no credential was tested. Treat every
  finding as live until it has been rotated.
- **Every commit, each secret once.** Each commit was scanned for the lines it added (a
  change is one file in one commit), and each secret is listed at the commit that first
  added it. Still in HEAD means a rule matches the same value in the files of the commit
  named above. A secret that isn't is still in history and in every clone, so rotating it
  is the fix either way; rewriting history doesn't replace that. Exceptions are the
  current configuration's, and inline markers count where they were present.
- **Patterns, not proof.** Rules match credentials in their usual forms. Encoded or
  deliberately split values aren't detected, and a finding can be test data: the
  exceptions register shows what was excused, and why.

---

Generated by [secret-scan](https://github.com/W3fix/secret-scan) <version>.
