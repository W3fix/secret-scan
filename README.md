# secret-scan

Find credentials and personal data before they're committed. **It reports
where, never what:** output gives the file, line, rule and length, and the
matched value never appears in your terminal, CI logs or code-scanning alerts.

```text
$ secret-scan
README.md:1:19  private-term  (21 chars)
    Matches an entry in your private terms list.
app/settings.py:4:17  github-token  (40 chars)
    A GitHub token can read or write repositories and act as its owner.
app/settings.py:5:78  connection-string-password  (15 chars)
    A password inside a connection string is a live database credential.
infra/terraform.tfstate  terraform-state  (file name)
    Terraform state stores resource attributes in plain text, including generated passwords and keys. Use a remote backend.

✗ 4 findings in 3 files (3 files scanned). Values withheld.
```

Runs as a CLI, a git pre-commit hook, or a GitHub Action. Pure Python standard
library: **no runtime dependencies.**

## Why

Most leaks aren't sophisticated. Someone pastes a token while debugging, commits
a `.env`, or checks in Terraform state. Once a secret is pushed, deleting it
doesn't help: it's in history, forks and clones, and it has to be rotated.

Two things existing scanners typically don't cover:

- **Their output is a second leak.** A scanner that prints the secret it found
  copies it into CI logs, which are retained and often more widely readable than
  the repository. secret-scan has no code path that can print a matched value.
- **Personal data, not just credentials.** Your phone number, a client's name,
  or your employer's name in a side project. These are specific to you, so they
  can't be built-in rules, and they can't go in a committed config file either.
  secret-scan reads them from a private file or a CI secret.

## Install

```bash
pipx install git+https://github.com/W3fix/secret-scan
```

Requires Python 3.10+.

## Usage

```bash
secret-scan                  # every file tracked by git (or the current directory, outside a repo)
secret-scan --staged         # staged content only: what the next commit will contain
secret-scan --since main     # files changed since a ref
secret-scan --history        # every commit on every branch and tag: what was ever committed
secret-scan path/ file.txt   # explicit files and directories
```

| Option | |
|---|---|
| `--format text\|json\|markdown` | stdout format (default `text`); `markdown` is the [audit report](#audit-report) |
| `--sarif FILE` | also write SARIF 2.1.0 for GitHub code scanning |
| `--config FILE` | repository config (default `.secret-scan.json`) |
| `--private FILE` | private terms (default `.secret-scan.local.json`) |
| `--no-user-config` | ignore `~/.config/secret-scan/private.json` |
| `--list-rules` | list active rules with their reasons |
| `--install-hook [--force]` | install a git pre-commit hook in this repository |
| `-q`, `--quiet` | print nothing when clean |

Exit status: `0` clean, `1` findings, `2` usage or configuration error.

### Pre-commit hook

```bash
secret-scan --install-hook
```

The hook scans what's **staged**, read from the git index rather than the files
on disk. That's what the commit will contain. If you stage a secret and then
delete it from the file without re-staging, the hook still catches it.

Using the [pre-commit](https://pre-commit.com) framework instead:

```yaml
repos:
  - repo: https://github.com/W3fix/secret-scan
    rev: <full commit SHA>  # v0.1.0
    hooks:
      - id: secret-scan
```

### GitHub Action

```yaml
permissions:
  contents: read

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha> # v7
        with:
          persist-credentials: false
      - uses: W3fix/secret-scan@<full commit SHA> # v0.1.0
        with:
          private-terms: ${{ secrets.SECRET_SCAN_PRIVATE_TERMS }}
```

Findings appear as annotations on the pull request diff. To scan only what a
pull request changed, pass `since: ${{ github.event.pull_request.base.sha }}`
and check out with `fetch-depth: 0`. To send findings to code scanning, add
`sarif: secret-scan.sarif` and upload it with `github/codeql-action/upload-sarif`
(that job needs `security-events: write`).

The action runs the code at the SHA you pin, directly from its checkout. It
doesn't run `pip install` or touch the network.

### Audit report

```bash
secret-scan --format markdown > secret-scan-report.md
```

A report to hand to a client or attach to an audit, readable as-is or rendered
on GitHub. It contains:

- **Scope:** what was scanned (tracked files, staged changes, a `--since` range
  or explicit paths), the commit, whether uncommitted changes were included, and
  when.
- **Tool and rule set:** the version and a fingerprint of the active rules, so two
  reports can show they used the same checks. Private terms are counted, never
  listed, and left out of the fingerprint.
- **Findings by rule,** each with why it matters and what to do about it.
- **The exceptions register:** every allow, ignore, disable and inline allow in
  effect, where it's declared, its reason and how much it skipped. Unused entries
  are marked.
- **Method and limits:** offline, current files only, values withheld.

Like every other format, it never contains a matched value, and the repository is
named by its directory, not its path on your machine. Set `SOURCE_DATE_EPOCH` to
pin the timestamp.

### Git history

```bash
secret-scan --history
```

Scans every commit on every branch, tag and remote-tracking branch, offline, and
reports each secret once: the commit that added it, when, where, and whether
`HEAD` still has it.

```text
$ secret-scan --history
config/settings.py:4:17  aws-access-key-id  (20 chars)
    An AWS access key ID is half of a usable credential and names the account it belongs to.
    Committed in 1f0e3a9c2b7d on 2026-03-02; no longer in HEAD, but still in history.
    What to do: Deactivate, then delete, the access key in IAM and check CloudTrail for its use. Prefer short-lived credentials: IAM roles, or OIDC federation from CI.

✗ 1 finding in history (214 commits scanned), 0 still in HEAD. Values withheld.
```

Deleting a committed secret doesn't revoke it: every clone still has it. That's
why history output says what to do about each finding. JSON adds `commit`, `date`
(the committer date, in UTC) and `inHead` to each finding, plus a `history` object
with the `HEAD` commit, the number of commits scanned and whether the clone is
shallow. In history mode, file counts in the summary count changes: one file in
one commit.

How it decides:

- **Once per secret.** A value is reported at the first commit that added it, even
  if later commits edit the line or copy it into other files. To recognise a value
  again without keeping it, each match gets a key: a hash under a random key that
  exists only for this run. Private keys are compared by their whole block, since
  every key of a type has the same header.
- **What each commit added.** Each change is read as a diff with three lines of
  context, so an inline allow on the line above still counts. A merge is scanned
  for what it added itself, such as a conflict resolution; what it brings in from a
  branch was scanned on that branch.
- **Today's config, that commit's markers.** `allow`, `ignore` and `disable` from
  the current `.secret-scan.json` apply to every commit. An inline allow counts in
  the commits where the marker was present.
- **In `HEAD`** means a rule matches the same value somewhere in `HEAD`'s committed
  files, even where an exception excuses it: an excused value is still exposed.
- **Repository settings can't hide content.** Every diff option that git config
  could change (prefixes, colour, context lines, text conversion) is pinned, and a
  file that `.gitattributes` marks as binary is read from the repository and
  checked like any other file.
- **Offline.** A partial clone (`git clone --filter`) is refused, because reading
  its history would download objects. A shallow clone is scanned, and the output
  says so: its oldest commit appears to add every file it has.

Authors and commit messages aren't read or reported. The commit id leads to both,
and names and email addresses are personal data the output doesn't need. History
mode doesn't produce SARIF, GitHub annotations or the markdown report yet: the
first two mark lines in the current files, and a secret in history may not be in them.

## Configuration

### Private terms: never committed

Names, phone numbers, addresses and client names to flag. Three sources, all
optional, all combined:

| Source | Scope |
|---|---|
| `~/.config/secret-scan/private.json` | every repository you scan |
| `.secret-scan.local.json` at the repository root (git-ignored) | this repository |
| `SECRET_SCAN_PRIVATE_TERMS` env var, one term per line | CI, from a secret |

```json
{
  "terms": ["Contoso Pharmaceuticals", "jane.doe@example.com"],
  "patterns": [
    { "id": "my-phone", "why": "Personal phone number.", "pattern": "\\(?555\\)?[ .-]?010[ .-]?4477" }
  ]
}
```

Terms match case-insensitively on word boundaries. Reports say `private-term`
and never which term matched. **If `.secret-scan.local.json` is ever tracked by
git, the scan stops with an error.** Its whole purpose has already failed, and
it says so loudly rather than scanning around it.

### Repository config: `.secret-scan.json`

Committed and shared. **Every exception needs a `reason`.** An exception
nobody can justify shouldn't exist, and the reason is what a reviewer reads.

```json
{
  "ignore": [
    { "path": "vendor/", "reason": "Third-party code, scanned upstream." }
  ],
  "allow": [
    { "rule": "github-token", "path": "docs/**", "reason": "Revoked tokens used in examples." },
    { "value": "unit-test-signing-key-0001", "reason": "Fixed key used only by unit tests." }
  ],
  "disable": [
    { "rule": "url-embedded-credentials", "reason": "Fixture URLs only; covered by review." }
  ],
  "rules": [
    {
      "id": "internal-hostname",
      "why": "Internal hostnames reveal network layout.",
      "fix": "Use the service's public name.",
      "pattern": "\\b[a-z0-9-]+\\.corp\\.contoso\\.com\\b",
      "ignoreCase": true
    }
  ],
  "maxFileBytes": 2097152
}
```

Unknown keys, unknown rule ids, missing reasons and invalid patterns are errors,
not silent no-ops, so a typo can't quietly switch off a check. A rule's optional
`fix` says what to do about a committed match. Every built-in rule has one, and it
appears in JSON (`fix`) and SARIF (`help`), not in the commit-time text output:
before a commit the secret hasn't left your machine, so there's nothing to revoke.

### Inline

```python
EXAMPLE = "..."  # secret-scan:allow revoked token, kept to test the parser
```

The marker goes on the same line, or alone on the line above for formats without
trailing comments. A marker without a reason doesn't suppress anything. The
finding is still reported, with a note asking for one.

### Exceptions register

JSON output lists every exception in effect under `exceptions`: each allow,
ignore and disable entry with where it's declared, its reason and how many
matches (or, for `ignore`, files) it skipped, and each inline allow that skipped
a match. An allow entry that pins a value shows `"value": "withheld"`. A reason
that contains text a rule matches, such as a quoted token or a private term, is
replaced with a note rather than repeated.

## Rules

`secret-scan --list-rules` shows the active set with each rule's reason.

**Content:** private key blocks · AWS access key IDs and secret keys · Azure
storage account keys · Azure SAS tokens · Entra ID client secrets ·
connection-string passwords · credentials in URLs · GitHub, GitLab, Slack, npm
tokens · Slack webhooks · live Stripe keys · Google API keys · Anthropic and
OpenAI API keys · inline `api_key = "…"`-style assignments (with an entropy
check).

**File names:** `.env` files (not `.env.example`) · Terraform state ·
key stores and certificate bundles (`.pfx`, `.p12`, `.jks`, SSH identity files).

Values that are obviously placeholders (`your-key-here`, `${VAR}`, `<token>`,
`EXAMPLE`, `xxxx`) are skipped. When a specific rule and the generic
assignment rule hit the same text, only the specific one is reported.

## Permissions

None. secret-scan reads files and runs read-only `git` commands (`ls-files`,
`diff`, `cat-file`, `rev-parse`, `status`, and for `--history`, `log`, `ls-tree`
and `config`). It makes no network calls.
`--install-hook` is the only command that writes, and it refuses to replace an
existing hook without `--force`.

## Design notes

**Findings have no field for the matched text.** The guarantee isn't "we're
careful not to print it". The data structure every output format is built from
doesn't contain it. A test runs every output format, including GitHub annotations
and SARIF, against a repository full of fake secrets and asserts none of them
appear anywhere.

**No runtime dependencies.** A secret scanner reads every file in your
repository, so any dependency it pulls in sits exactly where supply-chain
risk should be smallest. The standard library covers everything needed. Dev
tooling (pytest, ruff, mypy) never ships.

**Every rule and every exception has a written reason.** Rules without a
reason turn into noise, and noise gets ignored or disabled wholesale. Reasons
also make the report useful to someone who has never seen the tool.

**Staged mode reads the git index.** Scanning the working tree in a pre-commit
hook is a common bug: it misses secrets that are staged but since edited away,
and flags ones that are on disk but not being committed.

**History is read as diffs, not as every version of every file.** Scanning each
version would cost time in proportion to the size of every file at every commit;
a diff costs time in proportion to what changed, and says which commit added a
line. The trade is that a match must touch an added line to count, so a secret
whose two halves arrive in different commits isn't recognised.

**`--since` diffs the ref directly against the working tree**, not `base...HEAD`.
That needs only the ref's commit, not a merge base, so it works on shallow CI
checkouts as long as the base commit has been fetched.

**The GitHub Action is a composite action that runs from source.** That keeps
it auditable (the code you pin is the code that runs) and passes inputs through
environment variables, so an input value can't inject shell commands.

**Tests never contain a realistic secret literal.** Fakes are assembled at
runtime from seeded random characters (`tests/fakes.py`). Otherwise this
repository would fail its own scan and trip every other scanner that looks at it.

### Compared with TruffleHog and gitleaks

TruffleHog is the benchmark this tool measures itself against. Run on the same
files (TruffleHog 3.99.0, `--no-verification`), here is how they differ:

| | secret-scan | TruffleHog |
|---|---|---|
| Secret types | 21 rules, each with a written reason | 800+ detectors |
| Checks whether a credential is live | No (no network calls) | Yes, against the provider's API |
| Git history | Yes, with `--history`: each secret once, and whether `HEAD` still has it | Yes |
| GitHub orgs, S3, Docker images | No | Yes |
| Encoded secrets (base64 and similar) | No | Yes |
| Detector precision | Shape matching plus offline structural checks (key material after a key header, GitHub token checksums); looser, so more false positives | Structural checks (key pairs, parsed key bodies) |
| Prints the matched value | Never | By default |
| Personal data, `.env`, Terraform state | Yes | No |
| Fails the run on a finding | By default | Only with `--fail` |
| License | MIT | AGPL-3.0 |

On TruffleHog's public canary repository (`trufflesecurity/test_keys`), secret-scan
finds everything in the current files: the private key, the AWS key pair, and a
URL with `admin:admin` credentials. CI checks this on every change. With `--history`
it also finds the AWS key pair that the repository's first commit added and a later
one removed.

If you need breadth or verification, use TruffleHog or gitleaks.
secret-scan is the commit gate: it never echoes what it finds, treats personal
data as a first-class concern, and keeps a rule set short enough to read in one
sitting. Running it alongside one of them is reasonable.

## Limitations

- Without `--history`, it scans the current content of files, not git history.
- `--history` compares what each commit added. A secret split across commits, half
  added in one and half in another, isn't seen as one value.
- The generic `password = "…"` rule flags descriptive values in documentation, such as
  `SuperSecretToken`, on purpose: they look exactly like weak real passwords. Allow them
  with a reason.
- Pattern matching catches the mistakes people actually make, not a determined
  attempt to hide something (encoding, splitting a key across lines).
- Binary files and files over 2 MiB skip content rules. File-name rules still
  apply, and large files are listed in the output rather than skipped silently.
- Python's regex engine backtracks. The built-in patterns are written to avoid
  slow matches, but a badly written custom pattern can slow a scan.
- Symlinks aren't followed.

## License

MIT. See [LICENSE](LICENSE).
