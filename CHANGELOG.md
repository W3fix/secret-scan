# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Scanner with 18 content rules and 3 file-name rules, each with a written reason.
- Scan modes: tracked files (default), `--staged` (reads the git index), `--since REF`, explicit paths.
- Private terms from `~/.config/secret-scan/private.json`, a git-ignored `.secret-scan.local.json`,
  or `SECRET_SCAN_PRIVATE_TERMS`. The scanner refuses to run if the local file is tracked.
- Repository config `.secret-scan.json`: allow, ignore, disable and custom rules, each requiring a reason.
- Inline `secret-scan:allow <reason>` on the line or the line above.
- Output as text, JSON, and SARIF 2.1.0; GitHub annotations when running in Actions.
- `--install-hook` for a git pre-commit hook, a pre-commit framework hook, and a composite GitHub Action.
- `scripts/benchmark.py`: scans pinned public corpora (TruffleHog's canary keys, the CPython standard library,
  Node.js type definitions) and fails on any new or missing finding. Runs in CI.
