# Agent guide — secret-scan

The shared rules in `../w3fix-utils/AGENTS.md` apply in full; read them first.
The definition of "ready" is `../w3fix-utils/STANDARDS.md`.

## This tool

- **Purpose:** scan files for credentials and personal data without ever printing what it finds.
- **Local check before any PR:** `npm run check` (format/lint, tests, and a self-scan).
- **Runtime dependencies:** none, and it stays that way. The scanner reads every file
  in a repository, so each dependency would be supply-chain surface in exactly the place
  it should be smallest. Dev-only tooling is fine.
- **Never print a matched value:** not in output, errors, test failure messages, or debug logs.
  Tests check this.
- **Fake secrets in tests are built at runtime** (`'AKIA' + 'X'.repeat(16)`), never written
  as literals. Otherwise the repository fails its own scan, and other scanners flag it too.
