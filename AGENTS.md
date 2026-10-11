# Agent guide — secret-scan

The shared rules in `../w3fix-utils/AGENTS.md` apply in full; read them first.
The definition of "ready" is `../w3fix-utils/STANDARDS.md`.

## This tool

- **Purpose:** scan files for credentials and personal data without ever printing what it finds.
- **Local check before any PR:** `scripts/check.sh` (format, lint, types, tests, self-scan, benchmark).
- **Benchmark:** `scripts/benchmark.py` compares findings on pinned public corpora with
  `benchmarks/*.expected`. A rule change that moves those numbers updates the expected
  files with `--update` in the same PR, so the reviewer sees exactly which findings changed.
- **Python:** pyenv provides the interpreters (`.python-version` pins 3.11 for development).
  Create the venv from it, `uv venv --python "$(pyenv which python)"`, so uv doesn't
  download its own. Supported range: 3.10+. Test 3.10 before changing syntax.
- **Runtime dependencies:** none, and it stays that way. The scanner reads every file in
  a repository, so each dependency would be supply-chain surface in exactly the place it
  should be smallest. Dev tooling (pytest, ruff, mypy) is fine.
- **Never output a matched value:** not in reports, errors, notes, test failure messages
  or debug logs. `Finding` has no field for it on purpose; don't add one.
  `test_no_output_ever_contains_a_matched_value` must keep passing.
- **Fake secrets in tests are built at runtime** (`tests/fakes.py`), never written as
  literals. Otherwise this repository fails its own scan and trips other scanners.
- **New rules** need a `why`, a positive test in `tests/test_rules.py::POSITIVES`, and
  at least one look-alike that must stay quiet.
