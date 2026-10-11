#!/usr/bin/env bash
# The full local gate. Run before opening a pull request; CI runs the same steps.
set -euo pipefail
cd "$(dirname "$0")/.."
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest -q
uv run secret-scan
# Fetches the pinned corpora on first run, then reuses .benchmarks/.
uv run python scripts/benchmark.py
