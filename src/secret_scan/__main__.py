import sys

# The GitHub Action runs on whatever python3 the runner has. Fail with a clear
# message instead of a syntax error deep in an import.
if sys.version_info < (3, 10):  # noqa: UP036
    sys.stderr.write("secret-scan: error: Python 3.10 or newer is required\n")
    sys.exit(2)

from secret_scan.cli import main

sys.exit(main())
