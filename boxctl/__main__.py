"""Allow running as python -m boxctl."""

import sys

from boxctl.cli import main

if __name__ == "__main__":
    sys.exit(main())
