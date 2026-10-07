"""``python -m opencode_toolkit`` entry point."""

from __future__ import annotations

import sys

from opencode_toolkit.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
