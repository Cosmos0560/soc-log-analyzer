#!/usr/bin/env python3
"""Root-level entry point so the tool can be run as ``python analyzer.py ...``
without installing the package first."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from soc_analyzer.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
