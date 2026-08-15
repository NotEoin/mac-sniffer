"""Allows running with `python -m probe_sniffer`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
