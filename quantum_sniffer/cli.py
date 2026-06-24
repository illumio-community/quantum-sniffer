"""Command-line entry point (backward compatibility shim).

This module maintains backward compatibility for direct imports.
The actual CLI implementation has moved to quantum_sniffer.cli.app
"""

import sys
from .cli.app import main, build_parser, build_default_filter

__all__ = ["main", "build_parser", "build_default_filter"]

if __name__ == "__main__":
    sys.exit(main())
