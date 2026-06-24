"""Output module (backward compatibility shim).

This module maintains backward compatibility for direct imports.
The actual implementation has moved to quantum_sniffer.cli.output
"""

from .cli.output import DualWriter, JsonlWriter, print_info

__all__ = ["DualWriter", "JsonlWriter", "print_info"]
