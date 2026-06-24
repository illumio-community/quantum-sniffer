"""Skynet module (backward compatibility shim).

This module maintains backward compatibility for direct imports.
The actual implementation has moved to quantum_sniffer.cli.skynet
"""

from .cli.skynet import run, load_events, render_report

__all__ = ["run", "load_events", "render_report"]
