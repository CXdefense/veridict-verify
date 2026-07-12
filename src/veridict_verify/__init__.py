"""Standalone offline verifier for VERIDICT case bundles.

This package intentionally shares no runtime code with the veridict engine:
it re-implements every check from the bundle specification so that a skeptic
does not have to trust the tool that produced the bundle.
"""

__version__ = "0.2.0"

CURRENT_SPEC = "veridict-bundle/2"
SUPPORTED_SPECS = ("veridict-bundle/1", CURRENT_SPEC)
