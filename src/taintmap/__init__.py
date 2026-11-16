"""taintmap: map how untrusted input flows through AI agents, automations and code."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("taintmap")
except PackageNotFoundError:  # pragma: no cover - only when running from an uninstalled tree
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
