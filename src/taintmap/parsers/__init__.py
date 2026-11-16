"""Parsers turn files into graph fragments.

Built-in parsers are registered in the ``taintmap.parsers`` entry-point group (see pyproject.toml),
so third-party packages can add parsers the same way.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from taintmap.model import GraphFragment


@runtime_checkable
class Parser(Protocol):
    """Turns the files it understands into a :class:`GraphFragment`."""

    name: str

    def matches(self, path: Path) -> bool: ...

    def parse(self, path: Path, root: Path) -> GraphFragment: ...


__all__ = ["Parser"]
