"""Load YAML with ruamel.yaml in round-trip mode, keeping line numbers.

Round-trip mode uses YAML 1.2, so a GitHub Actions ``on:`` key stays the string ``"on"`` instead of
becoming the boolean ``True``. Mappings load as :class:`CommentedMap` and sequences as
:class:`CommentedSeq`; both carry 0-based positions in ``.lc``, which the helpers here turn into
1-based lines.
"""

from __future__ import annotations

import re
from collections.abc import Hashable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.constructor import DuplicateKeyError
from ruamel.yaml.error import MarkedYAMLError, YAMLError

from taintmap.loaders._common import one_line, read_text
from taintmap.model import ParseWarning

PathStep = Hashable
_DUPLICATE_KEY = re.compile(r'found duplicate key "(?P<key>.*?)" with value')


@dataclass(frozen=True)
class YamlDocument:
    """A loaded YAML file. ``data`` is ``None`` when the file was empty or could not be parsed."""

    file: str
    data: Any
    warnings: list[ParseWarning] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.warnings

    def line_of(self, path: Sequence[PathStep] = ()) -> int:
        """Return the 1-based line of the key or list item at ``path``.

        ``path`` is a sequence of mapping keys and list indexes, e.g. ``("jobs", "build", "steps",
        2, "run")``. An empty path gives the line where the document starts. Raises
        :class:`KeyError` when the path does not exist.
        """
        node = self.data
        if not path:
            if isinstance(node, CommentedMap | CommentedSeq):
                return int(node.lc.line) + 1
            raise KeyError("document has no mapping or sequence at its root")
        line = 0
        for step in path:
            if isinstance(node, CommentedMap) and step in node:
                line = key_line(node, step)
                node = node[step]
            elif (
                isinstance(node, CommentedSeq)
                and isinstance(step, int)
                and not isinstance(step, bool)
                and 0 <= step < len(node)
            ):
                line = item_line(node, step)
                node = node[step]
            else:
                raise KeyError(f"{self.file}: no such path {list(path)!r}")
        return line


def key_line(mapping: CommentedMap, key: Hashable) -> int:
    """1-based line of ``key`` in ``mapping``."""
    return int(mapping.lc.key(key)[0]) + 1


def value_line(mapping: CommentedMap, key: Hashable) -> int:
    """1-based line where the value of ``key`` starts (differs from the key for block values)."""
    return int(mapping.lc.value(key)[0]) + 1


def item_line(sequence: CommentedSeq, index: int) -> int:
    """1-based line of item ``index`` in ``sequence``."""
    return int(sequence.lc.item(index)[0]) + 1


def _warning_from_error(file: str, exc: Exception) -> ParseWarning:
    line = 1
    if isinstance(exc, MarkedYAMLError):
        mark = exc.problem_mark or exc.context_mark
        if mark is not None:
            line = int(mark.line) + 1
    if isinstance(exc, DuplicateKeyError):
        # ruamel's own message quotes both values, which may be secrets. Keep only the key.
        match = _DUPLICATE_KEY.search(str(exc.problem or ""))
        key = match.group("key") if match else "?"
        message = f'duplicate key "{key}"'
    elif isinstance(exc, MarkedYAMLError):
        parts = [p for p in (exc.context, exc.problem) if p]
        message = "invalid YAML: " + (", ".join(parts) or type(exc).__name__)
    else:
        message = f"invalid YAML: {type(exc).__name__}"
    return ParseWarning(file=file, line=line, message=one_line(message))


def parse_yaml(text: str, file: str) -> YamlDocument:
    """Parse YAML text. Problems become warnings on the returned document, never exceptions."""
    yaml = YAML(typ="rt")
    try:
        data = yaml.load(text)
    except YAMLError as exc:
        return YamlDocument(file=file, data=None, warnings=[_warning_from_error(file, exc)])
    except (ValueError, TypeError, RecursionError) as exc:
        return YamlDocument(file=file, data=None, warnings=[_warning_from_error(file, exc)])
    return YamlDocument(file=file, data=data)


def load_yaml(path: Path, root: Path) -> YamlDocument:
    """Read and parse a YAML file. ``file`` on the result is relative to ``root``."""
    rel, text, warning = read_text(path, root)
    if text is None:
        assert warning is not None
        return YamlDocument(file=rel, data=None, warnings=[warning])
    return parse_yaml(text, rel)
