"""Load JSON and map JSON pointers (RFC 6901) to 1-based line numbers.

The standard library's ``json`` module does not keep positions, so after ``json.loads`` accepts a
document a small scanner walks the same text and records the line of every object key and array
item. Only strict JSON is accepted; comments and trailing commas produce a parse warning.

When an object repeats a key, ``json.loads`` keeps the last value; the locator does the same and a
warning names the key (never its value).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from taintmap.loaders._common import one_line, read_text
from taintmap.model import ParseWarning


def escape_token(token: str) -> str:
    """Escape one reference token for use in a JSON pointer."""
    return token.replace("~", "~0").replace("/", "~1")


def pointer(*tokens: str | int) -> str:
    """Build a JSON pointer from tokens.

    ``pointer("mcpServers", "a/b")`` gives ``/mcpServers/a~1b``.
    """
    return "".join("/" + escape_token(str(t)) for t in tokens)


def _normalise_pointer(value: str) -> str:
    if value and not value.startswith("/"):
        raise ValueError(f"JSON pointer must be empty or start with '/': {value!r}")
    for i, char in enumerate(value):
        if char == "~" and value[i + 1 : i + 2] not in ("0", "1"):
            raise ValueError(f"invalid '~' escape in JSON pointer: {value!r}")
    return value


@dataclass(frozen=True)
class JsonDocument:
    """A loaded JSON file. ``data`` is ``None`` when the file could not be parsed."""

    file: str
    data: Any
    warnings: list[ParseWarning] = field(default_factory=list)
    lines: dict[str, int] = field(default_factory=dict, repr=False)

    @property
    def ok(self) -> bool:
        return not self.warnings

    def line_of(self, json_pointer: str) -> int:
        """Return the 1-based line of the key or array item that ``json_pointer`` names.

        ``""`` is the whole document. Raises :class:`KeyError` when the pointer does not exist and
        :class:`ValueError` when it is not a valid pointer.
        """
        key = _normalise_pointer(json_pointer)
        try:
            return self.lines[key]
        except KeyError:
            raise KeyError(f"{self.file}: no such JSON pointer {json_pointer!r}") from None


class _LineScanner:
    """Walk JSON text that ``json.loads`` already accepted and record a line for every pointer."""

    def __init__(self, text: str, file: str) -> None:
        self.text = text
        self.file = file
        self.pos = 0
        self.line = 1
        self.lines: dict[str, int] = {}
        self.warnings: list[ParseWarning] = []

    def scan(self) -> None:
        self._skip_ws()
        self.lines[""] = self.line
        self._value("")

    def _skip_ws(self) -> None:
        text, n = self.text, len(self.text)
        while self.pos < n and text[self.pos] in " \t\r\n":
            if text[self.pos] == "\n":
                self.line += 1
            self.pos += 1

    def _value(self, path: str) -> None:
        self._skip_ws()
        char = self.text[self.pos]
        if char == "{":
            self._object(path)
        elif char == "[":
            self._array(path)
        elif char == '"':
            self._string()
        else:
            while self.pos < len(self.text) and self.text[self.pos] not in ",]} \t\r\n":
                self.pos += 1

    def _string(self) -> str:
        start = self.pos
        self.pos += 1
        while self.text[self.pos] != '"':
            self.pos += 2 if self.text[self.pos] == "\\" else 1
        self.pos += 1
        decoded: str = json.loads(self.text[start : self.pos])
        return decoded

    def _object(self, path: str) -> None:
        self.pos += 1  # {
        seen: dict[str, int] = {}
        self._skip_ws()
        if self.text[self.pos] == "}":
            self.pos += 1
            return
        while True:
            self._skip_ws()
            key_line = self.line
            key = self._string()
            child = path + "/" + escape_token(key)
            if key in seen:
                self.warnings.append(
                    ParseWarning(
                        file=self.file,
                        line=key_line,
                        message=one_line(
                            f'duplicate key "{key}" (first on line {seen[key]}); '
                            "the last one is used"
                        ),
                    )
                )
                prefix = child + "/"
                for stale in [p for p in self.lines if p.startswith(prefix)]:
                    del self.lines[stale]
            seen[key] = key_line
            self.lines[child] = key_line
            self._skip_ws()
            self.pos += 1  # :
            self._value(child)
            self._skip_ws()
            closing = self.text[self.pos]
            self.pos += 1
            if closing == "}":
                return

    def _array(self, path: str) -> None:
        self.pos += 1  # [
        self._skip_ws()
        if self.text[self.pos] == "]":
            self.pos += 1
            return
        index = 0
        while True:
            self._skip_ws()
            self.lines[f"{path}/{index}"] = self.line
            self._value(f"{path}/{index}")
            self._skip_ws()
            closing = self.text[self.pos]
            self.pos += 1
            if closing == "]":
                return
            index += 1


def parse_json(text: str, file: str) -> JsonDocument:
    """Parse JSON text. Problems become warnings on the returned document, never exceptions."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        warning = ParseWarning(
            file=file, line=exc.lineno, message=one_line(f"invalid JSON: {exc.msg}")
        )
        return JsonDocument(file=file, data=None, warnings=[warning])
    except RecursionError:
        warning = ParseWarning(file=file, line=1, message="invalid JSON: nested too deeply")
        return JsonDocument(file=file, data=None, warnings=[warning])
    scanner = _LineScanner(text, file)
    try:
        scanner.scan()
    except RecursionError:
        warning = ParseWarning(file=file, line=1, message="invalid JSON: nested too deeply")
        return JsonDocument(file=file, data=None, warnings=[warning])
    return JsonDocument(file=file, data=data, warnings=scanner.warnings, lines=scanner.lines)


def load_json(path: Path, root: Path) -> JsonDocument:
    """Read and parse a JSON file. ``file`` on the result is relative to ``root``."""
    rel, text, warning = read_text(path, root)
    if text is None:
        assert warning is not None
        return JsonDocument(file=rel, data=None, warnings=[warning])
    return parse_json(text, rel)
