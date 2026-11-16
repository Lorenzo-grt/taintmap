"""Helpers shared by the loaders."""

from __future__ import annotations

from pathlib import Path

from taintmap.discover import relative_posix
from taintmap.model import ParseWarning

MAX_MESSAGE_LENGTH = 200


def one_line(message: str) -> str:
    """Collapse whitespace and cap the length so a warning stays on one line."""
    text = " ".join(message.split())
    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 3] + "..."
    return text


def read_text(path: Path, root: Path) -> tuple[str, str | None, ParseWarning | None]:
    """Read a UTF-8 file (a BOM is allowed).

    Returns ``(relative file, text, None)`` or ``(relative file, None, warning)``.
    """
    rel = relative_posix(path, root)
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return rel, handle.read(), None
    except UnicodeDecodeError as exc:
        return rel, None, ParseWarning(file=rel, line=1, message=f"not valid UTF-8: {exc.reason}")
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        return rel, None, ParseWarning(file=rel, line=1, message=f"cannot read file: {reason}")
