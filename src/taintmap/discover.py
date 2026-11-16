"""Find the files under a root that taintmap may parse.

Discovery is deliberately conservative about what it walks into:

* Directories named ``.git``, ``node_modules``, ``dist``, ``build``, ``__pycache__``, ``venv`` or
  ``.venv`` are skipped, as is any directory that contains a ``pyvenv.cfg`` (a virtualenv).
* Hidden entries (names starting with ``.``) are skipped, except the directories ``.github``,
  ``.cursor`` and ``.vscode`` and the file ``.mcp.json``.
* Symbolic links are followed only when their target resolves inside the root, because a link's
  own name and place can matter to a parser (``.mcp.json`` linked to ``config/mcp.json``). Links
  that point outside the root, broken links and links back to an enclosing directory are skipped.

Include and exclude globs are matched against the file's path relative to the root, with POSIX
separators. ``*`` and ``?`` do not cross ``/``; ``**`` matches any number of directories. A pattern
without ``/`` also matches the bare file or directory name at any depth, so ``--exclude vendor``
skips every ``vendor`` directory. A file must match at least one include glob (when any are given)
and no exclude glob. A directory matching an exclude glob is not walked.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Sequence
from pathlib import Path

SKIPPED_DIR_NAMES = frozenset(
    {".git", "node_modules", "dist", "build", "__pycache__", "venv", ".venv"}
)
ALLOWED_HIDDEN_NAMES = frozenset({".github", ".cursor", ".vscode", ".mcp.json"})


class Glob:
    """A compiled include/exclude pattern."""

    def __init__(self, pattern: str) -> None:
        normalised = pattern.strip().replace("\\", "/")
        while normalised.startswith("./"):
            normalised = normalised[2:]
        normalised = normalised.strip("/")
        if not normalised:
            raise ValueError(f"empty glob pattern: {pattern!r}")
        self.pattern = normalised
        self._regex = re.compile(_glob_to_regex(normalised))
        self._name_only = "/" not in normalised

    def matches(self, rel_path: str) -> bool:
        """True when the POSIX relative path (or, for slash-free patterns, its name) matches."""
        if self._regex.fullmatch(rel_path):
            return True
        return self._name_only and self._regex.fullmatch(rel_path.rsplit("/", 1)[-1]) is not None

    def __repr__(self) -> str:
        return f"Glob({self.pattern!r})"


def _glob_to_regex(pattern: str) -> str:
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                i += 2
                if i < n and pattern[i] == "/":
                    out.append("(?:.*/)?")
                    i += 1
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            end = pattern.find("]", i + 2 if pattern[i + 1 : i + 2] in ("!", "]") else i + 1)
            if end == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1 : end].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = end
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _compile(patterns: Iterable[str]) -> list[Glob]:
    return [Glob(p) for p in patterns]


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_hidden_and_not_allowed(name: str) -> bool:
    return name.startswith(".") and name not in ALLOWED_HIDDEN_NAMES


def _is_skipped_dir(name: str, path: Path) -> bool:
    if name in SKIPPED_DIR_NAMES or _is_hidden_and_not_allowed(name):
        return True
    try:
        return (path / "pyvenv.cfg").is_file()
    except OSError:
        return False


def discover(
    root: Path | str,
    include: Sequence[str] = (),
    exclude: Sequence[str] = (),
) -> list[Path]:
    """Return the files under ``root`` that pass the skip rules and globs.

    Paths are returned as ``<resolved root>/<relative path>`` (symlinks inside the root are not
    resolved), sorted by their POSIX relative path. Raises :class:`NotADirectoryError` when
    ``root`` is not a directory.
    """
    root_real = Path(root).resolve()
    if not root_real.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    includes = _compile(include)
    excludes = _compile(exclude)

    found: list[tuple[str, Path]] = []

    def walk(directory: Path, rel_prefix: str, ancestors: frozenset[str]) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            rel = rel_prefix + entry.name
            entry_path = Path(entry.path)
            try:
                is_dir = entry.is_dir()
                is_file = not is_dir and entry.is_file()
                # Directories are always resolved: Windows junctions are not reported as symlinks
                # but can still point anywhere.
                if is_dir or entry.is_symlink():
                    real = entry_path.resolve(strict=True)
                    if not _is_within(real, root_real):
                        continue
                else:
                    real = entry_path
            except (OSError, RuntimeError):
                continue  # broken link, link loop or unreadable entry

            if is_dir:
                if _is_skipped_dir(entry.name, entry_path):
                    continue
                if any(g.matches(rel) for g in excludes):
                    continue
                key = os.path.normcase(real)
                if key in ancestors:
                    continue  # a link back to a directory we are already inside
                walk(entry_path, rel + "/", ancestors | {key})
            elif is_file:
                if _is_hidden_and_not_allowed(entry.name):
                    continue
                if any(g.matches(rel) for g in excludes):
                    continue
                if includes and not any(g.matches(rel) for g in includes):
                    continue
                found.append((rel, root_real / rel))

    walk(root_real, "", frozenset({os.path.normcase(root_real)}))
    found.sort(key=lambda item: item[0])
    return [path for _, path in found]


def relative_posix(path: Path, root: Path) -> str:
    """Return ``path`` relative to ``root`` with POSIX separators, as used in locations."""
    return Path(os.path.relpath(path, Path(root).resolve())).as_posix()
