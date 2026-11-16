"""Run the whole pipeline on a directory: discover, parse, link, find paths, apply rules."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path

from taintmap.discover import discover, relative_posix
from taintmap.graph import Graph
from taintmap.link import build_graph
from taintmap.model import Finding, GraphFragment, ParseWarning
from taintmap.parsers import Parser
from taintmap.parsers.github_actions import DefaultTokenPermissions, GithubActionsParser
from taintmap.parsers.mcp_config import McpConfigParser
from taintmap.paths import candidate_paths
from taintmap.rules import run_rules

BUILTIN_PARSERS = frozenset({"github_actions", "mcp_config"})


@dataclass
class ScanResult:
    graph: Graph
    findings: list[Finding]
    warnings: list[ParseWarning]
    files: list[str] = field(default_factory=list)

    @property
    def parse_errors(self) -> list[ParseWarning]:
        """Warning-level problems (info notes such as unknown MCP servers are not errors)."""
        return [w for w in self.warnings if w.level == "warning"]


def load_parsers(default_token_permissions: DefaultTokenPermissions = "write") -> list[Parser]:
    """The built-in parsers plus any registered by other packages under ``taintmap.parsers``."""
    parsers: list[Parser] = [
        GithubActionsParser(default_token_permissions=default_token_permissions),
        McpConfigParser(),
    ]
    for entry in sorted(entry_points(group="taintmap.parsers"), key=lambda e: e.name):
        if entry.name not in BUILTIN_PARSERS:
            parsers.append(entry.load()())
    return parsers


def scan(
    root: Path | str,
    *,
    include: Sequence[str] = (),
    exclude: Sequence[str] = (),
    default_token_permissions: DefaultTokenPermissions = "write",
    parsers: Sequence[Parser] | None = None,
) -> ScanResult:
    """Scan a directory. Raises :class:`NotADirectoryError` when ``root`` is not a directory."""
    root_path = Path(root).resolve()
    active = list(parsers) if parsers is not None else load_parsers(default_token_permissions)
    fragments: list[GraphFragment] = []
    files: list[str] = []
    for path in discover(root_path, include=include, exclude=exclude):
        rel = Path(relative_posix(path, root_path))
        matched = [p for p in active if p.matches(rel)]
        if matched:
            files.append(rel.as_posix())
        fragments.extend(parser.parse(path, root_path) for parser in matched)
    graph, warnings = build_graph(fragments)
    findings = run_rules(graph, candidate_paths(graph))
    return ScanResult(graph=graph, findings=findings, warnings=warnings, files=files)
