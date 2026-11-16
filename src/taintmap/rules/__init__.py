"""Rules turn candidate paths into findings. One module per rule; rules never parse files.

Each module exposes ``RULE``: its :class:`RuleInfo` (id, title, risk class, default severity,
missing control) and a ``find(graph, candidates)`` function. Findings that reach their sink only
through assumed default token permissions are one severity level lower, and their fix text says to
declare ``permissions:`` explicitly.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from taintmap.graph import Graph
from taintmap.model import Finding
from taintmap.paths import CandidatePath
from taintmap.rules._common import RuleInfo


@dataclass(frozen=True)
class Rule:
    info: RuleInfo
    find: Callable[[Graph, list[CandidatePath]], list[Finding]]


def all_rules() -> list[Rule]:
    from taintmap.rules import (
        tm001_agent_write,
        tm002_agent_secrets,
        tm003_agent_exec,
        tm004_lethal_trifecta,
        tm005_shell_injection,
    )

    return [
        tm001_agent_write.RULE,
        tm002_agent_secrets.RULE,
        tm003_agent_exec.RULE,
        tm004_lethal_trifecta.RULE,
        tm005_shell_injection.RULE,
    ]


def run_rules(
    graph: Graph, candidates: list[CandidatePath], rules: Sequence[Rule] | None = None
) -> list[Finding]:
    """Every rule's findings, most severe first, then by rule id and path."""
    findings = [f for rule in (rules or all_rules()) for f in rule.find(graph, candidates)]
    return sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, f.path))


__all__ = ["Rule", "RuleInfo", "all_rules", "run_rules"]
