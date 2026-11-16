"""Helpers shared by the rules."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from taintmap import catalog
from taintmap.graph import Graph
from taintmap.model import Finding, Location, Node, Severity
from taintmap.paths import CandidatePath
from taintmap.taxonomy import CarrierCategory, is_untrusted_source

DECLARE_PERMISSIONS = (
    "Declare `permissions:` explicitly: with none declared, taintmap assumes the token can write."
)


@dataclass(frozen=True)
class RuleInfo:
    """What every rule declares."""

    id: str
    title: str
    risk_class: str
    default_severity: Severity
    missing_control: str


def severity_for(info: RuleInfo, candidate: CandidatePath) -> Severity:
    """The rule's default severity, one level lower when the sink relies on assumed permissions."""
    if candidate.permissions_assumed:
        return info.default_severity.lowered()
    return info.default_severity


def with_permissions_note(fix: str, candidate: CandidatePath) -> str:
    return f"{fix} {DECLARE_PERMISSIONS}" if candidate.permissions_assumed else fix


def from_untrusted(graph: Graph, candidate: CandidatePath) -> bool:
    return is_untrusted_source(graph.node(candidate.source).category)


def agents_on(graph: Graph, candidate: CandidatePath) -> list[Node]:
    """LLM agents strictly between the source and the sink."""
    return [
        graph.node(n)
        for n in candidate.nodes[1:-1]
        if graph.node(n).category == CarrierCategory.LLM_AGENT
    ]


def best_per_pair(candidates: Iterable[CandidatePath]) -> list[CandidatePath]:
    """One path per (source, sink): documented before inferred, then shortest, then by ids."""
    best: dict[tuple[str, str], CandidatePath] = {}
    for candidate in candidates:
        key = (candidate.source, candidate.sink)
        if key not in best or _rank(candidate) < _rank(best[key]):
            best[key] = candidate
    return [best[k] for k in sorted(best)]


def _rank(candidate: CandidatePath) -> tuple[bool, int, tuple[str, ...]]:
    return (candidate.inferred, len(candidate.nodes), candidate.nodes)


def evidence(graph: Graph, nodes: Iterable[str]) -> list[Location]:
    return [graph.node(n).location for n in nodes]


def make_finding(
    info: RuleInfo,
    graph: Graph,
    candidate: CandidatePath,
    fix: str,
    *,
    severity: Severity | None = None,
    related: list[str] | None = None,
    inferred: bool | None = None,
) -> Finding:
    related = related or []
    return Finding(
        rule_id=info.id,
        severity=severity or severity_for(info, candidate),
        title=info.title,
        path=list(candidate.nodes),
        evidence=evidence(graph, candidate.nodes),
        missing_control=info.missing_control,
        fix=with_permissions_note(fix, candidate),
        inferred=candidate.inferred if inferred is None else inferred,
        permissions_assumed=candidate.permissions_assumed,
        via_servers=list(candidate.via_servers),
        related=related,
        related_evidence=evidence(graph, related),
    )


def agent_path_rule(
    info: RuleInfo,
    sink_categories: frozenset[str],
    fix: Callable[[Graph, CandidatePath], str],
) -> Callable[[Graph, list[CandidatePath]], list[Finding]]:
    """A rule for ``untrusted source -> ... LLM agent ... -> sink`` paths."""

    def find(graph: Graph, candidates: list[CandidatePath]) -> list[Finding]:
        matching = [
            c
            for c in candidates
            if graph.node(c.sink).category in sink_categories
            and from_untrusted(graph, c)
            and agents_on(graph, c)
        ]
        return [make_finding(info, graph, c, fix(graph, c)) for c in best_per_pair(matching)]

    return find


def trigger_gate_hint(graph: Graph, candidate: CandidatePath) -> str:
    """How to restrict who can start the run, worded for the source."""
    source = graph.node(candidate.source)
    trigger_name = source.attrs.get("trigger")
    if trigger_name is None:
        return "Treat this content as untrusted: require human approval before the agent acts on it"
    triggers = catalog.gha_triggers()
    trigger = triggers.trigger(str(trigger_name))
    association = triggers.association(trigger.author if trigger else None)
    if association is None:
        return (
            f"Require approval through a protected `environment:` before acting on "
            f"`{trigger_name}` events"
        )
    return f"Gate the job with `if:` on `{association}` (OWNER, MEMBER or COLLABORATOR)"


def server_before(graph: Graph, candidate: CandidatePath) -> str | None:
    """The name of the MCP server right before the sink, if there is one."""
    node = graph.node(candidate.nodes[-2])
    if node.category != CarrierCategory.MCP_SERVER:
        return None
    return str(node.attrs.get("server", node.label))


def lower_first(text: str) -> str:
    return text[:1].lower() + text[1:]
