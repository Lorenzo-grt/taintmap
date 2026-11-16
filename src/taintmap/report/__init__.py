"""Reporters: terminal and JSON. Both show the same findings, hops and flags."""

from __future__ import annotations

from itertools import pairwise

from taintmap.graph import Graph
from taintmap.model import EdgeKind, Finding, Node, NodeKind, Severity
from taintmap.taxonomy import CarrierCategory


def at_least(findings: list[Finding], minimum: Severity) -> list[Finding]:
    return [f for f in findings if f.severity.rank >= minimum.rank]


def role(node: Node) -> str:
    """A short word for a node's role on a path."""
    if node.kind is NodeKind.SOURCE:
        return "source"
    if node.kind is NodeKind.SINK:
        return "sink"
    if node.kind is NodeKind.CONTROL:
        return "control"
    if node.category == CarrierCategory.LLM_AGENT:
        return "agent"
    if node.category == CarrierCategory.MCP_SERVER:
        return "server"
    if node.category == CarrierCategory.WORKFLOW_STEP:
        return "job" if "index" not in node.attrs else "step"
    return node.kind.value


def inferred_reasons(graph: Graph, finding: Finding) -> list[str]:
    """Why a finding is inferred: the reasons of the inferred nodes and hops it relies on."""
    reasons: list[str] = []

    def add(reason: object) -> None:
        if isinstance(reason, str) and reason and reason not in reasons:
            reasons.append(reason)

    for node_id in [*finding.path, *finding.related]:
        node = graph.node(node_id)
        if node.attrs.get("evidence") == "inferred":
            add(node.attrs.get("evidence_reason") or f"{node.label} is inferred")
    for src, dst in pairwise(finding.path):
        hop = [e for e in graph.edges_between(src, dst) if e.kind != EdgeKind.GUARDED_BY]
        if hop and all(e.attrs.get("evidence") == "inferred" for e in hop):
            add(hop[0].attrs.get("evidence_reason"))
    return reasons


def counts(findings: list[Finding]) -> dict[str, int]:
    """Findings per severity, most severe first, including zeros."""
    order = sorted(Severity, key=lambda s: -s.rank)
    return {s.value: sum(1 for f in findings if f.severity is s) for s in order}
