"""Find candidate paths from every source to every sink, and what each one depends on.

Rules receive these paths; they never search the graph themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

from taintmap.controls import evaluate
from taintmap.graph import Graph
from taintmap.model import EdgeKind, NodeKind

DEFAULT_MAX_DEPTH = 8
DEFAULT_MAX_PATHS_PER_PAIR = 5


@dataclass(frozen=True)
class CandidatePath:
    """A path from a source to a sink.

    * ``guarded_by`` / ``blocked_by``: controls on the path, and the ones that block it.
    * ``inferred``: the path relies on an inferred catalog claim (a node on it, or every edge of
      one of its hops, has ``attrs.evidence == "inferred"``). Reports show such findings as
      inferred.
    * ``permissions_assumed``: the sink exists only because default token permissions were
      assumed. Rules lower the severity of such findings by one level.
    """

    nodes: tuple[str, ...]
    guarded_by: tuple[str, ...]
    blocked_by: tuple[str, ...]
    inferred: bool
    permissions_assumed: bool

    @property
    def source(self) -> str:
        return self.nodes[0]

    @property
    def sink(self) -> str:
        return self.nodes[-1]

    @property
    def blocked(self) -> bool:
        return bool(self.blocked_by)


def candidate_paths(
    graph: Graph,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_paths_per_pair: int = DEFAULT_MAX_PATHS_PER_PAIR,
    include_blocked: bool = False,
) -> list[CandidatePath]:
    """Every path from a source node to a sink node, at most ``max_paths_per_pair`` per pair.

    Paths blocked by an effective control are dropped unless ``include_blocked`` is set. The cap
    keeps the shortest paths of each pair (ties broken by node ids) and is applied before
    blocked paths are dropped, so the result does not depend on which controls exist.
    """
    if max_paths_per_pair < 1:
        raise ValueError(f"max_paths_per_pair must be at least 1, got {max_paths_per_pair}")
    sources = graph.nodes_of_kind(NodeKind.SOURCE)
    sinks = graph.nodes_of_kind(NodeKind.SINK)
    out: list[CandidatePath] = []
    for source in sources:
        for sink in sinks:
            for nodes in graph.paths(source.id, sink.id, max_depth, limit=max_paths_per_pair):
                candidate = describe(graph, nodes)
                if include_blocked or not candidate.blocked:
                    out.append(candidate)
    return out


def describe(graph: Graph, nodes: list[str]) -> CandidatePath:
    """Evaluate controls and dependencies for one path."""
    decision = evaluate(graph, nodes)
    return CandidatePath(
        nodes=tuple(nodes),
        guarded_by=decision.guarding,
        blocked_by=decision.blocking,
        inferred=depends_on_inferred(graph, nodes),
        permissions_assumed=graph.node(nodes[-1]).attrs.get("permissions_assumed") is True,
    )


def depends_on_inferred(graph: Graph, nodes: list[str]) -> bool:
    """True when a node on the path, or every flow edge of one of its hops, is inferred."""
    if any(graph.node(n).attrs.get("evidence") == "inferred" for n in nodes):
        return True
    for src, dst in pairwise(nodes):
        hop = [e for e in graph.edges_between(src, dst) if e.kind != EdgeKind.GUARDED_BY]
        if hop and all(e.attrs.get("evidence") == "inferred" for e in hop):
            return True
    return False
