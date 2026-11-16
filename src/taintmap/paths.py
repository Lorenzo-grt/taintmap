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
    * ``via_servers``: MCP servers whose tool results carry the input along the path (from
      ``attrs.via_server`` on its edges), so reports can say which server the content came
      through even though the edge goes straight to the client.
    """

    nodes: tuple[str, ...]
    guarded_by: tuple[str, ...]
    blocked_by: tuple[str, ...]
    inferred: bool
    permissions_assumed: bool
    via_servers: tuple[str, ...] = ()

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
    """Every unblocked path from a source node to a sink node, at most ``max_paths_per_pair``
    per pair.

    The cap applies after blocked paths are removed, so an unblocked longer path is never hidden
    behind blocked shorter ones. Paths are examined shortest first and the cap keeps the shortest
    unblocked ones (ties broken by node ids). With ``include_blocked``, blocked paths found along
    the way are returned too, capped the same way. At most :data:`MAX_EXAMINED_PER_PAIR` paths
    are examined per pair.
    """
    if max_paths_per_pair < 1:
        raise ValueError(f"max_paths_per_pair must be at least 1, got {max_paths_per_pair}")
    sources = graph.nodes_of_kind(NodeKind.SOURCE)
    sinks = graph.nodes_of_kind(NodeKind.SINK)
    out: list[CandidatePath] = []
    for source in sources:
        for sink in sinks:
            open_, blocked = _pair(graph, source.id, sink.id, max_depth, max_paths_per_pair)
            out.extend(open_)
            if include_blocked:
                out.extend(blocked)
    return out


MAX_EXAMINED_PER_PAIR = 2000


def _pair(
    graph: Graph, source: str, sink: str, max_depth: int, cap: int
) -> tuple[list[CandidatePath], list[CandidatePath]]:
    open_: list[CandidatePath] = []
    blocked: list[CandidatePath] = []
    current_length = -1
    for examined, nodes in enumerate(graph.iter_paths_shortest_first(source, sink, max_depth)):
        # Finish the current length before stopping, so ties are chosen by node ids.
        if examined >= MAX_EXAMINED_PER_PAIR:
            break
        if len(nodes) != current_length:
            if len(open_) >= cap:
                break
            current_length = len(nodes)
        candidate = describe(graph, nodes)
        (blocked if candidate.blocked else open_).append(candidate)

    def key(c: CandidatePath) -> tuple[int, tuple[str, ...]]:
        return (len(c.nodes), c.nodes)

    return sorted(open_, key=key)[:cap], sorted(blocked, key=key)[:cap]


def describe(graph: Graph, nodes: list[str]) -> CandidatePath:
    """Evaluate controls and dependencies for one path."""
    decision = evaluate(graph, nodes)
    return CandidatePath(
        nodes=tuple(nodes),
        guarded_by=decision.guarding,
        blocked_by=decision.blocking,
        inferred=depends_on_inferred(graph, nodes),
        permissions_assumed=graph.node(nodes[-1]).attrs.get("permissions_assumed") is True,
        via_servers=via_servers(graph, nodes),
    )


def via_servers(graph: Graph, nodes: list[str]) -> tuple[str, ...]:
    """MCP servers named by ``attrs.via_server`` on the path's edges, in path order."""
    found: list[str] = []
    for src, dst in pairwise(nodes):
        for edge in graph.edges_between(src, dst):
            server = edge.attrs.get("via_server")
            if isinstance(server, str) and server not in found:
                found.append(server)
    return tuple(found)


def depends_on_inferred(graph: Graph, nodes: list[str]) -> bool:
    """True when a node on the path, or every flow edge of one of its hops, is inferred."""
    if any(graph.node(n).attrs.get("evidence") == "inferred" for n in nodes):
        return True
    for src, dst in pairwise(nodes):
        hop = [e for e in graph.edges_between(src, dst) if e.kind != EdgeKind.GUARDED_BY]
        if hop and all(e.attrs.get("evidence") == "inferred" for e in hop):
            return True
    return False
