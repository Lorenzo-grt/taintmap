"""The system graph: merged fragments with path search.

The graph wraps a :class:`networkx.MultiDiGraph`. Each networkx node stores its :class:`Node` under
the ``"node"`` attribute and each edge stores its :class:`Edge` under ``"edge"``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import networkx as nx

from taintmap.model import Edge, EdgeKind, GraphFragment, Node, NodeKind

JSON_SCHEMA_VERSION = 1

# Edge kinds that do not carry data or control flow. ``guarded_by`` links a node to the control that
# protects it; following it would lead a path into a control node, which is never a hop.
_NON_FLOW_EDGES = frozenset({EdgeKind.GUARDED_BY})


class GraphError(ValueError):
    """Base class for graph construction errors."""


class DuplicateNodeError(GraphError):
    """A node id was added twice with different content."""

    def __init__(self, existing: Node, new: Node) -> None:
        self.existing = existing
        self.new = new
        super().__init__(
            f"duplicate node id {new.id!r}: already defined at {existing.location} "
            f"(kind={existing.kind.value}, category={existing.category}), "
            f"redefined differently at {new.location} "
            f"(kind={new.kind.value}, category={new.category})"
        )


class UnknownNodeError(GraphError, KeyError):
    """A node id was referenced but is not in the graph."""

    def __init__(self, node_id: str, context: str = "") -> None:
        self.node_id = node_id
        suffix = f" ({context})" if context else ""
        super().__init__(f"unknown node id {node_id!r}{suffix}")

    def __str__(self) -> str:  # KeyError would otherwise repr() the message
        return str(self.args[0])


class Graph:
    """A deterministic, de-duplicated graph of nodes and edges."""

    def __init__(self) -> None:
        self._g: nx.MultiDiGraph[str] = nx.MultiDiGraph()

    # -- construction -------------------------------------------------------------------------

    def add_fragment(self, fragment: GraphFragment) -> None:
        """Merge a fragment into the graph.

        Adding a node whose id already exists is a no-op when the content is identical and
        raises :class:`DuplicateNodeError` otherwise. Every edge must reference nodes that exist
        in the graph or in the same fragment, else :class:`UnknownNodeError` is raised. Identical
        edges are stored once. The fragment is validated in full before anything is added, so a
        failed call leaves the graph unchanged.
        """
        pending: dict[str, Node] = {}
        for node in fragment.nodes:
            known = pending.get(node.id) or self._node_or_none(node.id)
            if known is not None and known != node:
                raise DuplicateNodeError(known, node)
            pending[node.id] = node

        for edge in fragment.edges:
            for end in (edge.src, edge.dst):
                if end not in pending and end not in self._g:
                    raise UnknownNodeError(
                        end, f"edge {edge.kind.value} {edge.src} -> {edge.dst} at {edge.location}"
                    )

        for node in pending.values():
            if node.id not in self._g:
                self._g.add_node(node.id, node=node)
        for edge in fragment.edges:
            if not self._has_edge(edge):
                self._g.add_edge(edge.src, edge.dst, edge=edge)

    def _node_or_none(self, node_id: str) -> Node | None:
        if node_id not in self._g:
            return None
        node: Node = self._g.nodes[node_id]["node"]
        return node

    def _has_edge(self, edge: Edge) -> bool:
        data = self._g.get_edge_data(edge.src, edge.dst)
        return data is not None and any(attrs["edge"] == edge for attrs in data.values())

    # -- queries ------------------------------------------------------------------------------

    def __len__(self) -> int:
        return int(self._g.number_of_nodes())

    def __contains__(self, node_id: object) -> bool:
        return node_id in self._g

    def node(self, node_id: str) -> Node:
        """Return the node with this id or raise :class:`UnknownNodeError`."""
        found = self._node_or_none(node_id)
        if found is None:
            raise UnknownNodeError(node_id)
        return found

    def nodes(self) -> list[Node]:
        """All nodes, sorted by id."""
        return sorted((data["node"] for _, data in self._g.nodes(data=True)), key=lambda n: n.id)

    def edges(self) -> list[Edge]:
        """All edges, in a deterministic order."""
        return sorted(self._iter_edges(), key=Edge.sort_key)

    def _iter_edges(self) -> Iterator[Edge]:
        for _, _, data in self._g.edges(data=True):
            yield data["edge"]

    def nodes_of_kind(self, kind: NodeKind | str) -> list[Node]:
        """All nodes of one kind, sorted by id."""
        wanted = NodeKind(kind)
        return [n for n in self.nodes() if n.kind == wanted]

    def paths(self, source_id: str, sink_id: str, max_depth: int = 8) -> list[list[str]]:
        """Return every simple path from source to sink with at most ``max_depth`` edges.

        Paths are lists of node ids, sorted, without duplicates (parallel edges between the same two
        nodes yield one path). ``guarded_by`` edges are not followed.
        """
        if max_depth < 1:
            raise ValueError(f"max_depth must be at least 1, got {max_depth}")
        for node_id in (source_id, sink_id):
            if node_id not in self._g:
                raise UnknownNodeError(node_id)
        if source_id == sink_id:
            return []

        flow: nx.DiGraph[str] = nx.DiGraph()
        flow.add_nodes_from(self._g.nodes)
        flow.add_edges_from(
            (u, v)
            for u, v, data in self._g.edges(data=True)
            if data["edge"].kind not in _NON_FLOW_EDGES
        )
        found = {tuple(p) for p in nx.all_simple_paths(flow, source_id, sink_id, cutoff=max_depth)}
        return [list(p) for p in sorted(found)]

    # -- serialisation ------------------------------------------------------------------------

    def to_fragment(self) -> GraphFragment:
        """The whole graph as one fragment, in deterministic order."""
        return GraphFragment(nodes=self.nodes(), edges=self.edges())

    def to_json(self, indent: int | None = 2) -> str:
        """Serialise the graph to JSON with a ``schema_version`` field."""
        payload = {
            "schema_version": JSON_SCHEMA_VERSION,
            **self.to_fragment().model_dump(mode="json"),
        }
        return json.dumps(payload, indent=indent, sort_keys=False, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> Graph:
        """Rebuild a graph from the output of :meth:`to_json`."""
        payload = json.loads(text)
        version = payload.pop("schema_version", None)
        if version != JSON_SCHEMA_VERSION:
            raise GraphError(f"unsupported graph schema_version {version!r}")
        graph = cls()
        graph.add_fragment(GraphFragment.model_validate(payload))
        return graph
