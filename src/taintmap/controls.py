"""Decide whether a control blocks a path, using the taxonomy.

A control is **effective** for a path when it guards a node on the path (a ``guarded_by`` edge
from that node to the control) and its category blocks the path, as set out in
:data:`taintmap.taxonomy.CONTROL_RULES`:

* ``all`` (``control.human_approval``): blocks every path.
* ``untrusted_sources`` (``control.trusted_actor_gate``): blocks paths from an untrusted source.
  A ``label`` gate blocks input from any author. An ``author_association`` gate blocks only input
  whose author it checks: every edge that carries the input from the source onto the path must
  name, in ``attrs.author_association``, one of the gate's ``attrs.checks``. A gate on the issue
  author therefore does not block a comment body, and a gate never blocks input with no known
  author (such as MCP tool results).
* ``targeted`` (``control.least_privilege``, ``control.tool_allowlist``): blocks only the sinks it
  names in ``attrs.sinks`` (node ids) or ``attrs.sink_categories``.
* ``sinks``: blocks paths ending at one of the listed sink categories. For
  ``control.input_isolation``, only code execution reached by expression injection: a sink with an
  ``expression_injection`` attribute (a workflow ``run:`` script) that is not interpolated. Input
  that is isolated in an environment variable still flows to every other sink.
"""

from __future__ import annotations

from dataclasses import dataclass

from taintmap.graph import Graph
from taintmap.model import EdgeKind, Node
from taintmap.taxonomy import (
    CONTROL_RULES,
    ControlCategory,
    Scope,
    SinkCategory,
    is_untrusted_source,
)


@dataclass(frozen=True)
class Decision:
    """Which controls guard a path and which of them block it."""

    guarding: tuple[str, ...]
    blocking: tuple[str, ...]

    @property
    def blocked(self) -> bool:
        return bool(self.blocking)


def guarding_controls(graph: Graph, path: list[str]) -> list[Node]:
    """Controls that guard any node on the path, sorted by id, without duplicates."""
    found: dict[str, Node] = {}
    for node_id in path:
        for edge in graph.out_edges(node_id):
            if edge.kind == EdgeKind.GUARDED_BY:
                found[edge.dst] = graph.node(edge.dst)
    return [found[k] for k in sorted(found)]


def evaluate(graph: Graph, path: list[str]) -> Decision:
    """Decide which controls guarding ``path`` block it."""
    if len(path) < 2:
        raise ValueError("a path needs at least a source and a sink")
    guards = guarding_controls(graph, path)
    blocking = [c.id for c in guards if blocks(graph, c, path)]
    return Decision(tuple(c.id for c in guards), tuple(blocking))


def is_blocked(graph: Graph, path: list[str]) -> bool:
    return evaluate(graph, path).blocked


def blocks(graph: Graph, control: Node, path: list[str]) -> bool:
    """Whether one control blocks a path, ignoring whether it guards the path."""
    try:
        category = ControlCategory(control.category)
    except ValueError:
        return False
    rule = CONTROL_RULES[category]
    source = graph.node(path[0])
    sink = graph.node(path[-1])

    if rule.scope is Scope.ALL:
        return True
    if rule.scope is Scope.UNTRUSTED_SOURCES:
        return is_untrusted_source(source.category) and _gate_covers(graph, control, path)
    if rule.scope is Scope.TARGETED:
        return sink.id in control.attrs.get("sinks", []) or sink.category in control.attrs.get(
            "sink_categories", []
        )
    # Scope.SINKS
    try:
        sink_category = SinkCategory(sink.category)
    except ValueError:
        return False
    if sink_category not in rule.sinks:
        return False
    if rule.via_expression_injection:
        return "expression_injection" in sink.attrs and sink.attrs["expression_injection"] is False
    return True


def _gate_covers(graph: Graph, gate: Node, path: list[str]) -> bool:
    if gate.attrs.get("gate") == "label":
        return True
    checks = set(gate.attrs.get("checks", []))
    entry = [e for e in graph.edges_between(path[0], path[1]) if e.kind != EdgeKind.GUARDED_BY]
    return bool(entry) and all(e.attrs.get("author_association") in checks for e in entry)
