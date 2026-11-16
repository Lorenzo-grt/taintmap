"""Merge parser fragments into one graph and connect nodes across files.

Cross-file links:

* **AI action -> MCP config.** A workflow step running a catalogued AI action that loads MCP config
  files (``mcp_configs`` in the AI actions catalog, e.g. ``claude-code-action`` loads the
  repository's ``.mcp.json``) is connected to the servers of that config which its tool config
  allows. The step ``can_call`` each allowed server, and each of the server's untrusted source
  capabilities passes input (tool results) to the step. A server is allowed when one of the step's
  tool-config inputs mentions ``mcp__<server>``, the tool name prefix the action's docs use.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from taintmap import catalog
from taintmap.graph import Graph
from taintmap.model import Edge, EdgeKind, GraphFragment, Node, NodeKind, ParseWarning
from taintmap.taxonomy import CarrierCategory


def build_graph(fragments: Iterable[GraphFragment]) -> tuple[Graph, list[ParseWarning]]:
    """Merge fragments, add cross-file links, and collect every fragment's warnings."""
    graph = Graph()
    warnings: list[ParseWarning] = []
    for fragment in fragments:
        warnings.extend(fragment.warnings)
        graph.add_fragment(fragment.model_copy(update={"warnings": []}))
    graph.add_fragment(link(graph))
    return graph, sorted(warnings, key=lambda w: (w.file, w.line, w.message))


def link(graph: Graph) -> GraphFragment:
    """The edges that connect nodes across files."""
    return GraphFragment(edges=sorted(_link_mcp_configs(graph), key=Edge.sort_key))


def allows_server(tool_config: dict[str, str], server: str) -> bool:
    """True when a tool config mentions ``mcp__<server>`` (all its tools or one of them)."""
    pattern = re.compile(r"mcp__" + re.escape(server) + r"(?:__|(?![\w-]))")
    return any(pattern.search(value) for value in tool_config.values())


def _mcp_clients(graph: Graph) -> dict[str, Node]:
    """MCP client nodes by config file."""
    return {
        n.location.file: n
        for n in graph.nodes()
        if n.category == CarrierCategory.LLM_AGENT
        and n.id.startswith("mcp:")
        and "client" in n.attrs
    }


def _link_mcp_configs(graph: Graph) -> list[Edge]:
    clients = _mcp_clients(graph)
    actions = catalog.ai_actions()
    edges: list[Edge] = []
    for step in graph.nodes():
        if step.category != CarrierCategory.LLM_AGENT or "ai_action" not in step.attrs:
            continue
        action = actions.by_id(step.attrs["ai_action"])
        if action is None:
            continue
        tool_config: dict[str, str] = step.attrs.get("tool_config", {})
        for config in action.mcp_configs:
            client = clients.get(config)
            if client is None:
                continue
            evidence = {
                "link": "mcp_config",
                "config": config,
                "evidence": (action.mcp_configs_evidence or action.evidence).value,
                "evidence_reason": action.mcp_configs_reason or action.evidence_reason,
            }
            for edge in graph.out_edges(client.id):
                if edge.kind != EdgeKind.CAN_CALL:
                    continue
                server = graph.node(edge.dst)
                if not allows_server(tool_config, str(server.attrs.get("server", ""))):
                    continue
                edges.append(
                    Edge(
                        src=step.id,
                        dst=server.id,
                        kind=EdgeKind.CAN_CALL,
                        location=step.location,
                        attrs=evidence,
                    )
                )
                edges.extend(_tool_results(graph, client, server, step, evidence))
    return edges


def _tool_results(
    graph: Graph, client: Node, server: Node, step: Node, evidence: dict[str, str]
) -> list[Edge]:
    out = []
    for node in graph.nodes():
        if node.kind != NodeKind.SOURCE:
            continue
        for edge in graph.edges_between(node.id, client.id):
            if edge.kind == EdgeKind.PASSES_INPUT and edge.attrs.get("server") == server.id:
                out.append(
                    Edge(
                        src=node.id,
                        dst=step.id,
                        kind=EdgeKind.PASSES_INPUT,
                        location=step.location,
                        attrs={**edge.attrs, **evidence, "evidence": _weakest(edge, evidence)},
                    )
                )
    return out


def _weakest(edge: Edge, evidence: dict[str, str]) -> str:
    """``inferred`` when either the capability or the link is inferred."""
    levels = {edge.attrs.get("evidence"), evidence["evidence"]}
    return catalog.Evidence.INFERRED.value if "inferred" in levels else evidence["evidence"]
