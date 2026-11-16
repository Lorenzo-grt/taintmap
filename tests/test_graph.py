import json

import pytest

from taintmap.graph import DuplicateNodeError, Graph, GraphError, UnknownNodeError
from taintmap.model import Edge, EdgeKind, GraphFragment, Location, Node, NodeKind


def loc(line: int = 1, file: str = "f.yml") -> Location:
    return Location(file=file, line=line)


def node(
    node_id: str,
    kind: NodeKind = NodeKind.CARRIER,
    category: str = "carrier.llm_agent",
    **attrs: object,
) -> Node:
    return Node(
        id=node_id, kind=kind, category=category, label=node_id, location=loc(), attrs=dict(attrs)
    )


def edge(src: str, dst: str, kind: EdgeKind = EdgeKind.PASSES_INPUT, line: int = 1) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, location=loc(line))


def small_graph() -> Graph:
    """src -> agent -> sink, src -> step -> agent, and agent guarded by a control."""
    g = Graph()
    g.add_fragment(
        GraphFragment(
            nodes=[
                node("src", NodeKind.SOURCE, "source.untrusted.issue_text"),
                node("agent"),
                node("step", category="carrier.workflow_step"),
                node("sink", NodeKind.SINK, "sink.repo.write"),
                node("ctl", NodeKind.CONTROL, "control.human_approval"),
            ],
            edges=[
                edge("src", "agent"),
                edge("src", "step"),
                edge("step", "agent"),
                edge("agent", "sink", EdgeKind.CAN_CALL),
                edge("agent", "ctl", EdgeKind.GUARDED_BY),
            ],
        )
    )
    return g


def test_fragments_merge_across_calls() -> None:
    g = Graph()
    g.add_fragment(GraphFragment(nodes=[node("a"), node("b")], edges=[edge("a", "b")]))
    # The second fragment refers to "b" from the first and repeats "a" identically.
    g.add_fragment(GraphFragment(nodes=[node("a"), node("c")], edges=[edge("b", "c")]))
    assert [n.id for n in g.nodes()] == ["a", "b", "c"]
    assert [(e.src, e.dst) for e in g.edges()] == [("a", "b"), ("b", "c")]
    assert len(g) == 3
    assert "a" in g and "z" not in g
    assert g.node("b").label == "b"


def test_identical_edges_are_stored_once_but_distinct_kinds_are_kept() -> None:
    g = Graph()
    frag = GraphFragment(nodes=[node("a"), node("b")], edges=[edge("a", "b"), edge("a", "b")])
    g.add_fragment(frag)
    g.add_fragment(frag)
    assert len(g.edges()) == 1
    g.add_fragment(GraphFragment(edges=[edge("a", "b", EdgeKind.INVOKES)]))
    assert len(g.edges()) == 2


def test_duplicate_id_with_different_content_raises_clear_error() -> None:
    g = Graph()
    g.add_fragment(GraphFragment(nodes=[node("a")]))
    with pytest.raises(DuplicateNodeError) as info:
        g.add_fragment(GraphFragment(nodes=[node("a", NodeKind.SINK, "sink.repo.write")]))
    message = str(info.value)
    assert "'a'" in message
    assert "f.yml:1" in message
    assert "sink.repo.write" in message


def test_duplicate_id_within_one_fragment_raises() -> None:
    with pytest.raises(DuplicateNodeError):
        Graph().add_fragment(GraphFragment(nodes=[node("a"), node("a", foo=1)]))


def test_failed_add_leaves_graph_unchanged() -> None:
    g = Graph()
    g.add_fragment(GraphFragment(nodes=[node("a")]))
    with pytest.raises(UnknownNodeError, match="'missing'"):
        g.add_fragment(GraphFragment(nodes=[node("b")], edges=[edge("b", "missing")]))
    assert [n.id for n in g.nodes()] == ["a"]
    assert g.edges() == []


def test_unknown_node_lookup_raises() -> None:
    with pytest.raises(UnknownNodeError, match="'nope'"):
        Graph().node("nope")


def test_nodes_of_kind() -> None:
    g = small_graph()
    assert [n.id for n in g.nodes_of_kind(NodeKind.CARRIER)] == ["agent", "step"]
    assert [n.id for n in g.nodes_of_kind("sink")] == ["sink"]
    assert g.nodes_of_kind(NodeKind.CODE) == []


def test_paths_returns_all_simple_paths_sorted() -> None:
    assert small_graph().paths("src", "sink") == [
        ["src", "agent", "sink"],
        ["src", "step", "agent", "sink"],
    ]


def test_paths_respects_max_depth() -> None:
    g = small_graph()
    assert g.paths("src", "sink", max_depth=2) == [["src", "agent", "sink"]]
    assert g.paths("src", "sink", max_depth=1) == []
    with pytest.raises(ValueError):
        g.paths("src", "sink", max_depth=0)


def test_paths_do_not_follow_guarded_by() -> None:
    assert small_graph().paths("src", "ctl") == []


def test_paths_ignore_cycles_and_parallel_edges() -> None:
    g = Graph()
    g.add_fragment(
        GraphFragment(
            nodes=[node("a"), node("b"), node("c")],
            edges=[
                edge("a", "b"),
                edge("a", "b", EdgeKind.INVOKES),
                edge("b", "a"),
                edge("b", "c"),
            ],
        )
    )
    assert g.paths("a", "c") == [["a", "b", "c"]]
    assert g.paths("a", "a") == []


def test_paths_unknown_ids_raise() -> None:
    with pytest.raises(UnknownNodeError):
        small_graph().paths("nope", "sink")


def test_json_round_trip() -> None:
    g = small_graph()
    text = g.to_json()
    payload = json.loads(text)
    assert payload["schema_version"] == 1
    assert [n["id"] for n in payload["nodes"]] == ["agent", "ctl", "sink", "src", "step"]
    restored = Graph.from_json(text)
    assert restored.to_json() == text
    assert restored.nodes() == g.nodes()
    assert restored.edges() == g.edges()


def test_json_output_is_deterministic_regardless_of_insertion_order() -> None:
    a, b = Graph(), Graph()
    a.add_fragment(GraphFragment(nodes=[node("x"), node("y")], edges=[edge("x", "y")]))
    b.add_fragment(GraphFragment(nodes=[node("y")]))
    b.add_fragment(GraphFragment(nodes=[node("x")], edges=[edge("x", "y")]))
    assert a.to_json() == b.to_json()


def test_from_json_rejects_unknown_schema_version() -> None:
    with pytest.raises(GraphError, match="schema_version"):
        Graph.from_json('{"schema_version": 99, "nodes": [], "edges": []}')


def test_warnings_are_not_part_of_the_graph_json() -> None:
    from taintmap.model import ParseWarning

    g = Graph()
    warning = ParseWarning(file="wf.yml", line=3, message="invalid YAML")
    g.add_fragment(GraphFragment(nodes=[node("a")], warnings=[warning]))
    assert "warnings" not in g.to_json()
    assert Graph.from_json(g.to_json()).nodes() == g.nodes()
