"""Tests for cross-file linking (link.py), control evaluation (controls.py) and path search."""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from taintmap.controls import blocks, evaluate, guarding_controls, is_blocked
from taintmap.discover import discover
from taintmap.graph import Graph
from taintmap.link import allows_server, build_graph
from taintmap.loaders import parse_yaml
from taintmap.model import Edge, EdgeKind, GraphFragment, Location, Node, NodeKind, ParseWarning
from taintmap.parsers.github_actions import GithubActionsParser, parse_workflow
from taintmap.parsers.mcp_config import McpConfigParser
from taintmap.paths import candidate_paths, depends_on_inferred, describe

FIXTURES = Path(__file__).parent / "fixtures"
GHA = FIXTURES / "gha"
PARSERS = (GithubActionsParser(), McpConfigParser())


def scan(root: Path) -> Graph:
    fragments = [
        parser.parse(path, root)
        for path in discover(root)
        for parser in PARSERS
        if parser.matches(path.relative_to(root))
    ]
    graph, _ = build_graph(fragments)
    return graph


def workflow(name: str) -> tuple[Graph, str]:
    graph, _ = build_graph([GithubActionsParser().parse(GHA / name, GHA)])
    return graph, f"gha:{name}:"


def inline(text: str) -> tuple[Graph, str]:
    graph, _ = build_graph([parse_workflow(parse_yaml(text, "wf.yml"))])
    return graph, "gha:wf.yml:"


# -- build_graph and linking ----------------------------------------------------------------------

LINKED = FIXTURES / "repos" / "linked"
WF = "gha:.github/workflows/agent.yml:"
MCP = "mcp:.mcp.json:"
AGENT = WF + "job:agent:step:1"


def test_build_graph_collects_warnings() -> None:
    bad = GraphFragment(warnings=[ParseWarning(file="b.yml", line=2, message="x")])
    also = GraphFragment(warnings=[ParseWarning(file="a.yml", line=9, message="y", level="info")])
    graph, warnings = build_graph([bad, also])
    assert len(graph) == 0
    assert [w.file for w in warnings] == ["a.yml", "b.yml"]


def test_ai_action_is_linked_to_allowed_servers_of_repo_mcp_config() -> None:
    graph = scan(LINKED)
    links = [e for e in graph.edges() if e.attrs.get("link") == "mcp_config"]
    can_call = [(e.src, e.dst) for e in links if e.kind == EdgeKind.CAN_CALL]
    assert can_call == [(AGENT, MCP + "server:fetch")]
    (results,) = [e for e in links if e.kind == EdgeKind.PASSES_INPUT]
    assert results.src == MCP + "server:fetch:cap:source.untrusted.web_content"
    assert results.dst == AGENT
    assert results.attrs["evidence"] == "documented"
    assert results.location == graph.node(AGENT).location
    # github is in .mcp.json but not allowed, so the step cannot reach it.
    assert not graph.edges_between(AGENT, MCP + "server:github")


def test_linked_path_from_tool_results_to_the_workflow_token() -> None:
    graph = scan(LINKED)
    web = MCP + "server:fetch:cap:source.untrusted.web_content"
    write = WF + "job:agent:permission:sink.repo.write"
    assert graph.paths(web, write) == [[web, AGENT, write]]
    # The job's gate checks the commenter; tool results have no author, so it does not block.
    assert not is_blocked(graph, [web, AGENT, write])
    comment = WF + "on:issue_comment"
    assert is_blocked(graph, [comment, AGENT, write])


def test_unrelated_mcp_config_is_not_linked() -> None:
    graph, _ = workflow("issue_agent.yml")
    assert not [e for e in graph.edges() if e.attrs.get("link")]


@pytest.mark.parametrize(
    ("config", "server", "expected"),
    [
        ({"claude_args": '--allowedTools "mcp__fetch__fetch"'}, "fetch", True),
        ({"claude_args": "--allowedTools mcp__fetch"}, "fetch", True),
        ({"settings": '{"permissions": {"allow": ["mcp__github"]}}'}, "github", True),
        ({"claude_args": "--allowedTools mcp__fetcher__x"}, "fetch", False),
        ({"claude_args": "--allowedTools Edit"}, "fetch", False),
        ({}, "fetch", False),
    ],
)
def test_allows_server(config: dict[str, str], server: str, expected: bool) -> None:
    assert allows_server(config, server) is expected


# -- controls -------------------------------------------------------------------------------------


def test_author_association_gate_blocks_input_from_the_checked_author() -> None:
    graph, p = workflow("gates.yml")
    path = [p + "on:issue_comment", p + "job:owner_only:step:0", p + "job:owner_only:step:0:run"]
    decision = evaluate(graph, path)
    assert decision.guarding == (p + "job:owner_only:if:trusted_actor",)
    assert decision.blocked


def test_issue_author_gate_does_not_block_the_commenters_input() -> None:
    graph, p = workflow("gate_bypass.yml")
    path = [p + "on:issue_comment", p + "job:reply:step:0", p + "job:reply:step:0:run"]
    decision = evaluate(graph, path)
    assert decision.guarding == (p + "job:reply:if:trusted_actor",)
    assert not decision.blocked


def test_issue_author_gate_blocks_issue_only_input() -> None:
    graph, p = inline(
        "on: issue_comment\n"
        "jobs:\n"
        "  reply:\n"
        "    if: github.event.issue.author_association == 'OWNER'\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
    )
    path = [p + "on:issue_comment", p + "job:reply:step:0", p + "job:reply:step:0:run"]
    assert is_blocked(graph, path)


def test_label_gate_blocks() -> None:
    graph, p = workflow("gates.yml")
    gate = graph.node(p + "job:label_step:step:0:if:trusted_actor")
    path = [p + "on:issues", p + "job:label_step:step:0", p + "job:label_step:step:0:run"]
    assert blocks(graph, gate, path)


def test_declared_environment_blocks() -> None:
    graph, p = workflow("environment.yml")
    path = [p + "on:workflow_run", p + "job:deploy:step:0", p + "job:deploy:step:0:run"]
    assert evaluate(graph, path).blocking == (p + "job:deploy:environment",)


def test_input_isolation_blocks_only_expression_injection_code_exec() -> None:
    graph, p = workflow("isolation_flow.yml")
    source, step = p + "on:issues", p + "job:safe:step:0"
    run = [source, step, p + "job:safe:step:0:run"]
    secret = [source, step, p + "job:safe:step:0:env:TOKEN:secret:FAKE_TOKEN_FOR_TESTS"]
    write = [source, step, p + "job:safe:permission:sink.repo.write"]
    isolation = p + "job:safe:step:0:input_isolation"
    assert evaluate(graph, run).blocking == (isolation,)
    # The same control guards the other paths but is unrelated to their sinks.
    for path in (secret, write):
        decision = evaluate(graph, path)
        assert decision.guarding == (isolation,)
        assert not decision.blocked


def test_interpolated_run_is_not_blocked() -> None:
    graph, p = workflow("shell_injection.yml")
    path = [p + "on:issue_comment", p + "job:echo:step:0", p + "job:echo:step:0:run"]
    assert evaluate(graph, path).guarding == ()
    assert not is_blocked(graph, path)


def _hand_graph(control: Node) -> tuple[Graph, list[str], list[str]]:
    loc = Location(file="x.yml", line=1)
    nodes = [
        Node(
            id="src", kind=NodeKind.SOURCE, category="source.untrusted.chat", label="", location=loc
        ),
        Node(
            id="agent", kind=NodeKind.CARRIER, category="carrier.llm_agent", label="", location=loc
        ),
        Node(
            id="out", kind=NodeKind.SINK, category="sink.network.outbound", label="", location=loc
        ),
        Node(id="write", kind=NodeKind.SINK, category="sink.repo.write", label="", location=loc),
        control,
    ]
    edges = [
        Edge(src="src", dst="agent", kind=EdgeKind.PASSES_INPUT, location=loc),
        Edge(src="agent", dst="out", kind=EdgeKind.CAN_CALL, location=loc),
        Edge(src="agent", dst="write", kind=EdgeKind.WRITES_TO, location=loc),
        Edge(src="agent", dst=control.id, kind=EdgeKind.GUARDED_BY, location=loc),
    ]
    graph = Graph()
    graph.add_fragment(GraphFragment(nodes=nodes, edges=edges))
    return graph, ["src", "agent", "out"], ["src", "agent", "write"]


def _control(category: str, **attrs: object) -> Node:
    return Node(
        id="ctl",
        kind=NodeKind.CONTROL,
        category=category,
        label="",
        location=Location(file="x.yml", line=1),
        attrs=attrs,
    )


def test_network_allowlist_blocks_outbound_but_not_an_unrelated_sink() -> None:
    graph, outbound, write = _hand_graph(_control("control.network_allowlist"))
    assert is_blocked(graph, outbound)
    assert not is_blocked(graph, write)
    assert [c.id for c in guarding_controls(graph, write)] == ["ctl"]


def test_targeted_control_blocks_only_the_sinks_it_names() -> None:
    graph, outbound, write = _hand_graph(_control("control.tool_allowlist", sinks=["write"]))
    assert is_blocked(graph, write)
    assert not is_blocked(graph, outbound)
    graph, outbound, write = _hand_graph(
        _control("control.least_privilege", sink_categories=["sink.network.outbound"])
    )
    assert is_blocked(graph, outbound)
    assert not is_blocked(graph, write)


def test_gate_without_author_does_not_block_and_unknown_control_is_ignored() -> None:
    graph, outbound, _ = _hand_graph(
        _control("control.trusted_actor_gate", gate="author_association", checks=["x"])
    )
    assert not is_blocked(graph, outbound)
    graph, outbound, _ = _hand_graph(_control("control.made_up"))
    assert not is_blocked(graph, outbound)


def test_evaluate_needs_two_nodes() -> None:
    graph, _, _ = _hand_graph(_control("control.sandbox"))
    with pytest.raises(ValueError):
        evaluate(graph, ["src"])


# -- path search ----------------------------------------------------------------------------------


def test_candidate_paths_from_every_source_to_every_sink() -> None:
    graph, p = workflow("shell_injection.yml")
    (path,) = candidate_paths(graph)
    assert path.nodes == (p + "on:issue_comment", p + "job:echo:step:0", p + "job:echo:step:0:run")
    assert path.source == p + "on:issue_comment"
    assert path.sink == p + "job:echo:step:0:run"
    assert not path.blocked
    assert not path.inferred
    assert not path.permissions_assumed


def test_blocked_paths_are_dropped_unless_asked_for() -> None:
    graph, p = workflow("isolation_flow.yml")
    kept = {c.sink for c in candidate_paths(graph)}
    assert p + "job:safe:step:0:run" not in kept
    assert p + "job:safe:step:0:env:TOKEN:secret:FAKE_TOKEN_FOR_TESTS" in kept
    everything = candidate_paths(graph, include_blocked=True)
    (blocked,) = [c for c in everything if c.blocked]
    assert blocked.sink == p + "job:safe:step:0:run"
    assert blocked.blocked_by == (p + "job:safe:step:0:input_isolation",)


def test_paths_relying_on_inferred_claims_are_marked() -> None:
    graph, p = workflow("comment_agent_event.yml")
    (path,) = [c for c in candidate_paths(graph) if c.sink.endswith("sink.repo.write")]
    assert path.nodes[:2] == (p + "on:issue_comment", p + "job:respond:step:0")
    assert path.inferred  # the only input edge is claude-code-action's inferred reads_event
    graph, p = workflow("issue_agent.yml")
    agent_paths = [c for c in candidate_paths(graph) if p + "job:triage:step:1" in c.nodes]
    assert agent_paths and not any(c.inferred for c in agent_paths)  # prompt edge is documented


def test_mcp_capability_evidence_marks_paths() -> None:
    graph = scan(FIXTURES / "mcp" / "claude_code")
    by_sink = {c.sink: c for c in candidate_paths(graph) if c.source.endswith("issue_text")}
    assert by_sink["mcp:.mcp.json:server:github:cap:sink.repo.write"].inferred is False
    assert by_sink["mcp:.mcp.json:server:github:cap:sink.network.outbound"].inferred is True


def test_paths_through_assumed_permissions_are_marked() -> None:
    graph, _ = workflow("issue_agent.yml")
    assumed = [c for c in candidate_paths(graph) if c.sink.endswith("sink.repo.write")]
    assert assumed and all(c.permissions_assumed for c in assumed)
    graph, _ = workflow("comment_agent_event.yml")
    declared = [c for c in candidate_paths(graph) if c.sink.endswith("sink.repo.write")]
    assert declared and not any(c.permissions_assumed for c in declared)


def _ladder(rungs: int) -> Graph:
    """src -> a_i -> b -> sink for each i: ``rungs`` paths of length 3, plus a long detour."""
    loc = Location(file="x.yml", line=1)

    def n(node_id: str, kind: NodeKind, category: str) -> Node:
        return Node(id=node_id, kind=kind, category=category, label="", location=loc)

    nodes = [
        n("src", NodeKind.SOURCE, "source.untrusted.chat"),
        n("b", NodeKind.CARRIER, "carrier.llm_agent"),
        n("sink", NodeKind.SINK, "sink.code_exec"),
    ]
    edges = [Edge(src="b", dst="sink", kind=EdgeKind.INVOKES, location=loc)]
    for i in range(rungs):
        nodes.append(n(f"a{i}", NodeKind.CARRIER, "carrier.mcp_server"))
        edges.append(Edge(src="src", dst=f"a{i}", kind=EdgeKind.PASSES_INPUT, location=loc))
        edges.append(Edge(src=f"a{i}", dst="b", kind=EdgeKind.PASSES_INPUT, location=loc))
    graph = Graph()
    graph.add_fragment(GraphFragment(nodes=nodes, edges=edges))
    return graph


def test_paths_per_pair_are_capped_shortest_first() -> None:
    graph = _ladder(7)
    capped = candidate_paths(graph, max_paths_per_pair=3)
    assert [c.nodes for c in capped] == [
        ("src", "a0", "b", "sink"),
        ("src", "a1", "b", "sink"),
        ("src", "a2", "b", "sink"),
    ]
    assert len(candidate_paths(graph, max_paths_per_pair=100)) == 7
    with pytest.raises(ValueError):
        candidate_paths(graph, max_paths_per_pair=0)


def test_depth_limit() -> None:
    graph = _ladder(2)
    assert candidate_paths(graph, max_depth=2) == []
    assert len(candidate_paths(graph, max_depth=3)) == 2


def test_describe_and_depends_on_inferred_on_plain_graph() -> None:
    graph = _ladder(1)
    candidate = describe(graph, ["src", "a0", "b", "sink"])
    assert candidate.guarded_by == () and not candidate.inferred
    assert not depends_on_inferred(graph, ["src", "a0", "b", "sink"])


def test_cap_applies_after_blocked_paths_are_removed() -> None:
    """Six short paths are blocked by human approval; one longer path is open."""
    loc = Location(file="x.yml", line=1)

    def n(node_id: str, kind: NodeKind, category: str) -> Node:
        return Node(id=node_id, kind=kind, category=category, label="", location=loc)

    def e(src: str, dst: str, kind: EdgeKind = EdgeKind.PASSES_INPUT) -> Edge:
        return Edge(src=src, dst=dst, kind=kind, location=loc)

    nodes = [
        n("src", NodeKind.SOURCE, "source.untrusted.issue_text"),
        n("sink", NodeKind.SINK, "sink.repo.write"),
        n("approval", NodeKind.CONTROL, "control.human_approval"),
    ]
    edges = []
    for i in range(6):
        nodes.append(n(f"short{i}", NodeKind.CARRIER, "carrier.llm_agent"))
        edges += [
            e("src", f"short{i}"),
            e(f"short{i}", "sink", EdgeKind.WRITES_TO),
            e(f"short{i}", "approval", EdgeKind.GUARDED_BY),
        ]
    long_path = ["src", "x1", "x2", "x3", "sink"]
    for node_id in long_path[1:-1]:
        nodes.append(n(node_id, NodeKind.CARRIER, "carrier.workflow_step"))
    edges += [e(a, b) for a, b in itertools.pairwise(long_path)]
    graph = Graph()
    graph.add_fragment(GraphFragment(nodes=nodes, edges=edges))

    found = candidate_paths(graph, max_paths_per_pair=5)
    assert [c.nodes for c in found] == [tuple(long_path)]
    everything = candidate_paths(graph, max_paths_per_pair=5, include_blocked=True)
    assert len([c for c in everything if c.blocked]) == 5
    assert [c.nodes for c in everything if not c.blocked] == [tuple(long_path)]


def test_paths_name_the_mcp_server_the_content_came_through() -> None:
    graph = scan(FIXTURES / "mcp" / "claude_code")
    by_pair = {(c.source, c.sink): c for c in candidate_paths(graph)}
    issue = "mcp:.mcp.json:server:github:cap:source.untrusted.issue_text"
    web = "mcp:.mcp.json:server:fetch:cap:source.untrusted.web_content"
    write = "mcp:.mcp.json:server:github:cap:sink.repo.write"
    assert by_pair[(issue, write)].via_servers == ("mcp:.mcp.json:server:github",)
    assert by_pair[(web, write)].via_servers == ("mcp:.mcp.json:server:fetch",)
    # A linked workflow step keeps the server too.
    linked = scan(LINKED)
    (path,) = [
        c
        for c in candidate_paths(linked)
        if c.source == MCP + "server:fetch:cap:source.untrusted.web_content"
        and c.sink == WF + "job:agent:permission:sink.repo.write"
    ]
    assert path.via_servers == (MCP + "server:fetch",)
    graph, _ = workflow("shell_injection.yml")
    assert candidate_paths(graph)[0].via_servers == ()
