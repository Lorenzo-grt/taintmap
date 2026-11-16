from __future__ import annotations

from pathlib import Path

import pytest

from taintmap.graph import Graph
from taintmap.loaders import parse_json
from taintmap.model import EdgeKind, GraphFragment, Node, NodeKind
from taintmap.parsers import Parser
from taintmap.parsers.mcp_config import (
    McpConfigParser,
    client_for,
    is_literal_secret,
    parse_mcp_config,
)

FIXTURES = Path(__file__).parent / "fixtures" / "mcp"
CASES = {
    "claude_code": ".mcp.json",
    "cursor": ".cursor/mcp.json",
    "vscode": ".vscode/mcp.json",
    "desktop": "claude_desktop_config.json",
    "broken": ".mcp.json",
}


class Parsed:
    def __init__(self, case: str) -> None:
        root = FIXTURES / case
        self.rel = CASES[case]
        self.prefix = f"mcp:{self.rel}:"
        self.fragment: GraphFragment = McpConfigParser().parse(root / self.rel, root)
        self.graph = Graph()
        self.graph.add_fragment(self.fragment)

    def id(self, suffix: str) -> str:
        return self.prefix + suffix

    def node(self, suffix: str) -> Node:
        return self.graph.node(self.id(suffix))

    def has(self, suffix: str) -> bool:
        return self.id(suffix) in self.graph

    def edge_kinds(self, src: str, dst: str) -> list[EdgeKind]:
        return sorted(
            e.kind for e in self.fragment.edges if e.src == self.id(src) and e.dst == self.id(dst)
        )


def test_parser_protocol_and_matching() -> None:
    parser = McpConfigParser()
    assert isinstance(parser, Parser)
    assert parser.name == "mcp_config"
    for path in (
        "repo/.mcp.json",
        ".cursor/mcp.json",
        "repo/.vscode/mcp.json",
        "claude_desktop_config.json",
    ):
        assert parser.matches(Path(path)), path
    assert not parser.matches(Path("repo/mcp.json"))
    assert not parser.matches(Path("repo/.cursor/settings.json"))


@pytest.mark.parametrize(
    ("rel", "client"),
    [
        (".mcp.json", "Claude Code"),
        ("sub/.cursor/mcp.json", "Cursor"),
        (".vscode/mcp.json", "VS Code"),
        ("claude_desktop_config.json", "Claude Desktop"),
        ("other.json", None),
    ],
)
def test_client_for(rel: str, client: str | None) -> None:
    assert client_for(rel) == client


@pytest.mark.parametrize("case", sorted(CASES))
def test_every_node_and_edge_has_a_line(case: str) -> None:
    p = Parsed(case)
    for item in [*p.fragment.nodes, *p.fragment.edges]:
        assert item.location.file == p.rel
        assert item.location.line >= 1


@pytest.mark.parametrize(
    ("case", "client", "servers"),
    [
        ("claude_code", "Claude Code", ["fetch", "github", "internal-tools"]),
        ("cursor", "Cursor", ["files"]),
        ("vscode", "VS Code", ["browser", "github"]),
        ("desktop", "Claude Desktop", ["github", "slack"]),
    ],
)
def test_each_format_gives_one_client_connected_to_all_servers(
    case: str, client: str, servers: list[str]
) -> None:
    p = Parsed(case)
    agent = p.node("client")
    assert agent.kind is NodeKind.CARRIER
    assert agent.category == "carrier.llm_agent"
    assert agent.label == client
    found = sorted(n.attrs["server"] for n in p.graph.nodes() if n.category == "carrier.mcp_server")
    assert found == servers
    for server in servers:
        assert p.edge_kinds("client", f"server:{server}") == [EdgeKind.CAN_CALL]
    assert len([n for n in p.graph.nodes() if n.category == "carrier.llm_agent"]) == 1


def test_server_lines() -> None:
    p = Parsed("claude_code")
    assert p.node("client").location.line == 2
    assert p.node("server:github").location.line == 3
    assert p.node("server:fetch").location.line == 10


def test_vscode_servers_key_and_remote_url() -> None:
    p = Parsed("vscode")
    github = p.node("server:github")
    assert github.attrs["section"] == "servers"
    assert github.attrs["catalog_id"] == "github"
    assert github.attrs["url"] == "https://api.githubcopilot.com/mcp/"
    assert p.node("server:browser").attrs["catalog_id"] == "playwright"


def test_catalogued_capabilities_become_sources_and_sinks() -> None:
    p = Parsed("claude_code")
    issue = p.node("server:github:cap:source.untrusted.issue_text")
    assert issue.kind is NodeKind.SOURCE
    assert issue.attrs["tools"]
    assert issue.attrs["evidence"] == "documented"
    write = p.node("server:github:cap:sink.repo.write")
    assert write.kind is NodeKind.SINK
    assert p.edge_kinds("server:github", "server:github:cap:sink.repo.write") == [
        EdgeKind.WRITES_TO
    ]
    assert p.node("server:github:cap:sink.network.outbound").attrs["evidence"] == "inferred"
    # Tool results reach the client directly, naming the server.
    (edge,) = [
        e
        for e in p.fragment.edges
        if e.src == p.id("server:github:cap:source.untrusted.issue_text")
    ]
    assert edge.dst == p.id("client")
    assert edge.attrs["via_server"] == p.id("server:github")


def test_read_and_write_through_the_same_server() -> None:
    p = Parsed("claude_code")
    source = p.id("server:github:cap:source.untrusted.issue_text")
    sink = p.id("server:github:cap:sink.repo.write")
    assert p.graph.paths(source, sink) == [[source, p.id("client"), p.id("server:github"), sink]]
    web = p.id("server:fetch:cap:source.untrusted.web_content")
    assert [web, p.id("client"), p.id("server:github"), sink] in p.graph.paths(web, sink)


def test_docker_image_match() -> None:
    p = Parsed("desktop")
    assert p.node("server:github").attrs["catalog_id"] == "github"


def test_unknown_server_is_a_node_and_an_info_note_not_a_finding() -> None:
    p = Parsed("claude_code")
    server = p.node("server:internal-tools")
    assert server.attrs["unknown"] is True
    assert not [n for n in p.graph.nodes() if n.id.startswith(p.id("server:internal-tools:"))]
    (note,) = p.fragment.warnings
    assert note.level == "info"
    assert "internal-tools" in note.message
    assert note.line == 14


def test_hardcoded_secrets_record_only_the_key() -> None:
    p = Parsed("cursor")
    secrets = sorted(n.id for n in p.graph.nodes() if n.category == "sink.secret.read")
    assert secrets == [p.id("server:files:env:SERVICE_API_KEY"), p.id("server:files:env:UPSTREAM")]
    secret = p.node("server:files:env:SERVICE_API_KEY")
    assert secret.attrs == {"key": "SERVICE_API_KEY", "via": "env", "hardcoded": True}
    assert secret.location.line == 7
    assert p.edge_kinds("server:files", "server:files:env:SERVICE_API_KEY") == [EdgeKind.RUNS_WITH]
    # The value never appears anywhere in the fragment.
    dumped = p.fragment.model_dump_json()
    assert "FAKE_TOKEN_FOR_TESTS" not in dumped
    assert "ghp_" not in dumped


def test_references_are_not_hardcoded() -> None:
    p = Parsed("claude_code")
    assert not [n for n in p.graph.nodes() if n.category == "sink.secret.read"]
    assert p.node("server:github").attrs["credential_references"] == [
        "env.GITHUB_PERSONAL_ACCESS_TOKEN"
    ]
    vscode = Parsed("vscode")
    assert not [n for n in vscode.graph.nodes() if n.category == "sink.secret.read"]
    assert vscode.node("server:github").attrs["credential_references"] == ["headers.Authorization"]
    desktop = Parsed("desktop")
    assert desktop.has("server:github:env:GITHUB_PERSONAL_ACCESS_TOKEN")
    assert not desktop.has("server:slack:env:SLACK_BOT_TOKEN")
    assert not desktop.has("server:slack:env:SLACK_TEAM_ID")


def test_hardcoded_secret_path_from_agent() -> None:
    p = Parsed("desktop")
    issue = p.id("server:github:cap:source.untrusted.issue_text")
    secret = p.id("server:github:env:GITHUB_PERSONAL_ACCESS_TOKEN")
    assert p.graph.paths(issue, secret) == [[issue, p.id("client"), p.id("server:github"), secret]]


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("API_KEY", "FAKE_TOKEN_FOR_TESTS", True),
        ("GITHUB_PERSONAL_ACCESS_TOKEN", "FAKE_TOKEN_FOR_TESTS", True),
        ("Authorization", "Bearer FAKE_TOKEN_FOR_TESTS", True),
        ("UPSTREAM", "ghp_FAKE_TOKEN_FOR_TESTS", True),
        ("UPSTREAM", "xoxb-FAKE", True),
        ("API_KEY", "${API_KEY}", False),
        ("API_KEY", "${env:API_KEY}", False),
        ("API_KEY", "${input:api_key}", False),
        ("API_KEY", "$API_KEY", False),
        ("Authorization", "Bearer ${input:token}", False),
        ("API_KEY", "<YOUR_KEY>", False),
        ("API_KEY", "", False),
        ("LOG_LEVEL", "debug", False),
        ("TOKEN", 123, False),
    ],
)
def test_is_literal_secret(key: str, value: object, expected: bool) -> None:
    assert is_literal_secret(key, value) is expected


def test_malformed_config_warns() -> None:
    p = Parsed("broken")
    assert p.fragment.nodes == []
    (warning,) = p.fragment.warnings
    assert warning.level == "warning"
    assert warning.line == 3


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[]", "MCP config is not a JSON object"),
        ('{"mcpServers": []}', '"mcpServers" is not an object'),
        ('{"mcpServers": {"a": 1}}', 'server "a" is not an object'),
        (
            '{"mcpServers": {"a": {"command": "x"}}, "servers": {"a": {"command": "x"}}}',
            'server "a" is defined in more than one section',
        ),
    ],
)
def test_unexpected_shapes_warn(text: str, message: str) -> None:
    fragment = parse_mcp_config(parse_json(text, ".mcp.json"))
    assert any(message in w.message for w in fragment.warnings), fragment.warnings
    Graph().add_fragment(fragment)


def test_config_without_servers_has_no_client() -> None:
    assert parse_mcp_config(parse_json('{"other": 1}', ".mcp.json")).nodes == []
