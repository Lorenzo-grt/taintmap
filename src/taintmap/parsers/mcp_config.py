"""Parse MCP client configuration files into graph fragments.

Supported files and the client that loads each one:

========================== ==================
``.mcp.json``              Claude Code
``.cursor/mcp.json``       Cursor
``.vscode/mcp.json``       VS Code
``claude_desktop_config.json`` Claude Desktop
========================== ==================

Servers are read from ``mcpServers`` and from ``servers`` (the key VS Code uses). Node ids
(``M`` = ``mcp:<file>``):

* The client -> one ``carrier.llm_agent`` [``M:client``] that ``can_call`` every server.
* Each server -> ``carrier.mcp_server`` [``M:server:<name>``]. A server the MCP catalog knows
  gets one node per capability [``M:server:<name>:cap:<category>``]. ``source.untrusted.*``
  capabilities pass input straight to the client (tool results; the edge names the server in
  ``attrs.via_server``), so that a path can read through a server and then act through the same
  server. ``sink.*`` capabilities are reached from the server. Capability nodes carry the catalog's
  evidence level.
* An unknown server has ``attrs.unknown = true`` and produces an info-level note, not a finding.
* A literal, secret-looking value in a server's ``env`` or ``headers`` (not a ``${...}``
  reference) -> ``sink.secret.read`` [``M:server:<name>:env:<KEY>``] with
  ``attrs.hardcoded = true``. Only the key name is ever recorded, never the value.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from taintmap import catalog
from taintmap.catalog import McpServer
from taintmap.loaders.json_lines import JsonDocument, load_json, pointer
from taintmap.model import (
    Edge,
    EdgeKind,
    GraphFragment,
    Location,
    Node,
    NodeKind,
    ParseWarning,
)
from taintmap.taxonomy import CarrierCategory, SinkCategory

CLIENTS: dict[str, str] = {
    ".mcp.json": "Claude Code",
    ".cursor/mcp.json": "Cursor",
    ".vscode/mcp.json": "VS Code",
    "claude_desktop_config.json": "Claude Desktop",
}
SERVER_KEYS = ("mcpServers", "servers")

SINK_EDGES: dict[str, EdgeKind] = {
    SinkCategory.CODE_EXEC: EdgeKind.INVOKES,
    SinkCategory.REPO_WRITE: EdgeKind.WRITES_TO,
    SinkCategory.DATA_WRITE: EdgeKind.WRITES_TO,
    SinkCategory.DEPLOY: EdgeKind.WRITES_TO,
    SinkCategory.PAYMENT: EdgeKind.WRITES_TO,
    SinkCategory.SECRET_READ: EdgeKind.RUNS_WITH,
}

_SECRET_KEY = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH|_PAT$|^PAT_)",
    re.IGNORECASE,
)
# Well-known credential prefixes, so a literal token under an innocent key name is still caught.
_SECRET_VALUE = re.compile(
    r"^(gh[pousr]_|github_pat_|xox[abpr]-|sk-|AKIA|ASIA|glpat-|AIza)", re.IGNORECASE
)
# ``${VAR}``, ``${env:VAR}``, ``${input:id}``, ``$VAR``, ``{{ VAR }}`` and placeholders like
# ``<YOUR_TOKEN>`` are not literal secrets.
_REFERENCE = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Za-z_]\w*|\{\{[^}]+\}\}|<[^>]*>)\s*$")
_BEARER_REFERENCE = re.compile(r"^\s*(Bearer|Basic|token)\s+(\$\{[^}]+\}|\$[A-Za-z_]\w*)\s*$", re.I)


def client_for(rel_path: str) -> str | None:
    """The client that loads a config file, from its path relative to the scanned root."""
    parts = rel_path.replace("\\", "/").split("/")
    for suffix, client in CLIENTS.items():
        wanted = suffix.split("/")
        if parts[-len(wanted) :] == wanted:
            return client
    return None


def is_literal_secret(key: str, value: Any) -> bool:
    """True when an env or header entry holds a literal value that looks like a credential."""
    if not isinstance(value, str) or not value.strip():
        return False
    if _REFERENCE.match(value) or _BEARER_REFERENCE.match(value):
        return False
    return bool(_SECRET_KEY.search(key) or _SECRET_VALUE.match(value.strip()))


class McpConfigParser:
    """Parser for MCP client configuration files."""

    name = "mcp_config"

    def matches(self, path: Path) -> bool:
        return client_for(path.as_posix()) is not None

    def parse(self, path: Path, root: Path) -> GraphFragment:
        return parse_mcp_config(load_json(path, root))


def parse_mcp_config(doc: JsonDocument, client: str | None = None) -> GraphFragment:
    """Turn a loaded MCP config into a fragment. Problems become warnings on the fragment."""
    return _Config(doc, client or client_for(doc.file) or "MCP client").build()


class _Config:
    def __init__(self, doc: JsonDocument, client: str) -> None:
        self.doc = doc
        self.file = doc.file
        self.client = client
        self.base = f"mcp:{doc.file}"
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.warnings: list[ParseWarning] = list(doc.warnings)

    def line(self, *tokens: str | int) -> int:
        return self.doc.line_of(pointer(*tokens))

    def node(
        self, node_id: str, kind: NodeKind, category: str, label: str, line: int, **attrs: Any
    ) -> str:
        self.nodes[node_id] = Node(
            id=node_id,
            kind=kind,
            category=category,
            label=label,
            location=Location(file=self.file, line=line),
            attrs=attrs,
        )
        return node_id

    def edge(self, src: str, dst: str, kind: EdgeKind, line: int, **attrs: Any) -> None:
        self.edges.append(
            Edge(
                src=src,
                dst=dst,
                kind=kind,
                location=Location(file=self.file, line=line),
                attrs=attrs,
            )
        )

    def note(self, line: int, message: str, level: Literal["warning", "info"] = "warning") -> None:
        self.warnings.append(ParseWarning(file=self.file, line=line, message=message, level=level))

    def fragment(self) -> GraphFragment:
        return GraphFragment(
            nodes=sorted(self.nodes.values(), key=lambda n: n.id),
            edges=sorted({e.model_dump_json(): e for e in self.edges}.values(), key=Edge.sort_key),
            warnings=self.warnings,
        )

    def build(self) -> GraphFragment:
        data = self.doc.data
        if data is None:
            return self.fragment()
        if not isinstance(data, dict):
            self.note(1, "MCP config is not a JSON object")
            return self.fragment()

        sections = [key for key in SERVER_KEYS if key in data]
        if not sections:
            return self.fragment()
        client_id = self.node(
            f"{self.base}:client",
            NodeKind.CARRIER,
            CarrierCategory.LLM_AGENT.value,
            self.client,
            self.line(sections[0]),
            client=self.client,
        )
        for section in sections:
            servers = data[section]
            if not isinstance(servers, dict):
                self.note(self.line(section), f'"{section}" is not an object')
                continue
            for name, config in servers.items():
                self.server(client_id, section, str(name), config)
        return self.fragment()

    def server(self, client_id: str, section: str, name: str, config: Any) -> None:
        line = self.line(section, name)
        server_id = f"{self.base}:server:{name}"
        if server_id in self.nodes:
            self.note(line, f'server "{name}" is defined in more than one section')
            return
        if not isinstance(config, dict):
            self.note(line, f'server "{name}" is not an object')
            return

        command = config.get("command") if isinstance(config.get("command"), str) else None
        raw_args = config.get("args")
        args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
        url = config.get("url") if isinstance(config.get("url"), str) else None
        known = catalog.mcp_servers().find([command, *args] if command else args, url)

        attrs: dict[str, Any] = {"server": name, "section": section}
        if command:
            attrs["command"] = command
        if url:
            attrs["url"] = url
        if known:
            attrs["catalog_id"] = known.id
            attrs["source_url"] = known.source_url
            attrs["evidence"] = known.evidence.value
        else:
            attrs["unknown"] = True
            self.note(
                line,
                f'MCP server "{name}" is not in the catalog; its capabilities are unknown',
                level="info",
            )

        references: list[str] = []
        for field in ("env", "headers"):
            values = config.get(field)
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                if is_literal_secret(str(key), value):
                    self.hardcoded_secret(
                        server_id, field, str(key), self.line(section, name, field, key)
                    )
                elif (
                    isinstance(value, str)
                    and _SECRET_KEY.search(str(key))
                    and (_REFERENCE.match(value) or _BEARER_REFERENCE.match(value))
                    and not value.strip().startswith("<")
                ):
                    references.append(f"{field}.{key}")
        if references:
            attrs["credential_references"] = sorted(references)

        self.node(
            server_id, NodeKind.CARRIER, CarrierCategory.MCP_SERVER.value, name, line, **attrs
        )
        self.edge(client_id, server_id, EdgeKind.CAN_CALL, line)
        if known:
            self.capabilities(client_id, server_id, known, line)

    def capabilities(self, client_id: str, server_id: str, known: McpServer, line: int) -> None:
        for capability in known.capabilities:
            category = capability.category.value
            is_source = category.startswith("source.")
            cap_id = self.node(
                f"{server_id}:cap:{category}",
                NodeKind.SOURCE if is_source else NodeKind.SINK,
                category,
                f"{known.id}: {capability.description}",
                line,
                catalog_id=known.id,
                tools=list(capability.tools),
                source_url=known.source_url,
                evidence=capability.evidence.value,
                evidence_reason=capability.evidence_reason,
            )
            if is_source:
                self.edge(
                    cap_id,
                    client_id,
                    EdgeKind.PASSES_INPUT,
                    line,
                    via_server=server_id,
                    tool_results=True,
                    evidence=capability.evidence.value,
                )
            else:
                kind = SINK_EDGES.get(capability.category, EdgeKind.CAN_CALL)
                self.edge(server_id, cap_id, kind, line)

    def hardcoded_secret(self, server_id: str, field: str, key: str, line: int) -> None:
        secret_id = self.node(
            f"{server_id}:{field}:{key}",
            NodeKind.SINK,
            SinkCategory.SECRET_READ.value,
            f"{field}.{key} (hardcoded)",
            line,
            key=key,
            via=field,
            hardcoded=True,
        )
        self.edge(server_id, secret_id, EdgeKind.RUNS_WITH, line)
