"""TM003: untrusted input reaches an AI agent that can run commands."""

from __future__ import annotations

from taintmap.graph import Graph
from taintmap.model import Severity
from taintmap.paths import CandidatePath
from taintmap.rules import Rule
from taintmap.rules._common import (
    RuleInfo,
    agent_path_rule,
    lower_first,
    server_before,
    trigger_gate_hint,
)

INFO = RuleInfo(
    id="TM003",
    title="Untrusted input reaches an AI agent that can run commands",
    risk_class="execution",
    default_severity=Severity.CRITICAL,
    missing_control="control.trusted_actor_gate, control.tool_allowlist or control.sandbox",
)


def fix(graph: Graph, candidate: CandidatePath) -> str:
    sink = graph.node(candidate.sink)
    gate = trigger_gate_hint(graph, candidate)
    tool = sink.attrs.get("via_tool")
    if tool:
        return f"Remove `{tool}` from the agent's allowed tools, or {lower_first(gate)}."
    server = server_before(graph, candidate)
    if server is not None:
        return f"{gate}, or remove the command tools of MCP server `{server}` from this agent."
    return f"{gate}, or stop the agent from running commands."


RULE = Rule(INFO, agent_path_rule(INFO, frozenset({"sink.code_exec"}), fix))
