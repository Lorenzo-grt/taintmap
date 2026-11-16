"""TM001: untrusted input reaches an AI agent with write access."""

from __future__ import annotations

from taintmap.graph import Graph
from taintmap.model import Severity
from taintmap.paths import CandidatePath
from taintmap.rules import Rule
from taintmap.rules._common import RuleInfo, agent_path_rule, server_before, trigger_gate_hint

INFO = RuleInfo(
    id="TM001",
    title="Untrusted input reaches an AI agent with write access",
    risk_class="integrity",
    default_severity=Severity.HIGH,
    missing_control="control.trusted_actor_gate, control.least_privilege or control.human_approval",
)


def fix(graph: Graph, candidate: CandidatePath) -> str:
    sink = graph.node(candidate.sink)
    gate = trigger_gate_hint(graph, candidate)
    scopes = sink.attrs.get("scopes")
    if sink.attrs.get("permissions_assumed"):
        return f"{gate}, and grant the job only the write scopes the agent needs."
    if scopes:
        listed = ", ".join(f"`{s}: write`" for s in scopes)
        return (
            f"{gate}, or remove {listed} from the job's `permissions:` "
            "if the agent does not need it."
        )
    server = server_before(graph, candidate)
    if server is not None:
        return (
            f"{gate}, or remove the write tools of MCP server `{server}` from this agent "
            "or require approval for them."
        )
    return f"{gate}, or remove the agent's write access."


RULE = Rule(INFO, agent_path_rule(INFO, frozenset({"sink.repo.write", "sink.data.write"}), fix))
