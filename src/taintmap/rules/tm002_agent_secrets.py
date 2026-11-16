"""TM002: untrusted input reaches an AI agent that holds secrets."""

from __future__ import annotations

from taintmap.graph import Graph
from taintmap.model import Severity
from taintmap.paths import CandidatePath
from taintmap.rules import Rule
from taintmap.rules._common import RuleInfo, agent_path_rule, lower_first, trigger_gate_hint

INFO = RuleInfo(
    id="TM002",
    title="Untrusted input reaches an AI agent that holds secrets",
    risk_class="confidentiality",
    default_severity=Severity.HIGH,
    missing_control="control.trusted_actor_gate or control.human_approval",
)


def fix(graph: Graph, candidate: CandidatePath) -> str:
    sink = graph.node(candidate.sink)
    gate = trigger_gate_hint(graph, candidate)
    if sink.attrs.get("hardcoded"):
        key = sink.attrs.get("key", "the value")
        return (
            f"Move `{key}` out of `{sink.location.file}` into an environment reference such as "
            f"`${{{key}}}` and rotate it; then {lower_first(gate)}."
        )
    if "secret" in sink.attrs:
        return (
            f"{gate}, or stop passing `secrets.{sink.attrs['secret']}` to a step that handles "
            "untrusted input."
        )
    if sink.attrs.get("scopes") == ["id-token"]:
        return f"{gate}, or remove `id-token: write` if the job does not need cloud credentials."
    return f"{gate}, or keep secrets away from this agent."


RULE = Rule(INFO, agent_path_rule(INFO, frozenset({"sink.secret.read"}), fix))
