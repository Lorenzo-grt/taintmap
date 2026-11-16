"""TM004: one agent combines untrusted content, sensitive access and outbound network.

For each LLM agent and each untrusted source that reaches it, the rule looks for unblocked paths
from that source through the agent to a sensitive sink (``sink.data.read_sensitive`` or
``sink.secret.read``) and to ``sink.network.outbound``. The finding's path ends at the outbound
sink; the sensitive sinks are listed in ``related``. One finding is reported per agent and source.
The agent is the last LLM agent on the path, the one that holds the tools.
"""

from __future__ import annotations

from taintmap.graph import Graph
from taintmap.model import Finding, Severity
from taintmap.paths import CandidatePath
from taintmap.rules import Rule
from taintmap.rules._common import RuleInfo, agents_on, best_per_pair, from_untrusted, make_finding

INFO = RuleInfo(
    id="TM004",
    title="Agent combines untrusted content, sensitive access and outbound network",
    risk_class="exfiltration",
    default_severity=Severity.CRITICAL,
    missing_control="control.network_allowlist, control.tool_allowlist or control.human_approval",
)

SENSITIVE = frozenset({"sink.data.read_sensitive", "sink.secret.read"})
OUTBOUND = "sink.network.outbound"


def find(graph: Graph, candidates: list[CandidatePath]) -> list[Finding]:
    groups: dict[tuple[str, str], tuple[list[CandidatePath], list[CandidatePath]]] = {}
    for candidate in best_per_pair(candidates):
        if not from_untrusted(graph, candidate):
            continue
        agents = agents_on(graph, candidate)
        if not agents:
            continue
        category = graph.node(candidate.sink).category
        sensitive, outbound = groups.setdefault((agents[-1].id, candidate.source), ([], []))
        if category in SENSITIVE:
            sensitive.append(candidate)
        elif category == OUTBOUND:
            outbound.append(candidate)

    findings = []
    for (agent_id, _source), (sensitive, outbound) in sorted(groups.items()):
        if not sensitive or not outbound:
            continue
        chosen = min(outbound, key=lambda c: (c.inferred, len(c.nodes), c.nodes))
        related = sorted({c.sink for c in sensitive})
        inferred = chosen.inferred or all(c.inferred for c in sensitive)
        labels = ", ".join(f"`{graph.node(n).label}`" for n in related)
        fix = (
            f"Break the combination for agent `{graph.node(agent_id).label}`: keep untrusted "
            f"content away from it, remove its sensitive access ({labels}), or limit its outbound "
            "requests to named hosts."
        )
        findings.append(make_finding(INFO, graph, chosen, fix, related=related, inferred=inferred))
    return findings


RULE = Rule(INFO, find)
