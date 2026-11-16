"""TM005: untrusted input interpolated into a shell step."""

from __future__ import annotations

from taintmap.graph import Graph
from taintmap.model import Finding, Severity
from taintmap.paths import CandidatePath
from taintmap.rules import Rule
from taintmap.rules._common import RuleInfo, best_per_pair, from_untrusted, make_finding
from taintmap.taxonomy import CarrierCategory

INFO = RuleInfo(
    id="TM005",
    title="Untrusted input interpolated into a shell step",
    risk_class="execution",
    default_severity=Severity.HIGH,
    missing_control="control.input_isolation",
)


def find(graph: Graph, candidates: list[CandidatePath]) -> list[Finding]:
    matching = []
    for candidate in candidates:
        sink = graph.node(candidate.sink)
        if sink.category != "sink.code_exec" or sink.attrs.get("expression_injection") is not True:
            continue
        carriers = [graph.node(n).category for n in candidate.nodes[1:-1]]
        if from_untrusted(graph, candidate) and CarrierCategory.WORKFLOW_STEP in carriers:
            matching.append(candidate)
    return [make_finding(INFO, graph, c, fix(graph, c)) for c in best_per_pair(matching)]


def fix(graph: Graph, candidate: CandidatePath) -> str:
    step = graph.node(candidate.nodes[-2])
    contexts = step.attrs.get("untrusted_contexts", [])
    example = f"`{contexts[0]}`" if contexts else "the untrusted value"
    return (
        f"Pass {example} to the step through `env:` and use the variable in the script "
        '(for example `"$VALUE"`) instead of `${{ }}` interpolation.'
    )


RULE = Rule(INFO, find)
