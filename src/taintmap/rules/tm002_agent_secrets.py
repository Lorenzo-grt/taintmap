"""TM002: untrusted input reaches an AI agent that holds secrets.

An AI action's own model credential (``model_credential_inputs`` in the AI actions catalog, such as
``anthropic_api_key``) is needed for the agent to work at all, and an agent that can neither run
commands nor reach the network has no way to leak it. Such a finding is ``high`` only when the same
untrusted input, through the same agent, also reaches ``sink.code_exec`` or
``sink.network.outbound``; otherwise it is ``info``. Every other secret stays ``high``.

A model-credential finding raised to ``high`` is marked inferred: that untrusted input can make the
agent use its tools to leak its own key is taintmap's judgement, not something a source states.
"""

from __future__ import annotations

from taintmap.graph import Graph
from taintmap.model import Finding, Severity
from taintmap.paths import CandidatePath
from taintmap.rules import Rule
from taintmap.rules._common import (
    RuleInfo,
    agents_on,
    best_per_pair,
    from_untrusted,
    lower_first,
    make_finding,
    trigger_gate_hint,
)

INFO = RuleInfo(
    id="TM002",
    title="Untrusted input reaches an AI agent that holds secrets",
    risk_class="confidentiality",
    default_severity=Severity.HIGH,
    missing_control="control.trusted_actor_gate or control.human_approval",
)

RAISED_REASON = (
    "Rated high because the agent can also {channels}; that untrusted input can make it leak its "
    "own model credential this way is taintmap's judgement."
)

LEAK_CHANNELS = {"sink.code_exec": "run commands", "sink.network.outbound": "send data out"}


def find(graph: Graph, candidates: list[CandidatePath]) -> list[Finding]:
    channels = _leak_channels(graph, candidates)
    findings = []
    for candidate in best_per_pair(candidates):
        sink = graph.node(candidate.sink)
        agents = agents_on(graph, candidate)
        if (
            sink.category != "sink.secret.read"
            or not agents
            or not from_untrusted(graph, candidate)
        ):
            continue
        reasons: list[str] = []
        if sink.attrs.get("model_credential"):
            can = channels.get((candidate.source, agents[-1].id), [])
            severity = Severity.HIGH if can else Severity.INFO
            text = _model_credential_fix(graph, candidate, can)
            if can:
                reasons.append(RAISED_REASON.format(channels=" and ".join(can)))
        else:
            severity = INFO.default_severity
            text = fix(graph, candidate)
        findings.append(
            make_finding(
                INFO,
                graph,
                candidate,
                text,
                severity=severity,
                inferred=candidate.inferred or bool(reasons),
                inferred_reasons=reasons,
            )
        )
    return findings


def _leak_channels(
    graph: Graph, candidates: list[CandidatePath]
) -> dict[tuple[str, str], list[str]]:
    """What each (source, agent) pair can do to leak a secret: run commands, send data out."""
    out: dict[tuple[str, str], list[str]] = {}
    for candidate in candidates:
        channel = LEAK_CHANNELS.get(graph.node(candidate.sink).category)
        agents = agents_on(graph, candidate)
        if channel and agents:
            found = out.setdefault((candidate.source, agents[-1].id), [])
            if channel not in found:
                found.append(channel)
    return {k: sorted(v) for k, v in out.items()}


def _model_credential_fix(graph: Graph, candidate: CandidatePath, channels: list[str]) -> str:
    sink = graph.node(candidate.sink)
    key = str(sink.attrs.get("via", "the model credential")).removeprefix("with.")
    gate = trigger_gate_hint(graph, candidate)
    if not channels:
        return (
            f"The agent holds its own model credential `{key}` but can neither run commands nor "
            "reach the network, so it has no way to leak it. Keep it that way; to be stricter, "
            f"{lower_first(gate)}."
        )
    return (
        f"The agent holds its model credential `{key}` and can {' and '.join(channels)}, so "
        f"untrusted input could make it leak the key. {gate}, or take those tools away."
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


RULE = Rule(INFO, find)
