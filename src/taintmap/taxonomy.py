"""The threat-model taxonomy in code: source, carrier, sink and control categories.

docs/threat-model.md is the reference. ``tests/test_taxonomy.py`` parses its tables and checks that
every category id, risk class and "Blocks" entry there matches this module, so the two cannot drift
silently.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SourceCategory(StrEnum):
    """Where untrusted input enters."""

    ISSUE_TEXT = "source.untrusted.issue_text"
    PR_CONTENT = "source.untrusted.pr_content"
    DISCUSSION = "source.untrusted.discussion"
    WEB_CONTENT = "source.untrusted.web_content"
    EMAIL = "source.untrusted.email"
    CHAT = "source.untrusted.chat"
    FILE_UPLOAD = "source.untrusted.file_upload"
    WEBHOOK = "source.untrusted.webhook"


UNTRUSTED_SOURCE_PREFIX = "source.untrusted."


class CarrierCategory(StrEnum):
    """What passes input along."""

    LLM_AGENT = "carrier.llm_agent"
    WORKFLOW_STEP = "carrier.workflow_step"
    MCP_SERVER = "carrier.mcp_server"
    AUTOMATION_NODE = "carrier.automation_node"


class SinkCategory(StrEnum):
    """Capabilities and sinks: what can cause harm."""

    CODE_EXEC = "sink.code_exec"
    REPO_WRITE = "sink.repo.write"
    SECRET_READ = "sink.secret.read"
    DATA_WRITE = "sink.data.write"
    DATA_READ_SENSITIVE = "sink.data.read_sensitive"
    NETWORK_OUTBOUND = "sink.network.outbound"
    DEPLOY = "sink.deploy"
    PAYMENT = "sink.payment"


class RiskClass(StrEnum):
    """The kind of harm a sink can cause."""

    EXECUTION = "execution"
    INTEGRITY = "integrity"
    CONFIDENTIALITY = "confidentiality"
    EXFILTRATION = "exfiltration"


SINK_RISK: dict[SinkCategory, RiskClass] = {
    SinkCategory.CODE_EXEC: RiskClass.EXECUTION,
    SinkCategory.REPO_WRITE: RiskClass.INTEGRITY,
    SinkCategory.SECRET_READ: RiskClass.CONFIDENTIALITY,
    SinkCategory.DATA_WRITE: RiskClass.INTEGRITY,
    SinkCategory.DATA_READ_SENSITIVE: RiskClass.CONFIDENTIALITY,
    SinkCategory.NETWORK_OUTBOUND: RiskClass.EXFILTRATION,
    SinkCategory.DEPLOY: RiskClass.INTEGRITY,
    SinkCategory.PAYMENT: RiskClass.INTEGRITY,
}


class ControlCategory(StrEnum):
    """What blocks a path."""

    HUMAN_APPROVAL = "control.human_approval"
    TRUSTED_ACTOR_GATE = "control.trusted_actor_gate"
    LEAST_PRIVILEGE = "control.least_privilege"
    TOOL_ALLOWLIST = "control.tool_allowlist"
    INPUT_ISOLATION = "control.input_isolation"
    SANDBOX = "control.sandbox"
    NETWORK_ALLOWLIST = "control.network_allowlist"


class Scope(StrEnum):
    """How far a control's protection reaches. Mirrors the "Blocks" column of the threat model."""

    ALL = "all"
    """Every path through the guarded node, whatever its sink."""

    UNTRUSTED_SOURCES = "untrusted_sources"
    """Every path through the guarded node that starts at an untrusted source."""

    TARGETED = "targeted"
    """Only the specific sink(s) the control is attached to (for example, the write scope that a
    permission set leaves out, or the tools an allow-list excludes)."""

    SINKS = "sinks"
    """Only paths ending at one of the listed sink categories."""


@dataclass(frozen=True)
class ControlRule:
    """What a control category blocks.

    ``sinks`` is set only for :attr:`Scope.SINKS`. ``via_expression_injection`` narrows the block to
    paths where input reaches the sink by ``${{ }}`` interpolation (``control.input_isolation``).
    """

    scope: Scope
    sinks: frozenset[SinkCategory] = frozenset()
    via_expression_injection: bool = False

    @property
    def risk_classes(self) -> frozenset[RiskClass]:
        """Risk classes this control can block. Targeted controls can block any of them."""
        if self.scope is Scope.SINKS:
            return frozenset(SINK_RISK[s] for s in self.sinks)
        return frozenset(RiskClass)


CONTROL_RULES: dict[ControlCategory, ControlRule] = {
    ControlCategory.HUMAN_APPROVAL: ControlRule(Scope.ALL),
    ControlCategory.TRUSTED_ACTOR_GATE: ControlRule(Scope.UNTRUSTED_SOURCES),
    ControlCategory.LEAST_PRIVILEGE: ControlRule(Scope.TARGETED),
    ControlCategory.TOOL_ALLOWLIST: ControlRule(Scope.TARGETED),
    ControlCategory.INPUT_ISOLATION: ControlRule(
        Scope.SINKS, frozenset({SinkCategory.CODE_EXEC}), via_expression_injection=True
    ),
    ControlCategory.SANDBOX: ControlRule(
        Scope.SINKS, frozenset({SinkCategory.DATA_WRITE, SinkCategory.CODE_EXEC})
    ),
    ControlCategory.NETWORK_ALLOWLIST: ControlRule(
        Scope.SINKS, frozenset({SinkCategory.NETWORK_OUTBOUND})
    ),
}


ALL_CATEGORY_IDS: frozenset[str] = frozenset(
    c.value
    for enum in (SourceCategory, CarrierCategory, SinkCategory, ControlCategory)
    for c in enum
)


def is_category(category_id: str) -> bool:
    """True when ``category_id`` is a known source, carrier, sink or control category."""
    return category_id in ALL_CATEGORY_IDS


def is_untrusted_source(category_id: str) -> bool:
    """True for every ``source.untrusted.*`` category."""
    return category_id.startswith(UNTRUSTED_SOURCE_PREFIX) and category_id in ALL_CATEGORY_IDS


def risk_class(sink: SinkCategory | str) -> RiskClass:
    """The risk class of a sink category. Raises :class:`ValueError` for an unknown id."""
    return SINK_RISK[SinkCategory(sink)]


def control_can_block(
    control: ControlCategory | str,
    sink: SinkCategory | str,
    *,
    source: SourceCategory | str | None = None,
    via_expression_injection: bool = False,
) -> bool:
    """Whether a control of this category can block a path to ``sink`` in principle.

    For :attr:`Scope.TARGETED` controls this answers whether the category *can* cover the sink; the
    caller must still check that the specific control instance covers it (see ``controls.py``).
    """
    rule = CONTROL_RULES[ControlCategory(control)]
    sink_cat = SinkCategory(sink)
    if rule.scope is Scope.UNTRUSTED_SOURCES:
        return source is None or is_untrusted_source(str(source))
    if rule.scope is Scope.SINKS:
        if sink_cat not in rule.sinks:
            return False
        return via_expression_injection or not rule.via_expression_injection
    return True
