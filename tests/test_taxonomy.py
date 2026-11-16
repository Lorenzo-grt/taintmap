"""Keep src/taintmap/taxonomy.py and docs/threat-model.md in sync by parsing the doc's tables."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from taintmap import taxonomy
from taintmap.taxonomy import (
    CONTROL_RULES,
    SINK_RISK,
    CarrierCategory,
    ControlCategory,
    RiskClass,
    Scope,
    SinkCategory,
    SourceCategory,
    control_can_block,
)

THREAT_MODEL = Path(__file__).resolve().parents[1] / "docs" / "threat-model.md"
_CATEGORY_TOKEN = re.compile(r"`((?:source|carrier|sink|control)\.[a-z_.*]+)`")


def _sections() -> dict[str, list[list[str]]]:
    """Map each ``## `` heading to the data rows of the tables under it (cells, stripped)."""
    sections: dict[str, list[list[str]]] = {}
    current = ""
    for line in THREAT_MODEL.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = []
        elif line.startswith("|") and current:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue  # separator row
            sections[current].append(cells)
    # Drop header rows: the first row of each table names its columns.
    return {name: rows[1:] for name, rows in sections.items() if rows}


def _ids(rows: list[list[str]]) -> set[str]:
    return {row[0].strip("`") for row in rows}


SECTIONS = _sections()


def test_sources_match_doc() -> None:
    assert _ids(SECTIONS["Sources: where untrusted input enters"]) == {
        c.value for c in SourceCategory
    }


def test_carriers_match_doc() -> None:
    assert _ids(SECTIONS["Carriers: what passes input along"]) == {c.value for c in CarrierCategory}


def test_sinks_and_risk_classes_match_doc() -> None:
    rows = SECTIONS["Capabilities and sinks: what can cause harm"]
    doc = {row[0].strip("`"): row[1] for row in rows}
    assert doc == {sink.value: risk.value for sink, risk in SINK_RISK.items()}
    assert set(SINK_RISK) == set(SinkCategory)


def test_controls_and_blocks_match_doc() -> None:
    rows = SECTIONS["Controls: what blocks a path"]
    assert _ids(rows) == {c.value for c in ControlCategory}
    for row in rows:
        control = ControlCategory(row[0].strip("`"))
        blocks = row[1]
        rule = CONTROL_RULES[control]
        if blocks == "all":
            assert rule.scope is Scope.ALL, control
        elif blocks == "all from untrusted sources":
            assert rule.scope is Scope.UNTRUSTED_SOURCES, control
        elif blocks in ("the specific sink", "sinks provided by excluded tools"):
            assert rule.scope is Scope.TARGETED, control
        else:
            sinks = {SinkCategory(s) for s in _CATEGORY_TOKEN.findall(blocks)}
            assert sinks, f"cannot read the Blocks column for {control}: {blocks!r}"
            assert rule.scope is Scope.SINKS, control
            assert rule.sinks == sinks, control
            assert rule.via_expression_injection == ("expression injection" in blocks), control


def test_every_category_mentioned_in_doc_exists() -> None:
    text = THREAT_MODEL.read_text(encoding="utf-8")
    mentioned = set(_CATEGORY_TOKEN.findall(text))
    assert mentioned, "the threat model should mention category ids"
    for token in sorted(mentioned):
        if token.endswith(".*"):
            prefix = token[:-1]
            assert any(c.startswith(prefix) for c in taxonomy.ALL_CATEGORY_IDS), token
        else:
            assert taxonomy.is_category(token), f"{token} is in threat-model.md but not in code"


def test_every_control_has_a_plain_name() -> None:
    assert set(taxonomy.CONTROL_PLAIN_NAMES) == set(ControlCategory)
    assert all("control." not in n for n in taxonomy.CONTROL_PLAIN_NAMES.values())


def test_plain_controls() -> None:
    assert taxonomy.plain_controls("control.input_isolation") == (
        "passing the input through an environment variable"
    )
    assert taxonomy.plain_controls("control.trusted_actor_gate or control.human_approval") == (
        "a check that only trusted people can trigger it or human approval before it acts "
        "(e.g. a protected environment)"
    )
    assert taxonomy.plain_controls("control.unknown") == "control.unknown"


def test_every_control_has_a_rule() -> None:
    assert set(CONTROL_RULES) == set(ControlCategory)


def test_helpers() -> None:
    assert taxonomy.is_untrusted_source("source.untrusted.issue_text")
    assert not taxonomy.is_untrusted_source("source.untrusted.nope")
    assert not taxonomy.is_untrusted_source("sink.code_exec")
    assert taxonomy.risk_class("sink.network.outbound") is RiskClass.EXFILTRATION
    with pytest.raises(ValueError):
        taxonomy.risk_class("sink.unknown")


@pytest.mark.parametrize(
    ("control", "sink", "kwargs", "expected"),
    [
        ("control.human_approval", "sink.payment", {}, True),
        (
            "control.trusted_actor_gate",
            "sink.repo.write",
            {"source": "source.untrusted.chat"},
            True,
        ),
        ("control.sandbox", "sink.code_exec", {}, True),
        ("control.sandbox", "sink.repo.write", {}, False),
        ("control.network_allowlist", "sink.network.outbound", {}, True),
        ("control.network_allowlist", "sink.secret.read", {}, False),
        ("control.input_isolation", "sink.code_exec", {"via_expression_injection": True}, True),
        ("control.input_isolation", "sink.code_exec", {}, False),
        ("control.input_isolation", "sink.repo.write", {"via_expression_injection": True}, False),
        ("control.least_privilege", "sink.repo.write", {}, True),
    ],
)
def test_control_can_block(
    control: str, sink: str, kwargs: dict[str, object], expected: bool
) -> None:
    assert control_can_block(control, sink, **kwargs) is expected  # type: ignore[arg-type]


def test_risk_classes_of_controls() -> None:
    assert CONTROL_RULES[ControlCategory.SANDBOX].risk_classes == {
        RiskClass.INTEGRITY,
        RiskClass.EXECUTION,
    }
    assert CONTROL_RULES[ControlCategory.HUMAN_APPROVAL].risk_classes == set(RiskClass)
