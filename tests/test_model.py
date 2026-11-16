import pytest
from pydantic import ValidationError

from taintmap.model import (
    Edge,
    EdgeKind,
    Finding,
    Location,
    Node,
    NodeKind,
    Severity,
    compute_fingerprint,
)


def test_location_normalises_windows_separators() -> None:
    loc = Location(file=".github\\workflows\\ci.yml", line=3)
    assert loc.file == ".github/workflows/ci.yml"
    assert str(loc) == ".github/workflows/ci.yml:3"


def test_location_line_is_one_based() -> None:
    with pytest.raises(ValidationError):
        Location(file="a.yml", line=0)


def test_location_end_line_not_before_line() -> None:
    with pytest.raises(ValidationError):
        Location(file="a.yml", line=5, end_line=4)


def test_location_snippet_is_one_trimmed_line() -> None:
    loc = Location(file="a.yml", line=1, snippet="  run: echo hi  \n  more\n")
    assert loc.snippet == "run: echo hi"


def test_enums_have_documented_values() -> None:
    assert {k.value for k in NodeKind} == {
        "source",
        "carrier",
        "capability",
        "code",
        "sink",
        "control",
    }
    assert {k.value for k in EdgeKind} == {
        "passes_input",
        "can_call",
        "runs_with",
        "invokes",
        "writes_to",
        "guarded_by",
    }
    assert [s.rank for s in Severity] == [0, 1, 2, 3]


def test_node_rejects_unknown_kind_and_extra_fields() -> None:
    loc = Location(file="a.yml", line=1)
    with pytest.raises(ValidationError):
        Node.model_validate(
            {"id": "n", "kind": "nope", "category": "x", "label": "x", "location": loc}
        )
    with pytest.raises(ValidationError):
        Node.model_validate(
            {"id": "n", "kind": "source", "category": "x", "label": "x", "location": loc, "x": 1}
        )


def test_edge_accepts_kind_as_string() -> None:
    e = Edge.model_validate(
        {"src": "a", "dst": "b", "kind": "passes_input", "location": {"file": "a", "line": 1}}
    )
    assert e.kind is EdgeKind.PASSES_INPUT


def _finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "rule_id": "TM001",
        "severity": "high",
        "title": "t",
        "path": ["a", "b"],
        "evidence": [Location(file="a", line=1), Location(file="b", line=2)],
        "missing_control": "control.human_approval",
        "fix": "Require approval.",
    }
    data.update(overrides)
    return Finding.model_validate(data)


def test_finding_fingerprint_is_stable_and_computed() -> None:
    f1 = _finding()
    f2 = _finding(title="different title", fix="other")
    assert f1.fingerprint == f2.fingerprint == compute_fingerprint("TM001", ["a", "b"])
    assert len(f1.fingerprint) == 32


def test_finding_fingerprint_depends_on_rule_and_path() -> None:
    base = _finding().fingerprint
    assert _finding(rule_id="TM002").fingerprint != base
    assert _finding(path=["b", "a"]).fingerprint != base
    # Joining ids must not be ambiguous.
    assert compute_fingerprint("R", ["ab", "c"]) != compute_fingerprint("R", ["a", "bc"])


def test_finding_rejects_wrong_fingerprint() -> None:
    with pytest.raises(ValidationError):
        _finding(fingerprint="0" * 32)


def test_finding_json_round_trip() -> None:
    f = _finding()
    assert Finding.model_validate_json(f.model_dump_json()) == f
