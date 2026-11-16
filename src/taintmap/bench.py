"""The benchmark harness (docs/benchmark.md).

Each case is a directory ``<benchmark>/cases/<id>/`` with a ``case.yaml`` and the files of a
minimal example system. ``<benchmark>/splits.yaml`` assigns case ids to ``dev`` and ``test``.

A produced finding matches an expected one when the rule id is equal and both the source and
sink locations (``file:line`` of the first and last node on the finding's path) are equal. Each
expected finding can be matched once. Only findings at ``low`` severity or above are counted;
``info`` findings are notes, not claims of a vulnerability.

Metrics: recall = matched / expected; precision = matched / produced; false-positive rate on safe
cases = safe cases with at least one counted finding / safe cases. Per rule, the false-positive
rate counts safe cases with at least one finding of that rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from taintmap.model import Finding, Severity
from taintmap.scan import scan

Split = Literal["dev", "test"]


class BenchError(Exception):
    """The benchmark itself is malformed (missing split file, unknown case, bad case.yaml)."""


class _Lenient(BaseModel):
    # Unknown fields are ignored so a case written with extra notes still loads.
    model_config = ConfigDict(extra="ignore", frozen=True)


class Expected(_Lenient):
    rule: str = Field(min_length=1)
    source: str = Field(pattern=r"^.+:\d+$")
    sink: str = Field(pattern=r"^.+:\d+$")


class Case(_Lenient):
    id: str = Field(min_length=1)
    description: str = ""
    kind: Literal["vulnerable", "safe"]
    expected: list[Expected] = Field(default_factory=list)

    @model_validator(mode="after")
    def _kind_matches_expected(self) -> Case:
        if self.kind == "safe" and self.expected:
            raise ValueError("a safe case must have `expected: []`")
        if self.kind == "vulnerable" and not self.expected:
            raise ValueError("a vulnerable case needs at least one expected finding")
        return self


@dataclass(frozen=True)
class Produced:
    rule: str
    source: str
    sink: str
    severity: str
    inferred: bool

    @classmethod
    def of(cls, finding: Finding) -> Produced:
        return cls(
            rule=finding.rule_id,
            source=str(finding.evidence[0]),
            sink=str(finding.evidence[-1]),
            severity=finding.severity.value,
            inferred=finding.inferred,
        )


@dataclass
class CaseResult:
    case: Case
    matched: list[Expected] = field(default_factory=list)
    missed: list[Expected] = field(default_factory=list)
    unexpected: list[Produced] = field(default_factory=list)
    produced: list[Produced] = field(default_factory=list)


@dataclass
class RuleMetrics:
    rule: str
    expected: int = 0
    matched: int = 0
    produced: int = 0
    safe_cases_flagged: int = 0


@dataclass
class BenchResult:
    split: Split
    results: list[CaseResult]
    rules: list[str]

    @property
    def expected(self) -> int:
        return sum(len(r.case.expected) for r in self.results)

    @property
    def matched(self) -> int:
        return sum(len(r.matched) for r in self.results)

    @property
    def produced(self) -> int:
        return sum(len(r.produced) for r in self.results)

    @property
    def safe(self) -> list[CaseResult]:
        return [r for r in self.results if r.case.kind == "safe"]

    @property
    def safe_flagged(self) -> int:
        return sum(1 for r in self.safe if r.produced)

    def per_rule(self) -> list[RuleMetrics]:
        metrics = {rule: RuleMetrics(rule) for rule in self.rules}
        for result in self.results:
            for e in result.case.expected:
                metrics.setdefault(e.rule, RuleMetrics(e.rule)).expected += 1
            for e in result.matched:
                metrics[e.rule].matched += 1
            for p in result.produced:
                metrics.setdefault(p.rule, RuleMetrics(p.rule)).produced += 1
            if result.case.kind == "safe":
                for rule in {p.rule for p in result.produced}:
                    metrics[rule].safe_cases_flagged += 1
        return [metrics[k] for k in sorted(metrics)]


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


# -- loading --------------------------------------------------------------------------------------


def _yaml(path: Path) -> Any:
    try:
        return YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))
    except (OSError, YAMLError) as exc:
        raise BenchError(f"{path}: cannot read: {exc}") from None


def load_split(benchmark: Path, split: Split) -> list[str]:
    path = benchmark / "splits.yaml"
    if not path.is_file():
        raise BenchError(f"{path} not found")
    data = _yaml(path) or {}
    ids = data.get(split) or []
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        raise BenchError(f"{path}: `{split}` must be a list of case ids")
    return ids


def load_case(benchmark: Path, case_id: str) -> Case:
    path = benchmark / "cases" / case_id / "case.yaml"
    if not path.is_file():
        raise BenchError(f"case {case_id}: {path} not found")
    try:
        case = Case.model_validate(_yaml(path))
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'case'}: {e['msg']}" for e in exc.errors()
        )
        raise BenchError(f"case {case_id}: {problems}") from None
    if case.id != case_id:
        raise BenchError(f"case {case_id}: id in case.yaml is {case.id!r}")
    return case


# -- running --------------------------------------------------------------------------------------


def run_case(benchmark: Path, case: Case) -> CaseResult:
    findings = scan(benchmark / "cases" / case.id).findings
    produced = sorted(
        (Produced.of(f) for f in findings if f.severity.rank >= Severity.LOW.rank),
        key=lambda p: (p.rule, p.source, p.sink),
    )
    result = CaseResult(case=case, produced=produced)
    remaining = list(produced)
    for expected in case.expected:
        hit = next(
            (
                p
                for p in remaining
                if (p.rule, p.source, p.sink) == (expected.rule, expected.source, expected.sink)
            ),
            None,
        )
        if hit is None:
            result.missed.append(expected)
        else:
            remaining.remove(hit)
            result.matched.append(expected)
    result.unexpected = remaining
    return result


def run(benchmark: Path, split: Split, rules: list[str]) -> BenchResult:
    ids = load_split(benchmark, split)
    if len(set(ids)) != len(ids):
        raise BenchError(f"splits.yaml: duplicate case ids in `{split}`")
    other: Split = "test" if split == "dev" else "dev"
    overlap = set(ids) & set(load_split(benchmark, other))
    if overlap:
        raise BenchError(f"splits.yaml: cases in both splits: {', '.join(sorted(overlap))}")
    cases = [load_case(benchmark, case_id) for case_id in ids]
    return BenchResult(split=split, results=[run_case(benchmark, c) for c in cases], rules=rules)


# -- reporting ------------------------------------------------------------------------------------


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def render_text(result: BenchResult) -> str:
    vulnerable = len(result.results) - len(result.safe)
    lines = [
        f"taintmap benchmark: split {result.split}, {len(result.results)} cases "
        f"({vulnerable} vulnerable, {len(result.safe)} safe)",
        "",
        f"recall     {_fmt(ratio(result.matched, result.expected))}  "
        f"({result.matched}/{result.expected} expected findings matched)",
        f"precision  {_fmt(ratio(result.matched, result.produced))}  "
        f"({result.matched}/{result.produced} produced findings matched)",
        f"safe FPR   {_fmt(ratio(result.safe_flagged, len(result.safe)))}  "
        f"({result.safe_flagged}/{len(result.safe)} safe cases with a finding)",
        "",
        "rule    expected  matched  produced  recall  precision  safe FPR",
    ]
    for m in result.per_rule():
        lines.append(
            f"{m.rule:<8}{m.expected:>8}  {m.matched:>7}  {m.produced:>8}  "
            f"{_fmt(ratio(m.matched, m.expected)):>6}  {_fmt(ratio(m.matched, m.produced)):>9}  "
            f"{_fmt(ratio(m.safe_cases_flagged, len(result.safe))):>8}"
        )
    misses = [(r.case.id, e) for r in result.results for e in r.missed]
    unexpected = [(r.case.id, p) for r in result.results for p in r.unexpected]
    lines += ["", f"missed ({len(misses)})"]
    lines += [f"  {cid}  {e.rule}  {e.source} -> {e.sink}" for cid, e in misses] or ["  none"]
    lines += ["", f"unexpected ({len(unexpected)})"]
    lines += [
        f"  {cid}  {p.rule}  {p.source} -> {p.sink}  {p.severity}"
        + ("  inferred" if p.inferred else "")
        for cid, p in unexpected
    ] or ["  none"]
    return "\n".join(lines) + "\n"


def to_json(result: BenchResult) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "split": result.split,
        "cases": len(result.results),
        "safe_cases": len(result.safe),
        "recall": ratio(result.matched, result.expected),
        "precision": ratio(result.matched, result.produced),
        "safe_false_positive_rate": ratio(result.safe_flagged, len(result.safe)),
        "expected": result.expected,
        "matched": result.matched,
        "produced": result.produced,
        "rules": [
            {
                "rule": m.rule,
                "expected": m.expected,
                "matched": m.matched,
                "produced": m.produced,
                "recall": ratio(m.matched, m.expected),
                "precision": ratio(m.matched, m.produced),
                "safe_false_positive_rate": ratio(m.safe_cases_flagged, len(result.safe)),
            }
            for m in result.per_rule()
        ],
        "missed": [{"case": r.case.id, **e.model_dump()} for r in result.results for e in r.missed],
        "unexpected": [
            {"case": r.case.id, **vars(p)} for r in result.results for p in r.unexpected
        ],
    }
