"""Tests for the benchmark harness on small synthetic benchmarks built in a temp directory."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from taintmap import bench
from taintmap.cli import EXIT_ERROR, app

REPO = Path(__file__).resolve().parents[1]
RULES = ["TM001", "TM002", "TM003", "TM004", "TM005"]
runner = CliRunner()

SHELL = """\
on: discussion_comment
permissions: read-all
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}"
"""
SAFE_SHELL = """\
on: discussion_comment
permissions: read-all
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - env:
          BODY: ${{ github.event.comment.body }}
        run: echo "$BODY"
"""


def make_case(root: Path, case_id: str, case_yaml: str, workflow: str | None = None) -> None:
    directory = root / "cases" / case_id
    directory.mkdir(parents=True)
    (directory / "case.yaml").write_text(case_yaml, encoding="utf-8")
    if workflow is not None:
        target = directory / ".github" / "workflows" / "wf.yml"
        target.parent.mkdir(parents=True)
        target.write_text(workflow, encoding="utf-8")


def vulnerable(case_id: str, source: int = 1, sink: int = 7, rule: str = "TM005") -> str:
    return (
        f"id: {case_id}\nkind: vulnerable\nexpected:\n"
        f"  - rule: {rule}\n"
        f"    source: .github/workflows/wf.yml:{source}\n"
        f"    sink: .github/workflows/wf.yml:{sink}\n"
    )


def splits(root: Path, dev: list[str], test: list[str] | None = None) -> None:
    lines = ["dev:"] + [f"  - {c}" for c in dev] or ["dev: []"]
    lines += ["test:"] + [f"  - {c}" for c in (test or [])] if test else ["test: []"]
    (root / "splits.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def small(tmp_path: Path) -> Path:
    make_case(tmp_path, "hit", vulnerable("hit"), SHELL)
    make_case(tmp_path, "wrong-line", vulnerable("wrong-line", sink=6), SHELL)
    make_case(tmp_path, "safe-ok", "id: safe-ok\nkind: safe\nexpected: []\n", SAFE_SHELL)
    make_case(tmp_path, "safe-flagged", "id: safe-flagged\nkind: safe\nexpected: []\n", SHELL)
    make_case(tmp_path, "held-out", vulnerable("held-out"), SHELL)
    splits(tmp_path, ["hit", "wrong-line", "safe-ok", "safe-flagged"], ["held-out"])
    return tmp_path


def test_matching_and_metrics(small: Path) -> None:
    result = bench.run(small, "dev", RULES)
    assert result.expected == 2
    assert result.matched == 1
    assert result.produced == 3
    assert result.safe_flagged == 1
    by_id = {r.case.id: r for r in result.results}
    assert by_id["hit"].matched and not by_id["hit"].unexpected
    # Same rule and source but a different sink line is a miss plus an unexpected finding.
    assert [e.sink for e in by_id["wrong-line"].missed] == [".github/workflows/wf.yml:6"]
    assert [p.sink for p in by_id["wrong-line"].unexpected] == [".github/workflows/wf.yml:7"]
    tm005 = next(m for m in result.per_rule() if m.rule == "TM005")
    assert (tm005.expected, tm005.matched, tm005.produced, tm005.safe_cases_flagged) == (2, 1, 3, 1)
    data = bench.to_json(result)
    assert data["recall"] == 0.5
    assert data["precision"] == pytest.approx(1 / 3)
    assert data["safe_false_positive_rate"] == 0.5
    text = bench.render_text(result)
    assert "missed (1)" in text and "unexpected (2)" in text
    assert "wrong-line  TM005  .github/workflows/wf.yml:1 -> .github/workflows/wf.yml:6" in text


def test_each_expected_finding_matches_once(tmp_path: Path) -> None:
    twice = vulnerable("twice") + (
        "  - rule: TM005\n"
        "    source: .github/workflows/wf.yml:1\n"
        "    sink: .github/workflows/wf.yml:7\n"
    )
    make_case(tmp_path, "twice", twice, SHELL)
    splits(tmp_path, ["twice"])
    (result,) = bench.run(tmp_path, "dev", RULES).results
    assert len(result.matched) == 1 and len(result.missed) == 1


def test_empty_split_reports_n_a(tmp_path: Path) -> None:
    splits(tmp_path, [])
    result = bench.run(tmp_path, "dev", RULES)
    assert "recall     n/a" in bench.render_text(result)


@pytest.mark.parametrize(
    ("case_yaml", "message"),
    [
        (
            "id: bad\nkind: safe\nexpected:\n  - {rule: TM005, source: a:1, sink: a:2}\n",
            "safe case",
        ),
        ("id: bad\nkind: vulnerable\nexpected: []\n", "at least one expected"),
        ("id: bad\nkind: maybe\n", "kind"),
        ("id: other\nkind: safe\n", "id in case.yaml"),
        (
            "id: bad\nkind: vulnerable\nexpected:\n  - {rule: TM005, source: a, sink: a:2}\n",
            "source",
        ),
        ("id: [bad\n", "cannot read"),
    ],
)
def test_malformed_cases_are_errors(tmp_path: Path, case_yaml: str, message: str) -> None:
    make_case(tmp_path, "bad", case_yaml)
    splits(tmp_path, ["bad"])
    with pytest.raises(bench.BenchError, match=message):
        bench.run(tmp_path, "dev", RULES)


def test_unknown_case_fields_are_ignored(tmp_path: Path) -> None:
    make_case(tmp_path, "extra", "id: extra\nkind: safe\nexpected: []\nnotes: anything\n")
    splits(tmp_path, ["extra"])
    assert bench.run(tmp_path, "dev", RULES).results[0].case.id == "extra"


def test_split_problems(tmp_path: Path) -> None:
    with pytest.raises(bench.BenchError, match="not found"):
        bench.run(tmp_path, "dev", RULES)
    splits(tmp_path, ["missing"])
    with pytest.raises(bench.BenchError, match="missing"):
        bench.run(tmp_path, "dev", RULES)
    make_case(tmp_path, "both", "id: both\nkind: safe\n")
    splits(tmp_path, ["both"], ["both"])
    with pytest.raises(bench.BenchError, match="both splits"):
        bench.run(tmp_path, "dev", RULES)


# -- CLI ------------------------------------------------------------------------------------------


def test_cli_dev_split(small: Path, tmp_path: Path) -> None:
    result = runner.invoke(app, ["bench", "--benchmark", str(small)])
    assert result.exit_code == 0
    assert "split dev, 4 cases (2 vulnerable, 2 safe)" in result.output
    out = tmp_path / "out" / "bench.json"
    runner.invoke(app, ["bench", "--benchmark", str(small), "--format", "json", "-o", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["split"] == "dev"


def test_cli_test_split_requires_final(small: Path) -> None:
    refused = runner.invoke(app, ["bench", "--benchmark", str(small), "--split", "test"])
    assert refused.exit_code == EXIT_ERROR
    assert "--final" in refused.output
    allowed = runner.invoke(app, ["bench", "--benchmark", str(small), "--split", "test", "--final"])
    assert allowed.exit_code == 0
    assert "split test, 1 cases" in allowed.output


def test_cli_reports_benchmark_errors(tmp_path: Path) -> None:
    result = runner.invoke(app, ["bench", "--benchmark", str(tmp_path)])
    assert result.exit_code == EXIT_ERROR
    assert "splits.yaml" in result.output


# -- the repository's own benchmark ---------------------------------------------------------------


def test_repository_dev_split_is_well_formed() -> None:
    """Every rule has at least two vulnerable and two safe dev cases, and nothing overlaps."""
    root = REPO / "benchmark"
    dev = bench.load_split(root, "dev")
    test = bench.load_split(root, "test")
    assert not set(dev) & set(test)
    cases = [bench.load_case(root, c) for c in dev]
    for rule in RULES:
        prefix = rule.lower() + "-"
        assert sum(c.kind == "vulnerable" for c in cases if c.id.startswith(prefix)) >= 2, rule
        assert sum(c.kind == "safe" for c in cases if c.id.startswith(prefix)) >= 2, rule


def test_saved_dev_results_are_current() -> None:
    """results/ holds the dev run; regenerate it with the commands in CONTRIBUTING.md."""
    result = bench.run(REPO / "benchmark", "dev", RULES)
    saved = (REPO / "results" / "bench-dev.txt").read_text(encoding="utf-8")
    assert bench.render_text(result) == saved
