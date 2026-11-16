from __future__ import annotations

import json
import os
from importlib.metadata import version
from pathlib import Path

import pytest
from typer.testing import CliRunner

from taintmap.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app

runner = CliRunner()
REPOS = Path(__file__).parent / "fixtures" / "repos"
DEMO = REPOS / "demo"
SNAPSHOT = Path(__file__).parent / "snapshots" / "demo_scan.json"


def scan(*args: str) -> tuple[int, str]:
    result = runner.invoke(app, ["scan", *args])
    return result.exit_code, result.output


def scan_json(*args: str) -> tuple[int, dict]:  # type: ignore[type-arg]
    code, output = scan(*args, "--format", "json")
    return code, json.loads(output)


def test_version_prints_package_metadata_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == version("taintmap")


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "version" in result.output
    assert "scan" in result.output


# -- terminal report ------------------------------------------------------------------------------


def test_terminal_report_end_to_end() -> None:
    code, output = scan(str(DEMO))
    assert code == EXIT_FINDINGS
    # Findings are grouped by source and agent, most severe group first.
    headings = [line for line in output.splitlines() if line.startswith("== ")]
    assert headings == [
        "== on: pull_request_target (.github/workflows/greet.yml:2) -> no AI agent"
        "  [1 finding, highest HIGH]",
        "== on: issue_comment (.github/workflows/respond.yml:2) -> agent "
        "anthropics/claude-code-action@v1 (.github/workflows/respond.yml:9)"
        "  [1 finding, highest HIGH]",
        "== on: issues (.github/workflows/triage.yml:3) -> agent "
        "anthropics/claude-code-action@v1 (.github/workflows/triage.yml:9)"
        "  [2 findings, highest MEDIUM]",
        "== NOTES",
    ]
    triage = output.split("(.github/workflows/triage.yml:9)  [2 findings")[1]
    assert triage.index("MEDIUM   TM001") < triage.index("INFO     TM002")
    # Every hop is shown with file:line.
    assert "source  .github/workflows/greet.yml:2  on: pull_request_target" in output
    assert "sink    .github/workflows/greet.yml:9  run: shell script" in output
    assert "TM005  Untrusted input interpolated into a shell step" in output
    # Inferred findings are marked, with the reason.
    assert "[inferred]" in output
    assert "it does not say so explicitly" in output
    # Assumed permissions: lowered severity and the fix asks to declare them.
    assert "MEDIUM   TM001" in output
    assert "Declare `permissions:` explicitly" in output
    assert "token permissions are assumed" in output
    # Info notes are listed but are not findings.
    assert 'info    .mcp.json:7  MCP server "internal" is not in the catalog' in output
    assert output.strip().endswith("4 findings (2 high, 1 medium, 1 info) in 4 files")


def test_terminal_groups_several_rules_under_one_source_and_agent() -> None:
    from taintmap.report.terminal import groups
    from taintmap.scan import scan as run_scan

    result = run_scan(REPOS / "linked")
    grouped = groups(result, result.findings)
    keys = [key for key, _ in grouped]
    assert len(keys) == len(set(keys))
    assert sum(len(members) for _, members in grouped) == len(result.findings)
    web = "mcp:.mcp.json:server:fetch:cap:source.untrusted.web_content"
    step = "gha:.github/workflows/agent.yml:job:agent:step:1"
    members = dict(grouped)[(web, step)]
    assert {f.rule_id for f in members} == {"TM001", "TM002", "TM004"}
    ranks = [f.severity.rank for f in members]
    assert ranks == sorted(ranks, reverse=True)
    # JSON stays one flat list per rule.
    _, report = scan_json(str(REPOS / "linked"))
    assert len(report["findings"]) == len(result.findings)


def test_terminal_report_shows_the_mcp_server_content_came_through() -> None:
    code, output = scan(str(REPOS / "linked"))
    assert code == EXIT_FINDINGS
    assert "via     .mcp.json:3" in output
    assert "MCP server fetch" in output


def test_no_findings() -> None:
    code, output = scan(str(REPOS / "notes_only"))
    assert code == EXIT_OK  # an info note never changes the exit code
    assert "0 findings in 1 file" in output


# -- JSON report ----------------------------------------------------------------------------------


def _normalised(report: dict) -> dict:  # type: ignore[type-arg]
    report = dict(report)
    report["taintmap_version"] = "<version>"
    return report


def test_json_report_matches_snapshot() -> None:
    code, report = scan_json(str(DEMO))
    assert code == EXIT_FINDINGS
    assert report["schema_version"] == 1
    actual = json.dumps(_normalised(report), indent=2, ensure_ascii=False) + "\n"
    if os.environ.get("UPDATE_SNAPSHOTS") == "1":
        SNAPSHOT.write_text(actual, encoding="utf-8", newline="\n")
    assert actual == SNAPSHOT.read_text(encoding="utf-8")


def test_json_report_fields() -> None:
    _, report = scan_json(str(DEMO))
    assert report["summary"]["findings"] == 4
    assert report["summary"]["by_severity"] == {
        "critical": 0,
        "high": 2,
        "medium": 1,
        "low": 0,
        "info": 1,
    }
    assert report["files"] == [
        ".github/workflows/greet.yml",
        ".github/workflows/respond.yml",
        ".github/workflows/triage.yml",
        ".mcp.json",
    ]
    inferred = [f for f in report["findings"] if f["inferred"]]
    assert len(inferred) == 1 and inferred[0]["inferred_reasons"]
    assumed = [f for f in report["findings"] if f["permissions_assumed"]]
    assert [f["severity"] for f in assumed] == ["medium"]
    for finding in report["findings"]:
        assert all({"file", "line", "role", "category"} <= set(hop) for hop in finding["path"])
    assert report["warnings"][0]["level"] == "info"
    _, linked = scan_json(str(REPOS / "linked"))
    assert any(f["via_servers"] for f in linked["findings"])


# -- options --------------------------------------------------------------------------------------


def test_min_severity_filters_the_report_but_not_the_exit_code() -> None:
    code, report = scan_json(str(DEMO), "--min-severity", "high")
    assert code == EXIT_FINDINGS
    assert {f["severity"] for f in report["findings"]} == {"high"}
    assert report["summary"]["not_shown"] == 2
    code, output = scan(str(DEMO), "--min-severity", "critical", "--fail-on", "medium")
    assert code == EXIT_FINDINGS
    assert "0 findings, 4 below critical not shown in 4 files" in output
    _, all_findings = scan_json(str(DEMO), "--min-severity", "info")
    assert all_findings["summary"]["findings"] == 4
    _, low_up = scan_json(str(DEMO), "--min-severity", "low")
    assert low_up["summary"]["not_shown"] == 1


@pytest.mark.parametrize(
    ("fail_on", "expected"),
    [
        ("low", EXIT_FINDINGS),
        ("medium", EXIT_FINDINGS),
        ("high", EXIT_FINDINGS),
        ("critical", EXIT_OK),
        ("never", EXIT_OK),
    ],
)
def test_fail_on(fail_on: str, expected: int) -> None:
    code, _ = scan(str(DEMO), "--fail-on", fail_on)
    assert code == expected


def test_default_token_permissions_read() -> None:
    _, write = scan_json(str(DEMO))
    _, read = scan_json(str(DEMO), "--default-token-permissions", "read")
    assert any(f["permissions_assumed"] for f in write["findings"])
    assert not any(f["permissions_assumed"] for f in read["findings"])
    assert read["summary"]["findings"] == write["summary"]["findings"] - 1


def test_include_and_exclude() -> None:
    _, only_workflows = scan_json(str(DEMO), "--include", ".github/**")
    assert ".mcp.json" not in only_workflows["files"]
    assert only_workflows["warnings"] == []
    _, no_greet = scan_json(str(DEMO), "--exclude", "greet.yml", "--exclude", ".mcp.json")
    assert no_greet["files"] == [".github/workflows/respond.yml", ".github/workflows/triage.yml"]
    assert not [f for f in no_greet["findings"] if f["rule_id"] == "TM005"]


def test_output_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    code, output = scan(str(DEMO), "--format", "json", "--output", str(target))
    assert code == EXIT_FINDINGS
    assert output == ""
    assert json.loads(target.read_text(encoding="utf-8"))["schema_version"] == 1
    text = tmp_path / "report.txt"
    scan(str(DEMO), "--output", str(text))
    assert "TM005" in text.read_text(encoding="utf-8")


# -- errors ---------------------------------------------------------------------------------------


def test_parse_error_exits_2() -> None:
    code, output = scan(str(REPOS / "broken"))
    assert code == EXIT_ERROR
    assert "warning .github/workflows/bad.yml:4" in output
    assert "1 file problem" in output


def test_missing_directory_exits_2(tmp_path: Path) -> None:
    code, output = scan(str(tmp_path / "missing"))
    assert code == EXIT_ERROR
    assert "not a directory" in output


def test_bad_option_exits_2() -> None:
    code, _ = scan(str(DEMO), "--format", "xml")
    assert code == EXIT_ERROR
    code, _ = scan(str(DEMO), "--include", "")
    assert code == EXIT_ERROR
