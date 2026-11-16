from __future__ import annotations

import re
from pathlib import Path

import pytest

from taintmap.discover import discover
from taintmap.graph import Graph
from taintmap.link import build_graph
from taintmap.model import Finding, Severity, compute_fingerprint
from taintmap.parsers.github_actions import GithubActionsParser
from taintmap.parsers.mcp_config import McpConfigParser
from taintmap.paths import candidate_paths
from taintmap.rules import all_rules, run_rules
from taintmap.rules._common import DECLARE_PERMISSIONS

FIXTURES = Path(__file__).parent / "fixtures"
RULE_FIXTURES = FIXTURES / "rules"
THREAT_MODEL = Path(__file__).resolve().parents[1] / "docs" / "threat-model.md"


def scan(root: Path) -> tuple[Graph, list[Finding]]:
    root = root.resolve()
    parsers = (GithubActionsParser(), McpConfigParser())
    fragments = [
        parser.parse(path, root)
        for path in discover(root)
        for parser in parsers
        if parser.matches(path.relative_to(root))
    ]
    graph, _ = build_graph(fragments)
    return graph, run_rules(graph, candidate_paths(graph))


def rule_ids(findings: list[Finding]) -> list[str]:
    return sorted({f.rule_id for f in findings})


# -- rule metadata --------------------------------------------------------------------------------


def test_rules_match_the_threat_model_table() -> None:
    rows = {}
    for line in THREAT_MODEL.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\| `(TM\d{3})` \| (.+?) \| .+ \| (\w+) \|$", line)
        if match:
            rows[match.group(1)] = (match.group(2), match.group(3))
    rules = {r.info.id: r.info for r in all_rules()}
    assert set(rows) == set(rules)
    for rule_id, (title, severity) in rows.items():
        assert rules[rule_id].title == title
        assert rules[rule_id].default_severity == Severity(severity)
        assert rules[rule_id].missing_control.startswith("control.")


# -- vulnerable and safe fixtures -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("case", "rule"),
    [
        ("tm001_vulnerable", "TM001"),
        ("tm002_vulnerable", "TM002"),
        ("tm003_vulnerable", "TM003"),
        ("tm004_vulnerable", "TM004"),
        ("tm005_vulnerable", "TM005"),
    ],
)
def test_vulnerable_fixture_triggers_its_rule(case: str, rule: str) -> None:
    _, findings = scan(RULE_FIXTURES / case)
    assert rule in rule_ids(findings)
    for finding in findings:
        assert len(finding.evidence) == len(finding.path)
        assert finding.fix
        assert finding.fingerprint == compute_fingerprint(finding.rule_id, finding.path)


@pytest.mark.parametrize(
    "case",
    [
        "tm001_safe",
        "tm001_safe_perms",
        "tm002_safe",
        "tm003_safe",
        "tm004_safe",
        "tm005_safe",
    ],
)
def test_safe_fixture_has_no_findings(case: str) -> None:
    _, findings = scan(RULE_FIXTURES / case)
    assert findings == []


def test_tm001_locations_and_fix() -> None:
    _, findings = scan(RULE_FIXTURES / "tm001_vulnerable")
    (finding,) = [f for f in findings if f.rule_id == "TM001"]
    assert finding.severity is Severity.HIGH
    assert str(finding.evidence[0]) == ".github/workflows/triage.yml:2"
    assert str(finding.evidence[-1]) == ".github/workflows/triage.yml:5"
    assert "github.event.issue.author_association" in finding.fix
    assert "`contents: write`" in finding.fix
    assert DECLARE_PERMISSIONS not in finding.fix
    assert not finding.permissions_assumed


def test_tm003_through_an_allowed_shell_tool() -> None:
    graph, findings = scan(RULE_FIXTURES / "tm003_vulnerable")
    (finding,) = findings
    assert finding.rule_id == "TM003"
    assert finding.severity is Severity.CRITICAL
    assert graph.node(finding.path[-1]).attrs["via_tool"] == "Bash"
    assert "Remove `Bash`" in finding.fix
    # The agent only sees the comment because claude-code-action reads the event itself.
    assert finding.inferred


def test_tm004_lists_sensitive_access_and_the_server() -> None:
    _, findings = scan(RULE_FIXTURES / "tm004_vulnerable")
    (finding,) = findings
    assert finding.rule_id == "TM004"
    assert finding.path[-1].endswith("cap:sink.network.outbound")
    assert finding.related == ["mcp:.mcp.json:server:browser:cap:sink.data.read_sensitive"]
    assert [str(loc) for loc in finding.related_evidence] == [".mcp.json:3"]
    assert finding.via_servers == ["mcp:.mcp.json:server:browser"]
    assert not finding.inferred


def test_tm005_fix_names_the_context() -> None:
    _, findings = scan(RULE_FIXTURES / "tm005_vulnerable")
    (finding,) = findings
    assert "`github.event.pull_request.title`" in finding.fix
    assert str(finding.evidence[-1]) == ".github/workflows/greet.yml:9"


# -- severity, fix text and flags -----------------------------------------------------------------


def test_assumed_permissions_lower_severity_and_ask_to_declare_them() -> None:
    _, findings = scan_single_workflow("issue_agent.yml")
    (write,) = [f for f in findings if f.rule_id == "TM001"]
    assert write.permissions_assumed
    assert write.severity is Severity.MEDIUM  # TM001 default is high
    assert write.fix.endswith(DECLARE_PERMISSIONS)
    assert "declare `permissions:` explicitly" in write.fix.lower()
    (secret,) = [f for f in findings if f.rule_id == "TM002"]
    assert not secret.permissions_assumed
    # The agent's own model key, with no command or network tools: informational.
    assert secret.severity is Severity.INFO


def scan_single_workflow(name: str) -> tuple[Graph, list[Finding]]:
    root = FIXTURES / "gha"
    graph, _ = build_graph([GithubActionsParser().parse(root / name, root)])
    return graph, run_rules(graph, candidate_paths(graph))


BENCH_DEV = Path(__file__).resolve().parents[1] / "benchmark" / "cases"


def test_tm002_model_credential_is_info_without_leak_channels() -> None:
    _, findings = scan(BENCH_DEV / "tm002-dev-discussion-gemini-deploy-token")
    by_sink = {str(f.evidence[-1]): f for f in findings if f.rule_id == "TM002"}
    model_key = by_sink[".github/workflows/answer.yml:12"]
    assert model_key.severity is Severity.INFO
    assert "`gemini_api_key`" in model_key.fix
    assert "no way to leak it" in model_key.fix
    assert not model_key.inferred and model_key.inferred_reasons == []
    other = by_sink[".github/workflows/answer.yml:9"]
    assert other.severity is Severity.HIGH  # any other secret stays high
    assert not other.inferred
    assert "secrets.FAKE_DEPLOY_TOKEN" in other.fix


def test_tm002_model_credential_is_high_when_the_agent_can_run_commands() -> None:
    _, findings = scan(BENCH_DEV / "tm002-dev-pr-target-claude-bash-key")
    (secret,) = [f for f in findings if f.rule_id == "TM002"]
    assert secret.severity is Severity.HIGH
    assert "can run commands" in secret.fix
    # Raising a model credential to high is taintmap's judgement, so the finding is inferred.
    assert secret.inferred
    assert secret.inferred_reasons == [
        "Rated high because the agent can also run commands; that untrusted input can make it "
        "leak its own model credential this way is taintmap's judgement."
    ]


def test_tm002_model_credential_is_high_when_the_agent_can_send_data_out() -> None:
    graph, findings = scan(FIXTURES / "repos" / "linked")
    model_key = [
        f
        for f in findings
        if f.rule_id == "TM002" and graph.node(f.path[-1]).attrs.get("model_credential")
    ]
    assert model_key and all(f.severity is Severity.HIGH for f in model_key)
    assert all("send data out" in f.fix for f in model_key)


def test_model_credential_inputs_are_catalogued_with_sources() -> None:
    from taintmap import catalog

    for action in catalog.ai_actions().actions:
        assert action.model_credential_inputs, action.id
        assert set(action.model_credential_inputs) <= set(action.credential_inputs)
        assert str(action.model_credential_source_url).startswith("https://")


def test_inferred_findings_are_marked() -> None:
    _, findings = scan_single_workflow("comment_agent_event.yml")
    (write,) = [f for f in findings if f.rule_id == "TM001"]
    assert write.inferred


def test_mcp_findings_name_the_server_and_hardcoded_key_only() -> None:
    _, findings = scan(FIXTURES / "mcp" / "desktop")
    secrets = [f for f in findings if f.rule_id == "TM002"]
    # One per untrusted source reaching the client: GitHub issues and PRs, and Slack messages.
    assert len(secrets) == 3
    for secret in secrets:
        assert "GITHUB_PERSONAL_ACCESS_TOKEN" in secret.fix
        assert "FAKE_TOKEN_FOR_TESTS" not in secret.model_dump_json()
    writes = [f for f in findings if f.rule_id == "TM001"]
    assert writes and all("MCP server `github`" in f.fix for f in writes)
    assert all(f.via_servers for f in writes)


def test_shell_injection_is_not_reported_for_isolated_or_gated_steps() -> None:
    for name in ("isolation_flow.yml", "env_isolation.yml"):
        _, findings = scan_single_workflow(name)
        steps = [f for f in findings if f.rule_id == "TM005"]
        assert all("step:2" in f.path[-1] for f in steps), name  # only the interpolated step
    _, gated = scan_single_workflow("gates.yml")
    assert not [f for f in gated if f.rule_id == "TM005"]
    _, bypass = scan_single_workflow("gate_bypass.yml")
    assert [f.rule_id for f in bypass if f.rule_id == "TM005"] == ["TM005"]


def test_one_finding_per_rule_source_and_sink() -> None:
    _, findings = scan(FIXTURES / "mcp" / "claude_code")
    keys = [(f.rule_id, f.path[0], f.path[-1]) for f in findings]
    assert len(keys) == len(set(keys))


def test_fingerprints_are_stable_across_runs() -> None:
    first = [f.fingerprint for f in scan(FIXTURES / "repos" / "linked")[1]]
    second = [f.fingerprint for f in scan(FIXTURES / "repos" / "linked")[1]]
    assert first and first == second


def test_findings_are_sorted_most_severe_first() -> None:
    _, findings = scan(FIXTURES / "mcp" / "claude_code")
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_severity_lowered() -> None:
    assert Severity.CRITICAL.lowered() is Severity.HIGH
    assert Severity.LOW.lowered() is Severity.LOW
    assert Severity.INFO.lowered() is Severity.INFO
