from __future__ import annotations

from pathlib import Path

import pytest

from taintmap.graph import Graph
from taintmap.loaders import parse_yaml
from taintmap.model import EdgeKind, GraphFragment, Node, NodeKind
from taintmap.parsers import Parser
from taintmap.parsers.github_actions import (
    Gate,
    GithubActionsParser,
    context_paths,
    parse_workflow,
    references_env,
    secret_names,
    trusted_actor_gate,
    untrusted_contexts,
)
from taintmap.taxonomy import control_can_block

FIXTURES = Path(__file__).parent / "fixtures" / "gha"


class Parsed:
    """A parsed fixture with lookups by id suffix (the part after ``gha:<file>:``)."""

    def __init__(self, name: str) -> None:
        self.prefix = f"gha:{name}:"
        self.fragment: GraphFragment = GithubActionsParser().parse(FIXTURES / name, FIXTURES)
        self.graph = Graph()
        self.graph.add_fragment(self.fragment)  # edges must reference known nodes

    def node(self, suffix: str) -> Node:
        return self.graph.node(self.prefix + suffix)

    def has(self, suffix: str) -> bool:
        return self.prefix + suffix in self.graph

    def edges(self, src: str, dst: str, kind: EdgeKind) -> list[int]:
        """Lines of matching edges."""
        return sorted(
            e.location.line
            for e in self.fragment.edges
            if e.src == self.prefix + src and e.dst == self.prefix + dst and e.kind == kind
        )

    def of_category(self, category: str) -> list[str]:
        return sorted(
            n.id.removeprefix(self.prefix) for n in self.fragment.nodes if n.category == category
        )


def parsed(name: str) -> Parsed:
    return Parsed(name)


ALL_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.yml"))


# -- the parser protocol --------------------------------------------------------------------------


def test_parser_protocol_and_matching() -> None:
    parser = GithubActionsParser()
    assert isinstance(parser, Parser)
    assert parser.name == "github_actions"
    assert parser.matches(Path("repo/.github/workflows/ci.yml"))
    assert parser.matches(Path(".github/workflows/ci.YAML"))
    assert not parser.matches(Path("repo/.github/ci.yml"))
    assert not parser.matches(Path("repo/workflows/ci.yml"))
    assert not parser.matches(Path("repo/.github/workflows/readme.md"))


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_every_node_and_edge_has_a_line(name: str) -> None:
    fragment = parsed(name).fragment
    for item in [*fragment.nodes, *fragment.edges]:
        assert item.location.file == name
        assert item.location.line >= 1


def test_output_is_deterministic() -> None:
    first = parsed("env_isolation.yml").fragment
    second = parsed("env_isolation.yml").fragment
    assert first == second


# -- triggers -> sources --------------------------------------------------------------------------


def test_untrusted_triggers_become_sources() -> None:
    p = parsed("gates.yml")
    comment = p.node("on:issue_comment")
    assert comment.kind is NodeKind.SOURCE
    assert comment.category == "source.untrusted.issue_text"
    assert comment.location.line == 2
    issues = p.node("on:issues")
    assert issues.attrs["types"] == ["labeled"]
    assert issues.location.line == 3


def test_trigger_forms_string_and_list() -> None:
    assert parsed("shell_injection.yml").node("on:issue_comment").location.line == 2
    assert parsed("comment_agent_event.yml").node("on:issue_comment").location.line == 1
    p = parsed("pr_target_forms.yml")
    assert p.node("on:pull_request_target").location.line == 2
    assert not p.has("on:push")


def test_trusted_triggers_create_no_sources_or_input() -> None:
    p = parsed("trusted_triggers.yml")
    assert p.graph.nodes_of_kind(NodeKind.SOURCE) == []
    assert not [e for e in p.fragment.edges if e.src.endswith(":on:push")]
    step = p.node("job:check:step:0")
    assert "untrusted_contexts" not in step.attrs
    assert p.node("job:check:step:0:run").attrs["expression_injection"] is False


# -- jobs, steps, agents --------------------------------------------------------------------------


def test_jobs_and_steps_are_workflow_steps() -> None:
    p = parsed("issue_agent.yml")
    job = p.node("job:triage")
    assert job.category == "carrier.workflow_step"
    assert job.location.line == 6
    checkout = p.node("job:triage:step:0")
    assert checkout.category == "carrier.workflow_step"
    assert checkout.attrs["uses"] == "actions/checkout@v4"
    assert p.edges("job:triage", "job:triage:step:0", EdgeKind.PASSES_INPUT) == [9]


def test_catalogued_ai_action_is_llm_agent() -> None:
    p = parsed("issue_agent.yml")
    agent = p.node("job:triage:step:1")
    assert agent.category == "carrier.llm_agent"
    assert agent.attrs["ai_action"] == "claude-code-action"
    assert agent.attrs["source_url"].startswith("https://")
    assert agent.attrs["evidence"] == "documented"
    assert agent.location.line == 10


def test_untrusted_expression_in_with_passes_input() -> None:
    p = parsed("issue_agent.yml")
    lines = p.edges("on:issues", "job:triage:step:1", EdgeKind.PASSES_INPUT)
    assert 13 in lines  # the prompt input
    assert p.node("job:triage:step:1").attrs["untrusted_contexts"] == ["github.event.issue.title"]


def test_agent_that_reads_the_event_gets_input_without_expressions() -> None:
    p = parsed("comment_agent_event.yml")
    assert p.edges("on:issue_comment", "job:respond:step:0", EdgeKind.PASSES_INPUT) == [9]
    path = [p.prefix + s for s in ("on:issue_comment", "job:respond:step:0")]
    sink = p.prefix + "job:respond:permission:sink.repo.write"
    assert [*path, sink] in p.graph.paths(path[0], sink)


# -- run: steps -----------------------------------------------------------------------------------


def test_run_step_is_code_exec_with_expression_injection() -> None:
    p = parsed("shell_injection.yml")
    exec_node = p.node("job:echo:step:0:run")
    assert exec_node.kind is NodeKind.SINK
    assert exec_node.category == "sink.code_exec"
    assert exec_node.attrs["expression_injection"] is True
    assert exec_node.location.line == 10
    assert p.edges("on:issue_comment", "job:echo:step:0", EdgeKind.PASSES_INPUT) == [10]
    assert p.edges("job:echo:step:0", "job:echo:step:0:run", EdgeKind.INVOKES) == [10]
    assert p.of_category("control.input_isolation") == []
    source, sink = p.prefix + "on:issue_comment", p.prefix + "job:echo:step:0:run"
    assert p.graph.paths(source, sink) == [[source, p.prefix + "job:echo:step:0", sink]]


def test_expression_forms() -> None:
    p = parsed("pr_target_forms.yml")
    assert p.node("job:forms:step:0").attrs["untrusted_contexts"] == ["github.head_ref"]
    assert p.node("job:forms:step:1").attrs["untrusted_contexts"] == [
        "github.event.pull_request.title"
    ]
    assert p.node("job:forms:step:2").attrs["untrusted_contexts"] == ["github.event"]
    assert "untrusted_contexts" not in p.node("job:forms:step:3").attrs
    assert p.node("job:forms:step:3:run").attrs["expression_injection"] is False


# -- input isolation ------------------------------------------------------------------------------


def test_env_passed_input_is_isolated() -> None:
    p = parsed("env_isolation.yml")
    control = p.node("job:safe:step:0:input_isolation")
    assert control.category == "control.input_isolation"
    assert control.attrs["referenced"] == ["TITLE"]
    assert p.edges("job:safe:step:0", "job:safe:step:0:input_isolation", EdgeKind.GUARDED_BY) == [
        14
    ]
    assert p.edges("on:issues", "job:safe:step:0", EdgeKind.PASSES_INPUT) == [13]
    assert p.node("job:safe:step:0:run").attrs["expression_injection"] is False


def test_job_and_workflow_env_feed_the_job() -> None:
    p = parsed("env_isolation.yml")
    assert p.edges("on:issues", "job:safe", EdgeKind.PASSES_INPUT) == [4, 9]
    braces = p.node("job:safe:step:1:input_isolation")
    assert braces.attrs["referenced"] == ["JOB_BODY"]
    assert set(braces.attrs["env"]) == {"JOB_BODY", "WF_TITLE"}


def test_interpolation_cancels_isolation() -> None:
    p = parsed("env_isolation.yml")
    assert not p.has("job:safe:step:2:input_isolation")
    assert p.node("job:safe:step:2:run").attrs["expression_injection"] is True


def test_trusted_env_values_are_not_untrusted() -> None:
    p = parsed("env_isolation.yml")
    assert "untrusted_contexts" not in p.node("job:safe:step:3").attrs


# -- permissions ----------------------------------------------------------------------------------


def test_default_permissions_when_absent() -> None:
    p = parsed("default_permissions.yml")
    repo = p.node("job:build:permission:sink.repo.write")
    assert repo.attrs["declared"] == "default"
    assert "contents" in repo.attrs["scopes"]
    assert repo.location.line == 3
    assert p.has("job:build:permission:sink.deploy")
    assert not p.has("job:build:permission:sink.secret.read")
    assert p.edges(
        "job:build:step:0", "job:build:permission:sink.repo.write", EdgeKind.RUNS_WITH
    ) == [3]


def test_workflow_read_all_and_job_overrides() -> None:
    p = parsed("permissions.yml")
    assert not [n for n in p.of_category("sink.repo.write") if n.startswith("job:inherits")]
    repo = p.node("job:overrides:permission:sink.repo.write")
    assert repo.attrs == {
        "scopes": ["contents", "pull-requests"],
        "declared": "job",
        "permissions_assumed": False,
    }
    assert repo.location.line == 11
    assert p.node("job:overrides:permission:sink.secret.read").attrs["scopes"] == ["id-token"]
    assert p.node("job:overrides:permission:sink.deploy").location.line == 14
    everything = p.node("job:everything:permission:sink.repo.write")
    assert "contents" in everything.attrs["scopes"]
    assert everything.location.line == 20


def test_workflow_level_permissions_apply_to_jobs() -> None:
    p = parsed("comment_agent_event.yml")
    repo = p.node("job:respond:permission:sink.repo.write")
    assert repo.attrs == {
        "scopes": ["issues"],
        "declared": "workflow",
        "permissions_assumed": False,
    }
    assert repo.location.line == 4


def test_empty_permissions_grant_nothing() -> None:
    p = parsed("env_isolation.yml")
    assert [n for n in p.of_category("sink.repo.write")] == []


# -- secrets --------------------------------------------------------------------------------------


def test_secret_references_become_secret_sinks() -> None:
    p = parsed("secrets.yml")
    assert p.of_category("sink.secret.read") == [
        "job:use:env:JOB_TOKEN:secret:FAKE_JOB_TOKEN",
        "job:use:step:0:with:token:secret:FAKE_WITH_TOKEN",
        "job:use:step:1:env:A:secret:FAKE_A",
        "job:use:step:1:env:A:secret:FAKE_B",
        "workflow:env:WF_TOKEN:secret:FAKE_WORKFLOW_TOKEN",
    ]
    with_secret = p.node("job:use:step:0:with:token:secret:FAKE_WITH_TOKEN")
    assert with_secret.location.line == 13
    assert with_secret.label == "secrets.FAKE_WITH_TOKEN"
    # Workflow and job secrets reach every step of the job.
    for step in ("job:use:step:0", "job:use:step:1"):
        assert p.edges(
            step, "workflow:env:WF_TOKEN:secret:FAKE_WORKFLOW_TOKEN", EdgeKind.RUNS_WITH
        ) == [4]
        assert p.edges(step, "job:use:env:JOB_TOKEN:secret:FAKE_JOB_TOKEN", EdgeKind.RUNS_WITH) == [
            9
        ]
    assert not p.edges(
        "job:use:step:1", "job:use:step:0:with:token:secret:FAKE_WITH_TOKEN", EdgeKind.RUNS_WITH
    )


def test_agent_credential_secret() -> None:
    p = parsed("issue_agent.yml")
    secret = "job:triage:step:1:with:anthropic_api_key:secret:FAKE_ANTHROPIC_KEY"
    assert p.node(secret).attrs["via"] == "with.anthropic_api_key"
    assert p.edges("job:triage:step:1", secret, EdgeKind.RUNS_WITH) == [14]


# -- trusted actor gates --------------------------------------------------------------------------


def test_author_association_gate_on_job() -> None:
    p = parsed("gates.yml")
    gate = p.node("job:owner_only:if:trusted_actor")
    assert gate.category == "control.trusted_actor_gate"
    assert gate.attrs["gate"] == "author_association"
    assert gate.location.line == 7
    for guarded in ("job:owner_only", "job:owner_only:step:0"):
        assert p.edges(guarded, "job:owner_only:if:trusted_actor", EdgeKind.GUARDED_BY) == [7]
    assert p.has("job:from_json:if:trusted_actor")


def test_label_gate_on_step() -> None:
    p = parsed("gates.yml")
    gate = p.node("job:label_step:step:0:if:trusted_actor")
    assert gate.attrs["gate"] == "label"
    assert p.edges(
        "job:label_step:step:0", "job:label_step:step:0:if:trusted_actor", EdgeKind.GUARDED_BY
    ) == [19]


def test_bypassable_and_negative_conditions_are_not_gates() -> None:
    p = parsed("gates.yml")
    assert not p.has("job:bypassable:if:trusted_actor")
    assert not p.has("job:negative:if:trusted_actor")


COMMENT_AA = "github.event.comment.author_association"
ISSUE_AA = "github.event.issue.author_association"


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (f"{COMMENT_AA} == 'OWNER'", Gate("author_association", (COMMENT_AA,))),
        (f"'MEMBER' == {ISSUE_AA}", Gate("author_association", (ISSUE_AA,))),
        (
            "${{ github.event['comment']['author_association'] == 'COLLABORATOR' }}",
            Gate("author_association", (COMMENT_AA,)),
        ),
        (
            f'contains(fromJSON(\'["OWNER", "MEMBER"]\'), {COMMENT_AA})',
            Gate("author_association", (COMMENT_AA,)),
        ),
        (
            f"{COMMENT_AA} == 'OWNER' || {COMMENT_AA} == 'MEMBER'",
            Gate("author_association", (COMMENT_AA,)),
        ),
        (
            f"{COMMENT_AA} == 'OWNER' && {ISSUE_AA} == 'OWNER'",
            Gate("author_association", (COMMENT_AA, ISSUE_AA)),
        ),
        # Each alternative trusts a different author, so neither author is always checked.
        (f"{COMMENT_AA} == 'OWNER' || {ISSUE_AA} == 'OWNER'", None),
        (
            f"contains(github.event.issue.labels.*.name, 'ok') || {COMMENT_AA} == 'OWNER'",
            Gate("author_association", (COMMENT_AA,)),
        ),
        (f"{COMMENT_AA} == 'CONTRIBUTOR'", None),
        (f"{COMMENT_AA} != 'NONE'", None),
        (f'contains(fromJSON(\'["OWNER", "NONE"]\'), {COMMENT_AA})', None),
        (f"!contains(fromJSON('[\"OWNER\"]'), {COMMENT_AA})", None),
        ("github.event.label.name == 'safe-to-run'", Gate("label")),
        ("!contains(github.event.issue.labels.*.name, 'skip')", None),
        ("github.event_name == 'issues'", None),
        ("always()", None),
    ],
)
def test_trusted_actor_gate(condition: str, expected: Gate | None) -> None:
    assert trusted_actor_gate(condition) == expected


def test_gate_records_which_author_it_checks() -> None:
    p = parsed("gates.yml")
    assert p.node("job:owner_only:if:trusted_actor").attrs["checks"] == [COMMENT_AA]
    assert p.node("job:from_json:if:trusted_actor").attrs["checks"] == [COMMENT_AA]
    assert p.node("job:label_step:step:0:if:trusted_actor").attrs["checks"] == []


def test_issue_author_gate_does_not_cover_the_commenter() -> None:
    # The workflow checks who opened the issue, but interpolates the comment, which anyone can
    # write on a maintainer's issue. The input edge names the comment author, the gate the issue.
    p = parsed("gate_bypass.yml")
    gate = p.node("job:reply:if:trusted_actor")
    assert gate.attrs["checks"] == [ISSUE_AA]
    edges = [
        e
        for e in p.fragment.edges
        if e.src == p.prefix + "on:issue_comment" and e.kind == EdgeKind.PASSES_INPUT
    ]
    by_author = {e.attrs["author"]: e.attrs for e in edges}
    assert by_author["comment"]["author_association"] == COMMENT_AA
    assert by_author["comment"]["contexts"] == ["github.event.comment.body"]
    assert by_author["issue"]["author_association"] == ISSUE_AA
    assert by_author["issue"]["contexts"] == ["github.event.issue.title"]
    assert COMMENT_AA not in gate.attrs["checks"]


# -- human approval -------------------------------------------------------------------------------


def test_environment_is_declared_human_approval() -> None:
    p = parsed("environment.yml")
    control = p.node("job:deploy:environment")
    assert control.category == "control.human_approval"
    assert control.attrs["environment"] == "production"
    assert control.attrs["declared"] is True
    assert control.attrs["verified"] is False
    assert control.location.line == 5
    assert p.edges("job:deploy:step:0", "job:deploy:environment", EdgeKind.GUARDED_BY) == [5]
    assert p.node("job:deploy_map:environment").attrs["environment"] == "staging"


def test_workflow_run_context() -> None:
    p = parsed("environment.yml")
    assert p.edges("on:workflow_run", "job:deploy:step:0", EdgeKind.PASSES_INPUT) == [7]


# -- malformed input ------------------------------------------------------------------------------


def test_malformed_workflow_gives_a_warning_not_a_crash() -> None:
    fragment = parsed("malformed.yml").fragment
    assert fragment.nodes == [] and fragment.edges == []
    assert len(fragment.warnings) == 1
    assert fragment.warnings[0].file == "malformed.yml"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("- just a list\n", "workflow is not a mapping"),
        ("on: issues\njobs: [a]\n", "jobs is not a mapping"),
        ("on: issues\njobs:\n  a: 1\n", 'job "a" is not a mapping'),
        ("on: issues\njobs:\n  a:\n    steps: run\n", 'steps of job "a" is not a list'),
        ("on: issues\njobs:\n  a:\n    steps: [1]\n", 'step 0 of job "a" is not a mapping'),
        ("on: issues\npermissions: lots\njobs:\n  a:\n    steps: []\n", "unexpected value"),
        (
            "on: issues\npermissions:\n  everything: write\njobs:\n  a:\n    steps: []\n",
            'unknown permission "everything"',
        ),
    ],
)
def test_unexpected_shapes_warn(text: str, message: str) -> None:
    fragment = parse_workflow(parse_yaml(text, "wf.yml"))
    assert any(message in w.message for w in fragment.warnings), fragment.warnings
    Graph().add_fragment(fragment)


def test_workflow_without_jobs_or_triggers() -> None:
    assert parse_workflow(parse_yaml("name: x\n", "wf.yml")).nodes == []
    assert parse_workflow(parse_yaml("", "wf.yml")).nodes == []


# -- helpers --------------------------------------------------------------------------------------


def test_context_paths_normalise_forms() -> None:
    assert context_paths("github.event['issue'][\"title\"]") == ["github.event.issue.title"]
    assert context_paths("toJSON(github.event.commits[0].message)") == [
        "github.event.commits.0.message"
    ]
    assert context_paths("format('{0}', github.head_ref)") == ["github.head_ref"]
    assert context_paths("mygithub.event.issue") == []


def test_untrusted_contexts_maps_to_triggers() -> None:
    found = untrusted_contexts("${{ github.event.comment.body }} ${{ github.event.issue.number }}")
    body = {"comment": {"github.event.comment.body"}}
    assert found == {
        "issue_comment": body,
        "discussion_comment": body,
        "pull_request_review_comment": body,
    }
    whole = untrusted_contexts("${{ toJSON(github.event) }}")
    assert set(whole["issue_comment"]) == {"issue", "comment"}
    assert set(whole["workflow_run"]) == {None}
    assert untrusted_contexts("github.event.issue.title") == {}  # not inside ${{ }}


def test_secret_names() -> None:
    text = "${{ secrets.A }} ${{ secrets['B-2'] }} secrets.C ${{ github.secrets_x }}"
    assert secret_names(text) == ["A", "B-2"]


def test_references_env() -> None:
    assert references_env('echo "$TITLE"', "TITLE")
    assert references_env("echo ${TITLE}", "TITLE")
    assert references_env("Write-Output $env:TITLE", "TITLE")
    assert references_env("echo %TITLE%", "TITLE")
    assert not references_env("echo $TITLES", "TITLE")


# -- review decisions -----------------------------------------------------------------------------


def test_default_permission_sinks_are_marked_assumed() -> None:
    p = parsed("default_permissions.yml")
    for sink in ("job:build:permission:sink.repo.write", "job:build:permission:sink.deploy"):
        assert p.node(sink).attrs["permissions_assumed"] is True
    assert p.node("job:build").attrs["permissions"] == {"declared": "default", "assumed": "write"}


def test_default_token_permissions_read_grants_nothing() -> None:
    parser = GithubActionsParser(default_token_permissions="read")
    fragment = parser.parse(FIXTURES / "default_permissions.yml", FIXTURES)
    assert not [n for n in fragment.nodes if n.id.endswith(("sink.repo.write", "sink.deploy"))]
    job = next(n for n in fragment.nodes if n.id.endswith(":job:build"))
    assert job.attrs["permissions"] == {"declared": "default", "assumed": "read"}
    # Explicit permissions are unaffected by the option.
    explicit = parser.parse(FIXTURES / "permissions.yml", FIXTURES)
    assert any(n.id.endswith("overrides:permission:sink.repo.write") for n in explicit.nodes)


def test_declared_permissions_are_kept_on_the_job() -> None:
    p = parsed("permissions.yml")
    assert p.node("job:inherits").attrs["permissions"] == {
        "declared": "workflow",
        "line": 2,
        "value": "read-all",
    }
    assert p.node("job:overrides").attrs["permissions"] == {
        "declared": "job",
        "line": 10,
        "value": {
            "contents": "write",
            "pull-requests": "write",
            "id-token": "write",
            "packages": "write",
            "issues": "read",
        },
    }


def test_reads_event_edge_is_inferred() -> None:
    p = parsed("comment_agent_event.yml")
    (edge,) = [
        e
        for e in p.fragment.edges
        if e.src == p.prefix + "on:issue_comment" and e.dst == p.prefix + "job:respond:step:0"
    ]
    assert edge.attrs["reads_event"] is True
    assert edge.attrs["evidence"] == "inferred"
    assert edge.attrs["evidence_reason"]
    assert edge.attrs["author_association"] == COMMENT_AA


def test_env_passed_input_still_flows_to_other_sinks() -> None:
    p = parsed("isolation_flow.yml")
    step = p.prefix + "job:safe:step:0"
    control = p.node("job:safe:step:0:input_isolation")
    assert control.attrs["referenced"] == ["TITLE"]
    source = p.prefix + "on:issues"
    secret = p.prefix + "job:safe:step:0:env:TOKEN:secret:FAKE_TOKEN_FOR_TESTS"
    write = p.prefix + "job:safe:permission:sink.repo.write"
    # The isolated input still reaches the step and, through it, the secret and the write token.
    assert p.graph.paths(source, secret) == [[source, step, secret]]
    assert [source, step, write] in p.graph.paths(source, write)
    # input_isolation can only ever block code execution reached by expression injection.
    assert control_can_block(control.category, "sink.code_exec", via_expression_injection=True)
    assert not control_can_block(control.category, "sink.secret.read")
    assert not control_can_block(control.category, "sink.repo.write")
