from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from taintmap import catalog
from taintmap.catalog import MODELS, SCHEMA_DIR, read_raw, schema_text


@pytest.mark.parametrize("name", sorted(MODELS))
def test_catalog_validates(name: str) -> None:
    MODELS[name].model_validate(read_raw(name))


@pytest.mark.parametrize("name", sorted(MODELS))
def test_checked_in_schema_is_current(name: str) -> None:
    path = SCHEMA_DIR / f"{name}.schema.json"
    assert path.read_text(encoding="utf-8") == schema_text(name), (
        f"{path.name} is out of date; run: python -m taintmap.catalog"
    )


def _entries(name: str) -> list[dict[str, Any]]:
    raw = read_raw(name)
    keys = {"gha_triggers": ("triggers", "contexts"), "ai_actions": ("actions",)}
    return [e for key in keys.get(name, ("servers",)) for e in raw[key]]


@pytest.mark.parametrize("name", sorted(MODELS))
def test_every_entry_has_a_source_link_and_evidence(name: str) -> None:
    entries = _entries(name)
    assert entries
    for entry in entries:
        assert str(entry.get("source_url", "")).startswith("https://"), entry.get("id")
        assert entry.get("evidence") in ("documented", "inferred"), entry.get("id")
        assert entry.get("evidence_reason"), entry.get("id")
        for capability in entry.get("capabilities", []):
            assert capability.get("evidence") in ("documented", "inferred"), entry.get("id")
            assert capability.get("evidence_reason"), entry.get("id")


def test_claude_code_action_reads_event_is_inferred() -> None:
    action = catalog.ai_actions().find("anthropics/claude-code-action@v1")
    assert action is not None
    assert action.reads_event is True
    assert action.reads_event_evidence is catalog.Evidence.INFERRED
    assert action.reads_event_reason


def _broken(name: str, mutate: Any) -> None:
    raw = copy.deepcopy(read_raw(name))
    mutate(raw)
    with pytest.raises(ValidationError):
        MODELS[name].model_validate(raw)


def test_missing_or_bad_evidence_is_rejected() -> None:
    _broken("ai_actions", lambda raw: raw["actions"][0].pop("source_url"))
    _broken("ai_actions", lambda raw: raw["actions"][0].pop("evidence_reason"))
    _broken("ai_actions", lambda raw: raw["actions"][0].pop("reads_event_evidence"))
    _broken("ai_actions", lambda raw: raw["actions"][0].pop("mcp_configs_reason"))
    _broken("ai_actions", lambda raw: raw["actions"][0].update(evidence="guessed"))
    _broken("mcp_servers", lambda raw: raw["servers"][0].update(source_url="http://insecure"))
    _broken("mcp_servers", lambda raw: raw["servers"][0]["capabilities"][0].pop("evidence"))
    _broken("gha_triggers", lambda raw: raw["triggers"][0].update(evidence_reason="two\nlines"))


def test_unknown_category_is_rejected() -> None:
    _broken("gha_triggers", lambda raw: raw["triggers"][0].update(source_category="source.nope"))
    _broken(
        "mcp_servers",
        lambda raw: raw["servers"][0]["capabilities"][0].update(category="control.sandbox"),
    )


def test_context_must_name_known_triggers() -> None:
    _broken("gha_triggers", lambda raw: raw["contexts"][0].update(triggers=["push"]))


def test_authors_must_exist() -> None:
    _broken("gha_triggers", lambda raw: raw["contexts"][0].update(author="sender"))
    _broken("gha_triggers", lambda raw: raw["triggers"][0].update(author="sender"))
    triggers = catalog.gha_triggers()
    assert triggers.association("comment") == "github.event.comment.author_association"
    assert triggers.association(None) is None
    trigger = triggers.trigger("issue_comment")
    assert trigger is not None and trigger.author == "comment"


def test_duplicate_ids_are_rejected() -> None:
    _broken("ai_actions", lambda raw: raw["actions"].append(raw["actions"][0]))
    _broken("mcp_servers", lambda raw: raw["servers"].append(raw["servers"][0]))


def test_unknown_fields_are_rejected() -> None:
    _broken("ai_actions", lambda raw: raw["actions"][0].update(guessed_input="x"))


def test_triggers_from_plan_are_present() -> None:
    triggers = catalog.gha_triggers()
    for name in (
        "issues",
        "issue_comment",
        "pull_request_target",
        "discussion",
        "discussion_comment",
        "pull_request_review_comment",
        "workflow_run",
    ):
        assert triggers.trigger(name) is not None, name
    assert triggers.trigger("push") is None


def test_context_matching() -> None:
    triggers = catalog.gha_triggers()
    assert [c.id for c in triggers.contexts_for("github.event.issue.title")] == [
        "github.event.issue.title"
    ]
    assert triggers.contexts_for("github.event.pull_request.head.ref")
    assert not triggers.contexts_for("github.event.issue.number")
    assert not triggers.contexts_for("github.event.issue")


def test_find_action() -> None:
    actions = catalog.ai_actions()
    found = actions.find("Anthropics/claude-code-action@v1")
    assert found is not None and found.id == "claude-code-action"
    assert actions.find("openai/codex-action@0123abcd") is not None
    assert actions.find("actions/checkout@v4") is None


@pytest.mark.parametrize(
    ("args", "url", "expected"),
    [
        (["-y", "@modelcontextprotocol/server-filesystem", "/tmp"], None, "filesystem"),
        (["-y", "@modelcontextprotocol/server-github@2025.1.1"], None, "github-archived"),
        (["mcp-server-fetch"], None, "fetch"),
        (["run", "-i", "--rm", "ghcr.io/github/github-mcp-server:v1"], None, "github"),
        (["run", "mcp/git@sha256:abc"], None, "git"),
        ([], "https://api.githubcopilot.com/mcp", "github"),
        (["-y", "some-unknown-server"], None, None),
    ],
)
def test_find_mcp_server(args: list[str], url: str | None, expected: str | None) -> None:
    found = catalog.mcp_servers().find(args, url)
    assert (found.id if found else None) == expected


def test_write_schemas(tmp_path: Path) -> None:
    written = catalog.write_schemas(tmp_path)
    assert {p.name for p in written} == {f"{n}.schema.json" for n in MODELS}
