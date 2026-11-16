"""Catalogs of third-party components: GitHub triggers, AI actions and MCP servers.

The data lives in YAML files next to this module. The Pydantic models below are the source of truth
for their structure; the JSON schemas in ``schemas/`` are generated from them with
``python -m taintmap.catalog`` and a test fails when they are out of date.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from ruamel.yaml import YAML

from taintmap.taxonomy import CarrierCategory, SinkCategory, SourceCategory

Url = Annotated[str, StringConstraints(pattern=r"^https://[^\s]+$")]
Id = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.-]*$")]
Name = Annotated[str, StringConstraints(min_length=1, pattern=r"^\S+$")]

CATALOG_FILES = {
    "gha_triggers": "gha_triggers.yaml",
    "ai_actions": "ai_actions.yaml",
    "mcp_servers": "mcp_servers.yaml",
}


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Evidence(StrEnum):
    """How firmly a catalog claim is backed by its source."""

    DOCUMENTED = "documented"
    """The cited source states it."""

    INFERRED = "inferred"
    """taintmap's reading of the source; reports mark findings that depend on it."""


Reason = Annotated[str, StringConstraints(min_length=1, pattern=r"^[^\n]+$")]


class _Sourced(_Model):
    """A catalog entry with a source link and how firmly the source backs it."""

    source_url: Url
    evidence: Evidence
    evidence_reason: Reason


def _unique(values: list[str], what: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {what} {value!r}")
        seen.add(value)


# -- GitHub Actions triggers and contexts ---------------------------------------------------------


class Trigger(_Sourced):
    id: Name
    description: str = Field(min_length=1)
    source_category: SourceCategory


class Context(_Sourced):
    id: Annotated[str, StringConstraints(pattern=r"^[a-z_]+(\.([A-Za-z0-9_-]+|\*))+$")]
    description: str = Field(min_length=1)
    source_category: SourceCategory
    triggers: list[Name] = Field(min_length=1)

    def matches(self, path: str) -> bool:
        """True when the dot-form expression path ``path`` is this context or lies inside it."""
        mine = self.id.split(".")
        theirs = path.split(".")
        if len(theirs) < len(mine):
            return False
        return all(m in ("*", t) for m, t in zip(mine, theirs, strict=False))


class GhaTriggersCatalog(_Model):
    version: Literal[1]
    triggers: list[Trigger]
    contexts: list[Context]

    @model_validator(mode="after")
    def _check(self) -> GhaTriggersCatalog:
        _unique([t.id for t in self.triggers], "trigger id")
        _unique([c.id for c in self.contexts], "context id")
        known = {t.id for t in self.triggers}
        for context in self.contexts:
            for trigger in context.triggers:
                if trigger not in known:
                    raise ValueError(f"context {context.id} names unknown trigger {trigger!r}")
        return self

    def trigger(self, name: str) -> Trigger | None:
        return next((t for t in self.triggers if t.id == name), None)

    def contexts_for(self, path: str) -> list[Context]:
        """Catalogued contexts that ``path`` (dot form) names or lies inside."""
        return [c for c in self.contexts if c.matches(path)]


# -- AI actions -----------------------------------------------------------------------------------


class AiAction(_Sourced):
    id: Id
    uses: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+$")]
    description: str = Field(min_length=1)
    category: Literal[CarrierCategory.LLM_AGENT]
    prompt_inputs: list[Name]
    tool_config_inputs: list[Name]
    credential_inputs: list[Name]
    sandbox_inputs: list[Name]
    actor_gate_inputs: list[Name]
    reads_event: bool
    reads_event_evidence: Evidence | None = None
    reads_event_reason: Reason | None = None
    notes: str | None = None

    @model_validator(mode="after")
    def _check(self) -> AiAction:
        if not self.prompt_inputs and not self.reads_event:
            raise ValueError(f"{self.id}: an AI action needs prompt_inputs or reads_event")
        if self.reads_event and (self.reads_event_evidence is None or not self.reads_event_reason):
            raise ValueError(f"{self.id}: reads_event needs reads_event_evidence and a reason")
        for field in (
            "prompt_inputs",
            "tool_config_inputs",
            "credential_inputs",
            "sandbox_inputs",
            "actor_gate_inputs",
        ):
            _unique(getattr(self, field), f"{self.id} {field} entry")
        return self


class AiActionsCatalog(_Model):
    version: Literal[1]
    actions: list[AiAction]

    @model_validator(mode="after")
    def _check(self) -> AiActionsCatalog:
        _unique([a.id for a in self.actions], "action id")
        _unique([a.uses.lower() for a in self.actions], "action uses")
        return self

    def find(self, uses: str) -> AiAction | None:
        """The action a step's ``uses:`` value refers to, ignoring ``@ref`` and case."""
        name = uses.split("@", 1)[0].strip().rstrip("/").lower()
        return next((a for a in self.actions if a.uses.lower() == name), None)


# -- MCP servers ----------------------------------------------------------------------------------

CapabilityCategory = SourceCategory | SinkCategory


class ServerMatch(_Model):
    packages: list[Name]
    images: list[Name]
    urls: list[Url]

    @model_validator(mode="after")
    def _not_empty(self) -> ServerMatch:
        if not (self.packages or self.images or self.urls):
            raise ValueError("match needs at least one package, image or url")
        return self


class Capability(_Model):
    category: CapabilityCategory
    evidence: Evidence
    evidence_reason: Reason
    description: str = Field(min_length=1)
    tools: list[Name]


class McpServer(_Sourced):
    id: Id
    description: str = Field(min_length=1)
    match: ServerMatch
    capabilities: list[Capability]
    notes: str | None = None

    @model_validator(mode="after")
    def _check(self) -> McpServer:
        _unique([str(c.category) for c in self.capabilities], f"{self.id} capability category")
        return self


_VERSIONED_PACKAGE = re.compile(r"^(?P<name>@?[^@]+)(@[^@]+)?$")


class McpServersCatalog(_Model):
    version: Literal[1]
    servers: list[McpServer]

    @model_validator(mode="after")
    def _check(self) -> McpServersCatalog:
        _unique([s.id for s in self.servers], "server id")
        for what in ("packages", "images", "urls"):
            _unique(
                [v for s in self.servers for v in getattr(s.match, what)], f"match {what} entry"
            )
        return self

    def find(
        self, args: list[str] | tuple[str, ...] = (), url: str | None = None
    ) -> McpServer | None:
        """The server a config entry launches, from its command arguments or its URL."""
        names = {_strip_version(a) for a in args}
        images = {_strip_tag(a) for a in args}
        wanted_url = url.rstrip("/") if url else None
        for server in self.servers:
            if names & set(server.match.packages) or images & set(server.match.images):
                return server
            if wanted_url and wanted_url in {u.rstrip("/") for u in server.match.urls}:
                return server
        return None


def _strip_version(arg: str) -> str:
    match = _VERSIONED_PACKAGE.match(arg)
    return match.group("name") if match else arg


def _strip_tag(arg: str) -> str:
    image = arg.split("@", 1)[0]
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        image = image[: len(image) - len(last)] + last.split(":", 1)[0]
    return image


# -- loading --------------------------------------------------------------------------------------

MODELS: dict[str, type[_Model]] = {
    "gha_triggers": GhaTriggersCatalog,
    "ai_actions": AiActionsCatalog,
    "mcp_servers": McpServersCatalog,
}


def read_raw(name: str) -> Any:
    """The parsed YAML of one catalog, before validation."""
    text = resources.files(__name__).joinpath(CATALOG_FILES[name]).read_text(encoding="utf-8")
    return YAML(typ="safe", pure=True).load(text)


@cache
def gha_triggers() -> GhaTriggersCatalog:
    return GhaTriggersCatalog.model_validate(read_raw("gha_triggers"))


@cache
def ai_actions() -> AiActionsCatalog:
    return AiActionsCatalog.model_validate(read_raw("ai_actions"))


@cache
def mcp_servers() -> McpServersCatalog:
    return McpServersCatalog.model_validate(read_raw("mcp_servers"))


def json_schema(name: str) -> dict[str, Any]:
    """The JSON schema of one catalog, generated from its model."""
    schema = MODELS[name].model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"https://github.com/aakashsiwach/taintmap/schemas/{name}.schema.json"
    return schema


def schema_text(name: str) -> str:
    return json.dumps(json_schema(name), indent=2, sort_keys=True) + "\n"


SCHEMA_DIR = Path(__file__).parent / "schemas"


def write_schemas(directory: Path = SCHEMA_DIR) -> list[Path]:
    """Regenerate the checked-in JSON schemas."""
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name in MODELS:
        target = directory / f"{name}.schema.json"
        target.write_text(schema_text(name), encoding="utf-8", newline="\n")
        written.append(target)
    return written
