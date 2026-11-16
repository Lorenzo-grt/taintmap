"""Core data model: locations, nodes, edges, findings and graph fragments.

See docs/architecture.md ("Data model") for the meaning of each field.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class NodeKind(StrEnum):
    """The role a node plays on a path."""

    SOURCE = "source"
    CARRIER = "carrier"
    CAPABILITY = "capability"
    CODE = "code"
    SINK = "sink"
    CONTROL = "control"


class EdgeKind(StrEnum):
    """The relationship an edge declares between two nodes."""

    PASSES_INPUT = "passes_input"
    CAN_CALL = "can_call"
    RUNS_WITH = "runs_with"
    INVOKES = "invokes"
    WRITES_TO = "writes_to"
    GUARDED_BY = "guarded_by"


class Severity(StrEnum):
    """Finding severity, from least to most severe."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric order: ``low`` is 0, ``critical`` is 3."""
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Location(_Model):
    """A place in a scanned file.

    ``file`` is relative to the scanned root and always uses POSIX separators.
    """

    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    snippet: str | None = None

    @field_validator("file")
    @classmethod
    def _posix_separators(cls, value: str) -> str:
        return value.replace("\\", "/")

    @field_validator("snippet")
    @classmethod
    def _single_trimmed_line(cls, value: str | None) -> str | None:
        if value is None:
            return None
        lines = value.strip().splitlines()
        return lines[0].strip() if lines else ""

    @model_validator(mode="after")
    def _end_after_start(self) -> Location:
        if self.end_line is not None and self.end_line < self.line:
            raise ValueError(f"end_line {self.end_line} is before line {self.line}")
        return self

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


class Node(_Model):
    """A source, carrier, capability, code element, sink or control."""

    id: str = Field(min_length=1)
    kind: NodeKind
    category: str = Field(min_length=1)
    label: str
    location: Location
    attrs: dict[str, Any] = Field(default_factory=dict)


class Edge(_Model):
    """A directed relationship between two nodes, identified by their ids."""

    src: str = Field(min_length=1)
    dst: str = Field(min_length=1)
    kind: EdgeKind
    location: Location

    def sort_key(self) -> tuple[str, str, str, str, int]:
        """A key that orders edges deterministically."""
        return (self.src, self.dst, self.kind.value, self.location.file, self.location.line)


def compute_fingerprint(rule_id: str, path: list[str]) -> str:
    """Return a stable hash of a rule id and the node ids on a path."""
    payload = "\x1f".join([rule_id, *path]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


class Finding(_Model):
    """A path that a rule reports, with evidence for every hop and a suggested fix.

    ``fingerprint`` is computed from ``rule_id`` and ``path`` when not given.
    """

    rule_id: str = Field(min_length=1)
    severity: Severity
    title: str
    path: list[str] = Field(min_length=1)
    evidence: list[Location]
    missing_control: str
    fix: str
    fingerprint: str = ""

    @model_validator(mode="after")
    def _fill_fingerprint(self) -> Finding:
        expected = compute_fingerprint(self.rule_id, self.path)
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", expected)
        elif self.fingerprint != expected:
            raise ValueError("fingerprint does not match rule_id and path")
        return self


class ParseWarning(_Model):
    """A file that could not be read or parsed. Reported to the user; never a crash.

    Messages must never contain values from the file, only key names, so that secrets in a
    malformed file are not echoed.
    """

    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    message: str

    @field_validator("file")
    @classmethod
    def _posix_separators(cls, value: str) -> str:
        return value.replace("\\", "/")

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: {self.message}"


class GraphFragment(_Model):
    """The nodes and edges one parser produced from one file (or one group of files).

    ``warnings`` carries parse problems from the parser to the report. The graph does not store
    them, so they are not part of the graph's JSON export.
    """

    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    warnings: list[ParseWarning] = Field(default_factory=list)
