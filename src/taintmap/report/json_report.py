"""JSON report with a stable, versioned schema (``schema_version: 1``)."""

from __future__ import annotations

import json
from importlib.metadata import version
from typing import Any

from taintmap.graph import Graph
from taintmap.model import Finding, Location, Severity
from taintmap.report import at_least, counts, inferred_reasons, role
from taintmap.scan import ScanResult

SCHEMA_VERSION = 1


def _hop(graph: Graph, node_id: str, location: Location) -> dict[str, Any]:
    node = graph.node(node_id)
    return {
        "id": node.id,
        "role": role(node),
        "kind": node.kind.value,
        "category": node.category,
        "label": node.label,
        "file": location.file,
        "line": location.line,
    }


def _finding(graph: Graph, finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "fingerprint": finding.fingerprint,
        "inferred": finding.inferred,
        "inferred_reasons": inferred_reasons(graph, finding) if finding.inferred else [],
        "permissions_assumed": finding.permissions_assumed,
        "missing_control": finding.missing_control,
        "fix": finding.fix,
        "path": [
            _hop(graph, n, loc) for n, loc in zip(finding.path, finding.evidence, strict=True)
        ],
        "via_servers": [_hop(graph, s, graph.node(s).location) for s in finding.via_servers],
        "related": [
            _hop(graph, n, loc)
            for n, loc in zip(finding.related, finding.related_evidence, strict=True)
        ],
    }


def report(result: ScanResult, min_severity: Severity = Severity.LOW) -> dict[str, Any]:
    shown = at_least(result.findings, min_severity)
    return {
        "schema_version": SCHEMA_VERSION,
        "taintmap_version": version("taintmap"),
        "summary": {
            "findings": len(shown),
            "by_severity": counts(shown),
            "min_severity": min_severity.value,
            "not_shown": len(result.findings) - len(shown),
            "files_scanned": len(result.files),
            "parse_errors": len(result.parse_errors),
        },
        "findings": [_finding(result.graph, f) for f in shown],
        "warnings": [w.model_dump(mode="json") for w in result.warnings],
        "files": result.files,
    }


def render(result: ScanResult, min_severity: Severity = Severity.LOW) -> str:
    return json.dumps(report(result, min_severity), indent=2, ensure_ascii=False) + "\n"
