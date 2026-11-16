"""Terminal report: grouped by severity, one block per finding, each hop with ``file:line``.

Output is plain ASCII so it prints on any console, including legacy Windows code pages.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from taintmap.model import Finding, Node, Severity
from taintmap.report import at_least, counts, inferred_reasons, role
from taintmap.scan import ScanResult

STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
}
LABEL_WIDTH = 8


def render(result: ScanResult, console: Console, min_severity: Severity = Severity.LOW) -> None:
    findings = at_least(result.findings, min_severity)
    current: Severity | None = None
    for finding in findings:
        if finding.severity is not current:
            current = finding.severity
            group = [f for f in findings if f.severity is current]
            console.print(Text(f"== {current.value.upper()} ({len(group)})", style="bold"))
            console.print()
        _finding(result, finding, console)
        console.print()
    _notes(result, console)
    console.print(_summary(result, findings, min_severity))


def _row(label: str, location: str, text: str, location_width: int) -> Text:
    row = Text("  ")
    row.append(f"{label:<{LABEL_WIDTH}}", style="dim")
    row.append(f"{location:<{location_width}}  ", style="cyan")
    row.append(text)
    return row


def _finding(result: ScanResult, finding: Finding, console: Console) -> None:
    graph = result.graph
    head = Text()
    head.append(f"{finding.severity.value.upper():<8}", style=STYLES[finding.severity])
    head.append(f" {finding.rule_id}  ", style="bold")
    head.append(finding.title, style="bold")
    if finding.inferred:
        head.append("  [inferred]", style="magenta")
    console.print(head)

    hops = [
        (graph.node(n), str(loc)) for n, loc in zip(finding.path, finding.evidence, strict=True)
    ]
    related = [
        (graph.node(n), str(loc))
        for n, loc in zip(finding.related, finding.related_evidence, strict=True)
    ]
    servers = [(graph.node(s), str(graph.node(s).location)) for s in finding.via_servers]
    width = max(len(loc) for _, loc in [*hops, *related, *servers])

    for node, loc in hops:
        console.print(_row(role(node), loc, _describe(node), width))
    for node, loc in servers:
        console.print(_row("via", loc, f"MCP server {node.label}", width))
    for node, loc in related:
        console.print(_row("also", loc, _describe(node), width))
    console.print(_row("missing", "", finding.missing_control, 0))
    console.print(_row("fix", "", finding.fix, 0))
    if finding.inferred:
        for reason in inferred_reasons(graph, finding):
            console.print(_row("inferred", "", reason, 0))
    if finding.permissions_assumed:
        console.print(
            _row("note", "", "token permissions are assumed (none declared); severity lowered", 0)
        )


def _describe(node: Node) -> str:
    """The node's label, with its category when the label does not already say it."""
    return node.label if node.category in node.label else f"{node.label}  ({node.category})"


def _notes(result: ScanResult, console: Console) -> None:
    if not result.warnings:
        return
    console.print(Text("== NOTES", style="bold"))
    for warning in result.warnings:
        style = "yellow" if warning.level == "warning" else "dim"
        line = Text("  ")
        line.append(f"{warning.level:<{LABEL_WIDTH}}", style=style)
        line.append(f"{warning.file}:{warning.line}  ", style="cyan")
        line.append(warning.message)
        console.print(line)
    console.print()


def _summary(result: ScanResult, shown: list[Finding], min_severity: Severity) -> Text:
    by_severity = ", ".join(f"{n} {s}" for s, n in counts(shown).items() if n)
    text = Text(f"{len(shown)} finding{'s' if len(shown) != 1 else ''}", style="bold")
    if by_severity:
        text.append(f" ({by_severity})")
    hidden = len(result.findings) - len(shown)
    if hidden:
        text.append(f", {hidden} below {min_severity.value} not shown")
    files = len(result.files)
    text.append(f" in {files} file{'s' if files != 1 else ''}")
    errors = len(result.parse_errors)
    if errors:
        text.append(f"; {errors} file problem{'s' if errors != 1 else ''}", style="yellow")
    return text
