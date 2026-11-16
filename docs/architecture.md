# Architecture

This document describes how taintmap is built. The plan for building it is in [plan.md](plan.md), and the
taxonomy of sources, sinks and controls is in [threat-model.md](threat-model.md).

## Pipeline

```text
repository
   │
   ▼
1. discover      find files each parser understands (workflows, MCP configs, agent configs, code)
   │
   ▼
2. parse         each parser turns its files into a GraphFragment: nodes + edges, with file/line locations
   │
   ▼
3. link          merge fragments and connect them across files (agent → MCP server by name,
   │             tool → code by endpoint or method, workflow step → action catalog entry)
   ▼
4. find paths    walk from every source node to every sink node; drop paths blocked by an effective control
   │
   ▼
5. classify      rules turn remaining paths into findings with a rule id, severity, missing control and fix
   │
   ▼
6. report        terminal, JSON, and later SARIF
```

Every stage is deterministic. No stage calls an LLM or the network. The same input always produces the
same output, which keeps findings explainable and the benchmark reproducible.

## Data model

All models are Pydantic v2 classes in `src/taintmap/model.py`.

### Location
`file` (path relative to the scanned root, POSIX separators), `line` (1-based), optional `end_line`,
optional `snippet` (one line, trimmed).

### Node
| Field | Meaning |
|---|---|
| `id` | Stable, unique string, e.g. `gha:.github/workflows/triage.yml:job:triage:step:2` |
| `kind` | `source`, `carrier`, `capability`, `code`, `sink`, `control` |
| `category` | Taxonomy id from the threat model, e.g. `source.untrusted.issue_text`, `sink.repo.write` |
| `label` | Short human-readable name |
| `location` | Where it is defined |
| `attrs` | Free-form dict for parser-specific details |

### Edge
| Field | Meaning |
|---|---|
| `src`, `dst` | Node ids |
| `kind` | `passes_input`, `can_call`, `runs_with`, `invokes`, `writes_to`, `guarded_by` |
| `location` | Where the relationship is declared |

`guarded_by` edges point from a node to a `control` node. A control is **effective** for a path when it
guards any node on that path and its category blocks the path's risk class (see threat model).

### Finding
`rule_id`, `severity` (`low`, `medium`, `high`, `critical`), `title`, `path` (ordered node ids),
`evidence` (one location per hop), `missing_control`, `fix` (one or two sentences), `fingerprint`
(stable hash of rule id + path node ids, used to track a finding across runs).

### Graph
`src/taintmap/graph.py` wraps a `networkx.MultiDiGraph`. It offers `add_fragment`, `nodes_of_kind`,
`paths(source, sink, max_depth)`, and JSON export (`taintmap graph --json`) for debugging.

Node ids are unique: re-adding an identical node is a no-op, while the same id with different content is an
error. `paths` returns sorted simple paths of at most `max_depth` edges and does not follow `guarded_by`
edges, since those point to controls rather than carrying input. The JSON export carries `schema_version: 1`.

## Parsers

A parser implements:

```python
class Parser(Protocol):
    name: str

    def matches(self, path: Path) -> bool: ...
    def parse(self, path: Path, root: Path) -> GraphFragment: ...
```

Parsers are registered through the `taintmap.parsers` entry-point group, so third-party packages can add
parsers without changing taintmap. Built-in parsers for v0.1:

| Parser | Files |
|---|---|
| `github_actions` | `.github/workflows/*.yml`, `.github/workflows/*.yaml` |
| `mcp_config` | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, and files listed in `taintmap.yaml` |

Planned: `java_spring` (v0.2), `taintmap_manifest` for hand-declared agents and tools (v0.2), and importers
for SARIF from other scanners (v0.3).

### Line numbers
YAML is loaded with `ruamel.yaml` in round-trip mode, which keeps line information for every mapping and
sequence item. JSON has no line information in the standard library, so `src/taintmap/loaders/json_lines.py`
provides a small locator that maps a JSON pointer to its line by scanning tokens. Evidence without a line
number is a bug.

Malformed files never crash a scan: the loaders return a parse warning (file, line, message) instead.
Warning messages name keys but never quote values, so a secret in a broken file is not echoed. YAML is
read as YAML 1.2 (`on:` stays a string) and duplicate keys are an error. JSON must be strict (no comments
or trailing commas); when a JSON object repeats a key, the last value is used and a warning is raised.

## Catalogs

Knowledge about third-party components lives in data files, not code, so contributors can extend it with a
small pull request:

- `src/taintmap/catalog/ai_actions.yaml`: GitHub Actions that run AI agents, and which inputs carry
  prompts, tool allow-lists and credentials.
- `src/taintmap/catalog/mcp_servers.yaml`: known MCP servers (matched by package name or command) and
  the capabilities their tools provide: reads untrusted content, writes files, executes commands, makes
  outbound requests, accesses a database.
- `src/taintmap/catalog/gha_triggers.yaml`: workflow triggers and expression contexts that carry
  untrusted input.

Each catalog entry has an id, a description, the evidence it relies on (an `evidence` field with a
documentation link), and the taxonomy categories it maps to. The structure is defined by Pydantic models in
`src/taintmap/catalog/__init__.py`; the JSON schemas in `src/taintmap/catalog/schemas/` are generated from
them with `python -m taintmap.catalog`, and a test fails when the checked-in schemas are out of date or an
entry does not validate.

## Rules

Rules live in `src/taintmap/rules/`, one module per rule, each with an id (`TM001`...), a title, the risk
class it detects, a severity function and a fix template. A rule receives candidate paths and returns
findings. Rules never parse files; they only read the graph.

## Reporters

- `terminal`: grouped by severity, one block per finding showing each hop with file:line (rich).
- `json`: stable schema, versioned with a `schema_version` field.
- `sarif` (v0.2): SARIF 2.1.0 for GitHub code scanning.

## CLI

```text
taintmap scan [PATH] [--format terminal|json] [--output FILE] [--min-severity LEVEL] [--fail-on LEVEL]
taintmap graph [PATH] --json          # dump the graph for debugging
taintmap bench [--split dev|test]     # run the benchmark and report recall and false-positive rate
taintmap version
```

Exit codes: `0` no findings at or above `--fail-on`, `1` findings found, `2` usage or parse error.

## Project layout

```text
src/taintmap/
  cli.py              Typer app
  model.py            Location, Node, Edge, Finding, GraphFragment
  graph.py            Graph wrapper, path search
  discover.py         file discovery with include/exclude
  taxonomy.py         category ids from threat-model.md and what each control blocks
  loaders/            yaml_lines.py, json_lines.py
  parsers/            github_actions.py, mcp_config.py
  catalog/            *.yaml data + loader + schemas
  link.py             cross-file linking
  controls.py         control evaluation
  rules/              tm001_*.py ...
  report/             terminal.py, json_report.py
benchmark/
  cases/<case-id>/    files of a minimal example system + expected.yaml
  splits.yaml         dev and test case ids
tests/                unit tests per module, plus end-to-end tests on benchmark cases
```

## Technology choices

| Need | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | Matches the tooling ecosystem and contributors' skills |
| Packaging | `pyproject.toml` with hatchling | Standard, simple |
| CLI | Typer + rich | Clear help text, readable output |
| Models | Pydantic v2 | Validation and stable JSON |
| Graph | NetworkX | Mature path algorithms |
| YAML | ruamel.yaml | Line numbers |
| Java (v0.2) | tree-sitter + tree-sitter-java | Fast, robust parsing |
| Quality | pytest, ruff, mypy (strict on `src/`) | Run in CI on every push |
