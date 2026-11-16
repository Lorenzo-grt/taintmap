# Changelog

All notable changes to taintmap are listed here. Benchmark numbers for a release are measured once, on the
tagged commit, and are not updated afterwards.

## Unreleased

### Changed
- An AI agent's command execution (`sink.code_exec` from an allowed shell tool such as `Bash`) is now
  located on the `with:` input that allows it, for example the `claude_args:` line, instead of on the
  step line. The line each node kind uses is documented in `docs/benchmark.md`. Dev cases were updated to
  this convention; the held-out test cases were not changed.
- A TM002 finding for an AI action's own model credential that is raised to `high` because the agent can
  run commands or reach the network is now marked `[inferred]`, with the reason shown in both reports.
  The held-out unexpected TM002 in `tm003-pr-agent-bash` came from this rating.

### Added
- `results/bench-test-v0.1.txt`: the v0.1.0 held-out results, transcribed from the single `--final` run.

## 0.1.0 - 2026-11-16

The first release, tagged on commit `411c672`.

### Added
- Graph model (`Location`, `Node`, `Edge`, `Finding`, `GraphFragment`) with deterministic merging, path
  search and JSON export.
- File discovery with skip rules, include/exclude globs, symlink containment and deduplication.
- YAML and JSON loaders that keep line numbers and turn malformed files into warnings.
- The threat-model taxonomy in code, checked against `docs/threat-model.md`.
- Catalogs with a source link and an evidence level (`documented` or `inferred`) for every entry:
  untrusted GitHub Actions triggers and contexts, AI agent actions (`claude-code-action`, `codex-action`,
  `run-gemini-cli`) and well-known MCP servers.
- GitHub Actions parser: untrusted triggers, jobs and steps, AI agent steps, untrusted `${{ }}`
  expressions, `run:` scripts, effective token permissions (assumed write when none are declared,
  configurable with `--default-token-permissions`), secrets, trusted-actor gates that only block input
  from the author they check, declared environments and env-based input isolation.
- MCP config parser for `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` and
  `claude_desktop_config.json`, with hardcoded-secret detection that never records values.
- Cross-file linking of AI action steps to the MCP servers their tool config allows, control evaluation
  and source-to-sink path search.
- Rules TM001–TM005. Findings relying on assumed token permissions are one severity level lower and ask
  for explicit permissions. An AI action's own model credential is TM002 `high` only when the agent can
  also run commands or reach the network, otherwise `info`.
- `taintmap scan` with terminal and JSON (`schema_version: 1`) reports. The terminal report groups
  findings by source and agent and names missing controls in plain language.
- `taintmap bench` with 20 dev cases and 8 independently written held-out test cases; `--final` is
  required for the test split.

### Benchmark
Measured on `411c672` in a single `--final` run of the held-out test split, against the original case
expectations:

| Split | Cases | Recall | Precision | False-positive rate on safe cases |
|---|---|---|---|---|
| test | 8 (5 vulnerable, 3 safe) | 0.80 (4/5) | 0.67 (4/6) | 0.00 (0/3) |
| dev | 20 (10 vulnerable, 10 safe) | 1.00 (12/12) | 1.00 (12/12) | 0.00 (0/10) |

Per rule on the test split (recall / precision): TM001 1.00 / 1.00, TM002 1.00 / 0.50, TM003 0.00 / 0.00,
TM004 1.00 / 1.00, TM005 1.00 / 1.00. Both errors are in `tm003-pr-agent-bash`: TM003 expected at
`review.yml:3 -> review.yml:15` was missed, and TM003 `review.yml:3 -> review.yml:11` (critical) and TM002
`review.yml:3 -> review.yml:13` (high) were unexpected.
