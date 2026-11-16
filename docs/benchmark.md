# Benchmark

taintmap's accuracy is measured on an open benchmark of small, deliberately designed example systems.
Every release reports its numbers on it.

## A case

```text
benchmark/cases/gha-issue-agent-write/
  case.yaml                      metadata and expected findings
  .github/workflows/triage.yml   the minimal files that make up the example system
```

`case.yaml`:

```yaml
id: gha-issue-agent-write
description: An issue-triggered workflow runs an AI agent with contents write permission.
kind: vulnerable            # vulnerable | safe
expected:
  - rule: TM001
    source: .github/workflows/triage.yml:3     # file:line of the source node
    sink: .github/workflows/triage.yml:8       # file:line of the sink node
```

A **safe** case has `kind: safe` and `expected: []`. Safe cases are usually the vulnerable case plus the
fix, for example the same workflow with a trusted-actor gate. They measure false positives.

## Rules for cases

- **Minimal:** only the files and lines needed to show the pattern.
- **Synthetic:** no copies of real projects' vulnerable files, and no real credentials. Use obvious
  placeholders such as `FAKE_TOKEN_FOR_TESTS`.
- **Defensive:** a case describes a configuration pattern. It never contains an exploit payload.
- **Paired:** every vulnerable case should have at least one safe twin.

## Running it

```bash
taintmap bench --split dev                       # metrics, per-rule table, misses and unexpected findings
taintmap bench --split dev --format json         # the same as JSON
taintmap bench --split test --final              # held-out cases, for releases only
```

`--split test` is refused without `--final`. CI runs the dev split and checks that `results/bench-dev.txt`
and `results/bench-dev.json` are up to date. A malformed case (missing `case.yaml`, a safe case with
expected findings, a vulnerable case without any) stops the run with an error; unknown fields in
`case.yaml` are ignored.

## Matching

A produced finding matches an expected one when the rule id is equal and both the source and sink
locations are equal (same file, same line). Each expected finding can be matched once. Only findings at `low` severity or above count as produced
findings; `info` findings are notes, not claims that the case is vulnerable.

## Locations

An expected `source` and `sink` is the `file:line` of the first and last node on the finding's path. Each
kind of node has one fixed line:

| Node | Line |
|---|---|
| Workflow trigger (source) | the trigger's name under `on:`: its key, its list item, or the `on:` line for `on: issues` |
| Job | the job's key under `jobs:` |
| Step | the step's list item (the `- ` line) |
| `run:` script (`sink.code_exec`) | the `run:` key |
| Agent command execution (`sink.code_exec`) | the `with:` input that allows the shell tool, e.g. `claude_args:` or `settings:` |
| Secret (`sink.secret.read`) | the `env:` or `with:` key whose value references `secrets.*` |
| Token permission (`sink.repo.write`, `sink.deploy`, `sink.secret.read` for `id-token`) | the first write scope of that category under the effective `permissions:`; the `permissions:` line for `write-all`; the job key when no permissions are declared |
| Controls | the `if:`, `environment:` or (for input isolation) `run:` key |
| MCP client (`carrier.llm_agent`) | the `mcpServers` or `servers` key |
| MCP server and each of its catalogued capabilities | the server's key |
| Hardcoded MCP secret | the key under the server's `env` or `headers` |

For TM004 the sink is the outbound-network capability; the sensitive access is reported separately and is
not part of matching.

## Metrics

| Metric | Definition |
|---|---|
| Recall | matched expected findings ÷ all expected findings |
| Precision | matched findings ÷ all produced findings |
| False-positive rate on safe cases | safe cases with at least one finding ÷ all safe cases |

`taintmap bench` prints these overall and per rule, and lists every missed and unexpected finding.

## Dev and test splits

`benchmark/splits.yaml` assigns each case to `dev` or `test`, stratified by rule. Rules are tuned on
`dev` only. `test` is run for releases with `taintmap bench --split test --final`, and those numbers go in
the release notes. Never change a test case to improve a number. If a test case is wrong, fix it in its
own pull request that explains why, and note it in the changelog.
