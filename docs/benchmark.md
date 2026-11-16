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
