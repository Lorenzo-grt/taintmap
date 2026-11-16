# taintmap: vision and design

*Author: Aakash Siwach ([@aakashsiwach](https://github.com/aakashsiwach))*

## Why now

Software is changing in two ways at once:

1. **AI agents act, not just answer.** They read untrusted content and call tools with real permissions:
   databases, cloud accounts, payments, email, production deployments.
2. **Systems are glued together by automation.** CI/CD workflows, MCP servers, agent frameworks and
   no-code automations connect components that were designed and reviewed separately.

Security tools grew up around single artifacts: a source file, a dependency, a workflow file, a config.
The new risks live **between** artifacts. A prompt-injectable agent is harmless if its tools are
read-only. A powerful database tool is harmless if only trusted code can reach it. Put them together and
an attacker who can write a GitHub issue can delete production data.

The question every team adding AI agents needs answered is:

> **Can untrusted input reach anything dangerous, and by which path?**

taintmap exists to answer that question with evidence.

## Core idea: taint analysis across the whole system

Taint analysis is an established technique: mark data from untrusted sources as *tainted*, follow it
through the program, and flag it when it reaches a sensitive *sink* without being sanitised. taintmap
applies the same idea at system level, across agents, tools, workflows and code.

### The graph

| Node type | Examples |
|---|---|
| **Source** | issue/PR text, email body, web page, user chat message, uploaded file, webhook payload |
| **Carrier** | LLM agent, CI workflow step, automation node, MCP server |
| **Capability** | MCP tool, workflow permission, cloud credential, API token |
| **Code** | controller, service and repository methods reached by a tool |
| **Sink** | data deletion or modification, secret access, outbound network, payment, deployment, shell execution |

Edges record how data or control moves: *passes input to*, *can call*, *runs with permission*,
*invokes*, *writes to*.

### What counts as a finding

A finding is a path from a source to a sink where no adequate **control** sits in between. Controls
include human approval, input validation, least-privilege permissions, allow-lists and sandboxing. Every
finding reports:

- the full path, with file and line for each hop
- the risk category and severity, with the reasoning
- which control is missing, and the smallest change that adds it

## How taintmap differs from existing tools

There are good scanners for single layers: static analysis for application code, workflow auditors for
GitHub Actions, and a fast-growing set of scanners for MCP and agent configurations. taintmap does not
replace them. It:

- **connects the layers** into one graph, so cross-component paths become visible
- **imports findings** from existing scanners as nodes and edges, rather than duplicating their rules
- **follows tools into real application code**, starting with Java/Spring, where enterprise systems live
- **publishes its accuracy**, measured on an open benchmark

## Evaluation is part of the product

Security tools that are noisy get ignored, and tools that miss things give false comfort. taintmap treats
measurement as a first-class feature:

- **Open benchmark:** deliberately vulnerable example systems, each with the expected findings, plus safe
  variants that must produce *no* finding.
- **Dev and held-out splits:** rules are tuned on the dev split only; the held-out split is used to report
  release numbers, so they are not fitted to the test.
- **Every release reports** recall (dangerous paths found) and false-positive rate (safe setups flagged).

## Responsible use

taintmap is a defensive tool. It explains risks so that owners can fix them.

- It does not generate exploits or attack payloads.
- Findings in other people's projects should be reported **privately** first, through GitHub private
  vulnerability reporting or the project's security policy, and only discussed publicly after a fix.
- taintmap does not file reports or pull requests on anyone's behalf. People review findings and decide
  what to send. Maintainers' time is valuable, and unverified automated reports waste it.

## Roadmap

### Phase 1: the map (v0.1–v0.2)
- Graph model and plugin interface for parsers
- Parsers: MCP and agent configurations, GitHub Actions workflows
- Java/Spring code layer: from a tool's endpoint or call to controller, service and repository methods
- Path finding from sources to sinks, with controls
- Terminal, JSON and SARIF output
- First public benchmark

### Phase 2: in every pipeline (v0.3+)
- GitHub Action and pre-commit hook
- Importers for findings from existing scanners
- Suggested fixes as patches for common cases (narrow a permission, add an approval step)

### Phase 3: wider coverage
- Python, Node.js and no-code automation platforms
- Runtime traces from real agent runs, to confirm or rule out static paths
- Policy files: teams declare which paths are allowed, and taintmap enforces them in CI

### Long term
As organisations hand more work to AI agents, every one of them will need an independent, explainable
answer to "what can our agents reach?". taintmap aims to be the open standard for that answer: the
security map that humans and agents both rely on.

## How the project grows

- **Small, independent contributions.** Rules, source and sink definitions, framework adapters and
  benchmark cases are designed so each can be added in one focused pull request.
- **Always-open good first issues**, with clear acceptance criteria.
- **Fast, respectful reviews.** Contributors' time matters as much as maintainers'.
- **Honest reporting** of what works and what does not, in the README and release notes.

## Non-goals

- Replacing static analysis, dependency scanning or secret scanning tools
- Offensive tooling or exploit generation
- Automated mass reporting to third-party projects
