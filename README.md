# taintmap

**Map how untrusted input flows through your AI agents, automations and code, before attackers do.**

> **Status: design stage.** There is no usable release yet. This repository holds the vision, the design and
> the roadmap. Feedback and contributors are very welcome; see [Contributing](#contributing).

---

## The problem

AI agents and automations now read emails, GitHub issues, web pages and support tickets. They call tools
that touch databases, secrets, payments and production. Each piece can look safe on its own. The danger is
the **path** between them:

```text
untrusted input  ──▶  agent / workflow  ──▶  tool  ──▶  application code  ──▶  sensitive action
(issue text)          (LLM agent)            (run_sql)   (UserRepository)      (delete all users)
```

Most security scanners look at one file or one component at a time: an MCP config, a CI workflow, or the
application code. Nobody draws the whole map. taintmap does.

## What taintmap will do

1. **Build one graph of the whole system**: agent and MCP tool configurations, CI/CD workflows (starting
   with GitHub Actions), and the application code those tools call (starting with Java/Spring).
2. **Find dangerous paths** from untrusted **sources** (user input, issues, emails, web content) to
   sensitive **sinks** (secrets, data deletion, payments, outbound network, production changes).
3. **Explain every finding with evidence**: the exact path, the files and lines on it, why it is risky, and
   a concrete fix such as removing a permission, adding human approval or validating input.
4. **Reuse existing scanners** as inputs instead of rewriting them, and add the cross-system view on top.
5. **Report where developers already look**: terminal, JSON and SARIF (GitHub's Security tab).

Planned usage:

```bash
pip install taintmap
taintmap scan .
```

Illustrative output (planned format):

```text
HIGH  untrusted-input → destructive-action
  source  .github/workflows/triage.yml:12   issue body passed to agent prompt
  agent   agents/triage-agent.yaml:4        has tool: run_sql
  tool    mcp/db-server.json:18             run_sql allows DELETE, no approval
  sink    src/main/java/.../UserRepository.java:41   deleteAll()
  fix     restrict run_sql to SELECT, or require human approval for writes
```

## Principles

- **Evidence over opinions.** Every finding shows its full path and the lines involved. No path, no finding.
- **Measured accuracy.** taintmap ships with a public benchmark of deliberately vulnerable setups, and
  every release reports recall and false-positive rate on it.
- **Defensive only.** taintmap finds and explains risks so they can be fixed. It does not generate exploits.
- **Responsible disclosure.** If you find a vulnerability in someone else's project with taintmap, report
  it privately (GitHub private vulnerability reporting or the project's `SECURITY.md`), never in a public
  issue or pull request first.
- **Humans decide.** taintmap informs people; it does not auto-report to other projects on anyone's behalf.

## Roadmap

| Milestone | Scope |
|---|---|
| **v0.1** | Graph model; parsers for MCP/agent configs and GitHub Actions; source → sink path finding; terminal and JSON output |
| **v0.2** | Java/Spring code layer (tool → controller/service → repository); SARIF output; first public benchmark |
| **v0.3** | GitHub Action and pre-commit hook; import findings from existing scanners |
| **later** | More frameworks (Python, Node, n8n), runtime traces, fix suggestions as patches |

## Documentation

| Document | What it covers |
|---|---|
| [VISION.md](VISION.md) | Why taintmap exists and where it is going |
| [docs/architecture.md](docs/architecture.md) | Pipeline, data model, parsers, catalogs, rules, CLI, project layout |
| [docs/threat-model.md](docs/threat-model.md) | Sources, carriers, sinks, controls and the v0.1 rules |
| [docs/benchmark.md](docs/benchmark.md) | How accuracy is measured: cases, matching, metrics, dev/test splits |
| [docs/plan.md](docs/plan.md) | The task-by-task build plan with acceptance criteria |

## Contributing

taintmap is designed to be built by many people. Each detection rule, framework adapter and benchmark case
is a small, self-contained contribution. Good ways to help right now:

- **Benchmark cases:** small, deliberately vulnerable example setups with the expected finding.
- **Source and sink definitions** for frameworks and tools you know.
- **Design feedback:** open an issue or a discussion on the graph model and the roadmap.

A full contributing guide will arrive with v0.1.

## License

[MIT](LICENSE) © Aakash Siwach
