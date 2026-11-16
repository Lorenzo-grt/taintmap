# taintmap

**Map how untrusted input flows through your AI agents, automations and code, before attackers do.**

> **Status: v0.1.0, early.** taintmap scans GitHub Actions workflows and MCP client configs today; the code
> layer (Java/Spring) and SARIF output are planned. Feedback and contributors are very welcome; see
> [Contributing](#contributing).

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

## Usage

Install from the v0.1.0 tag and scan a repository:

```bash
pip install "git+https://github.com/aakashsiwach/taintmap@v0.1.0"
taintmap scan .
taintmap scan . --format json --output taintmap.json
taintmap scan . --fail-on high --default-token-permissions read
```

v0.1 reads `.github/workflows/*.yml`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` and
`claude_desktop_config.json`. Findings are grouped by untrusted source and agent; each hop is shown with
its `file:line`:

```text
== on: issue_comment (.github/workflows/respond.yml:2) -> agent anthropics/claude-code-action@v1 (.github/workflows/respond.yml:9)  [1 finding, highest HIGH]

HIGH     TM001  Untrusted input reaches an AI agent with write access  [inferred]
  source  .github/workflows/respond.yml:2  on: issue_comment  (source.untrusted.issue_text)
  agent   .github/workflows/respond.yml:9  anthropics/claude-code-action@v1  (carrier.llm_agent)
  sink    .github/workflows/respond.yml:4  GITHUB_TOKEN issues: write  (sink.repo.write)
  missing   a check that only trusted people can trigger it, only the permissions it needs or human approval before it acts (e.g. a protected environment)
  fix       Gate the job with `if:` on `github.event.comment.author_association` (OWNER, MEMBER or COLLABORATOR), or remove `issues: write` from the job's `permissions:` if the agent does not need it.
```

Exit codes: `0` no findings at or above `--fail-on`, `1` findings, `2` usage or parse error. See
[docs/architecture.md](docs/architecture.md#cli) for every option.

## Results

Accuracy is measured on the open benchmark described in [docs/benchmark.md](docs/benchmark.md). The v0.1.0
numbers below were measured on commit `411c672` (tag `v0.1.0`) in a single `--final` run of the held-out
test split, against the original expectations of its eight independently written cases.

| Split | Cases | Recall | Precision | False-positive rate on safe cases |
|---|---|---|---|---|
| test (held out) | 8 (5 vulnerable, 3 safe) | 0.80 (4/5) | 0.67 (4/6) | 0.00 (0/3) |
| dev (used for tuning) | 20 (10 vulnerable, 10 safe) | 1.00 (12/12) | 1.00 (12/12) | 0.00 (0/10) |

Per rule on the test split (recall / precision): TM001 1.00 / 1.00, TM002 1.00 / 0.50, TM003 0.00 / 0.00,
TM004 1.00 / 1.00, TM005 1.00 / 1.00. Both errors are in one case, `tm003-pr-agent-bash`: the
command-execution sink was reported on a different line than expected, and a TM002 finding for the agent's
model credential was not expected. The full output is in
[results/bench-test-v0.1.txt](results/bench-test-v0.1.txt). Changes made after v0.1.0 are listed under
*Unreleased* in the [changelog](CHANGELOG.md); they do not change the v0.1.0 numbers, which stay as
measured.

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
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release |

## Contributing

taintmap is designed to be built by many people. Each detection rule, framework adapter and benchmark case
is a small, self-contained contribution. Good ways to help right now:

- **Benchmark cases:** small, deliberately vulnerable example setups with the expected finding.
- **Source and sink definitions** for frameworks and tools you know.
- **Design feedback:** open an issue or a discussion on the graph model and the roadmap.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and checks.

## License

[MIT](LICENSE) © Aakash Siwach
