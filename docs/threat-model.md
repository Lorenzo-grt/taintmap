# Threat model

taintmap looks for paths where **untrusted input** can reach a **sensitive capability** without an
effective **control** in between. This document defines each of those terms. Catalogs and rules refer to
these category ids.

## Sources: where untrusted input enters

| Category id | Examples |
|---|---|
| `source.untrusted.issue_text` | Issue title or body, issue comments |
| `source.untrusted.pr_content` | Pull request title, body, branch name, code from a fork |
| `source.untrusted.discussion` | Discussion and review comments |
| `source.untrusted.web_content` | Pages fetched from the internet |
| `source.untrusted.email` | Email subjects and bodies |
| `source.untrusted.chat` | Messages from end users of an agent |
| `source.untrusted.file_upload` | Files supplied by users |
| `source.untrusted.webhook` | Payloads from external webhooks |

A source is untrusted when anyone outside the trusted group can write it. For example, anyone can open an
issue on a public repository.

## Carriers: what passes input along

| Category id | Examples |
|---|---|
| `carrier.llm_agent` | An agent whose prompt or context includes the input |
| `carrier.workflow_step` | A CI step that receives the input through an expression or environment variable |
| `carrier.mcp_server` | A tool server whose tool results return content to an agent |
| `carrier.automation_node` | A node in a no-code automation (later) |

LLM agents are treated as **able to be steered by any text in their context**. That is the conservative
assumption about prompt injection: if untrusted text reaches an agent, assume the agent may follow
instructions in it.

## Capabilities and sinks: what can cause harm

| Category id | Risk class | Examples |
|---|---|---|
| `sink.code_exec` | execution | Shell commands, `run:` steps, code-execution tools |
| `sink.repo.write` | integrity | Push to a branch, merge or approve a PR, edit issues and releases |
| `sink.secret.read` | confidentiality | Secrets in the environment, credential files, cloud tokens |
| `sink.data.write` | integrity | Database writes and deletes, file writes outside a sandbox |
| `sink.data.read_sensitive` | confidentiality | Private repositories, databases with personal data |
| `sink.network.outbound` | exfiltration | HTTP requests to arbitrary URLs, sending email or messages |
| `sink.deploy` | integrity | Deployments, infrastructure changes, package publishing |
| `sink.payment` | integrity | Payments and refunds |

Some dangers need a combination. **Exfiltration** needs both a way to read something sensitive and a way
to send data out; the same agent holding untrusted input, sensitive read access and outbound network
access is the classic dangerous combination (often called the "lethal trifecta").

## Controls: what blocks a path

| Category id | Blocks | Examples |
|---|---|---|
| `control.human_approval` | all | Required reviewers on a GitHub environment, a tool that requires confirmation |
| `control.trusted_actor_gate` | all from untrusted sources | `if:` conditions on `author_association` (OWNER, MEMBER, COLLABORATOR) or on a label only maintainers can add |
| `control.least_privilege` | the specific sink | `permissions: read-all` or a job-level permission set without the needed write scope |
| `control.tool_allowlist` | sinks provided by excluded tools | An agent configured with an explicit, narrow list of allowed tools |
| `control.input_isolation` | `sink.code_exec` via expression injection | Passing input through an environment variable instead of `${{ }}` in `run:` |
| `control.sandbox` | `sink.data.write`, `sink.code_exec` | Tools confined to a temporary directory or container without credentials |
| `control.network_allowlist` | `sink.network.outbound` | Outbound access limited to named hosts |

A `control.trusted_actor_gate` on `author_association` only blocks input written by the actor it
checks. On `issue_comment`, a check of `github.event.issue.author_association` says who opened the
issue, not who wrote the comment, so it does not block the comment body.

A control only counts when taintmap can see it in the scanned files. Controls that exist elsewhere (for
example, in organisation settings) can be declared in `taintmap.yaml` (v0.2).

## Rules for v0.1

| Rule | Title | Path | Default severity |
|---|---|---|---|
| `TM001` | Untrusted input reaches an AI agent with write access | `source.untrusted.*` → `carrier.llm_agent` → `sink.repo.write` or `sink.data.write` | high |
| `TM002` | Untrusted input reaches an AI agent that holds secrets | `source.untrusted.*` → `carrier.llm_agent` → `sink.secret.read` | high |
| `TM003` | Untrusted input reaches an AI agent that can run commands | `source.untrusted.*` → `carrier.llm_agent` → `sink.code_exec` | critical |
| `TM004` | Agent combines untrusted content, sensitive access and outbound network | one agent with all three, via any servers or tools | critical |
| `TM005` | Untrusted input interpolated into a shell step | `source.untrusted.*` → `carrier.workflow_step` → `sink.code_exec` without `control.input_isolation` | high |

`TM005` overlaps with dedicated workflow linters. taintmap keeps it because it is part of the path picture,
and v0.3 will import findings from those tools instead of duplicating them.

## Out of scope

- Vulnerabilities inside a single function that do not involve agents or automations: use a static
  analysis tool.
- Known-vulnerable dependencies: use a dependency scanner.
- Secrets committed to the repository: use a secret scanner.
- Testing whether a model actually follows an injected instruction. taintmap assumes it might.
