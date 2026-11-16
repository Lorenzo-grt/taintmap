# Instructions for AI coding assistants

taintmap is a defensive security tool that maps how untrusted input can flow through AI agents,
automations and code to sensitive actions. Maintainer: Aakash Siwach (@aakashsiwach).

## Before you start
1. Read `docs/plan.md`, `docs/architecture.md` and `docs/threat-model.md`.
2. Work on the **first unchecked task** in `docs/plan.md` unless you are told otherwise.
3. If a task needs a design decision the docs do not settle, stop and ask instead of guessing.

## How to work
- One task at a time. Keep changes inside the task's scope.
- Write tests with the code. A task is done only when `ruff check .`, `ruff format --check .`,
  `mypy src` and `pytest` all pass.
- Tick the task's checkboxes in `docs/plan.md` in the same commit that completes it.
- Update docs when behaviour or commands change.
- No network access in tests. No LLM calls anywhere in taintmap's analysis.
- Catalog entries must cite a source link. Never invent action inputs, server names or tool names.

## Git rules (strict)
- Commit with the repository's configured git identity. Never change `user.name` or `user.email`.
- **Never** add `Co-Authored-By`, `Generated with Claude Code`, `Claude-Session` or any other AI
  attribution line to commit messages or pull request descriptions.
- Small commits with clear messages in the imperative mood, e.g. `Add YAML loader with line numbers`.
- Do not push, tag, publish or create releases unless the maintainer asks in the current session.
- Never commit secrets. Test fixtures use obvious placeholders like `FAKE_TOKEN_FOR_TESTS`.

## Security scope
- taintmap finds and explains risks so they can be fixed. Do not write exploit code or attack payloads.
- Benchmark cases and fixtures are minimal synthetic configurations, never copies of real projects'
  vulnerable files.
- taintmap never reports to third-party projects on anyone's behalf.
