# Contributing to taintmap

Thanks for helping. taintmap is built task by task from [docs/plan.md](docs/plan.md); the design is in
[docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md).

## Set up a development environment

You need Python 3.11 or newer and git.

### Windows PowerShell

```powershell
git clone https://github.com/aakashsiwach/taintmap.git
cd taintmap
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
git config core.hooksPath .githooks
taintmap version
```

### bash (Linux, macOS, Git Bash)

```bash
git clone https://github.com/aakashsiwach/taintmap.git
cd taintmap
python3 -m venv .venv
source .venv/bin/activate        # Git Bash on Windows: source .venv/Scripts/activate
python -m pip install -e ".[dev]"
git config core.hooksPath .githooks
taintmap version
```

## Checks

Every change must pass these before it is merged. CI runs them on Python 3.11 and 3.12, on Ubuntu and
Windows.

```bash
ruff check .
ruff format --check .
mypy src
pytest
```

`ruff format .` fixes formatting. `ruff check --fix .` fixes many lint findings.

## Guidelines

- One task or topic per pull request, with tests for new behaviour.
- Tests must not use the network, and taintmap's analysis never calls an LLM.
- Catalog entries must cite a source link. Do not guess action inputs, server names or tool names.
  Each entry's `evidence` field holds the link. The catalog structure is defined by the Pydantic models
  in `src/taintmap/catalog/__init__.py`; after changing a model, regenerate the JSON schemas with
  `python -m taintmap.catalog`.
- Benchmark cases and fixtures are minimal synthetic configurations, never copies of real projects'
  vulnerable files. Use obvious placeholders such as `FAKE_TOKEN_FOR_TESTS` for secrets.
- Commit messages are short and in the imperative mood, for example `Add YAML loader with line numbers`.
- taintmap is defensive. Do not contribute exploit code or attack payloads.

## Reporting vulnerabilities

If you find a vulnerability in someone else's project with taintmap, report it privately to that project
(GitHub private vulnerability reporting or its `SECURITY.md`), never in a public issue first.
