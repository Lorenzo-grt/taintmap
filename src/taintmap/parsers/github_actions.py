"""Parse GitHub Actions workflows into graph fragments.

What becomes what (node ids in brackets, ``W`` = ``gha:<file>``):

* An untrusted trigger from the triggers catalog -> ``source`` [``W:on:<trigger>``].
* A job -> ``carrier.workflow_step`` [``W:job:<job>``]; a step -> ``carrier.workflow_step``
  [``W:job:<job>:step:<index>``] (index is 0-based), or ``carrier.llm_agent`` when it uses a
  catalogued AI action. Each job passes input to its steps.
* ``${{ }}`` expressions in ``with:``, ``env:`` or ``run:`` that read an untrusted context which one
  of the workflow's untrusted triggers fills -> ``passes_input`` edges from that trigger. Workflow
  and job ``env:`` feed the job; step ``with:``, ``env:`` and ``run:`` feed the step. An AI action
  that reads the triggering event itself receives input from every untrusted trigger.
* A ``run:`` step -> ``sink.code_exec`` [``<step>:run``]; ``attrs.expression_injection`` says
  whether untrusted input is interpolated into the script.
* Effective ``GITHUB_TOKEN`` permissions (job level, else workflow level, else the permissive
  default) -> one sink per category the write scopes grant [``W:job:<job>:permission:<category>``]:
  ``sink.repo.write``, ``sink.deploy``, or ``sink.secret.read`` for ``id-token: write``.
* ``secrets.*`` in ``env:`` or ``with:`` -> ``sink.secret.read``.
* ``if:`` on ``author_association`` (OWNER, MEMBER, COLLABORATOR) or on labels ->
  ``control.trusted_actor_gate``; ``environment:`` -> ``control.human_approval`` recorded as
  declared but unverified; untrusted input passed via ``env:`` and used as ``$VAR`` in ``run:``
  with no interpolation -> ``control.input_isolation``.

Steps reach sinks with ``runs_with`` (permissions, secrets) or ``invokes`` (``run:``) edges, and
controls with ``guarded_by`` edges.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml.comments import CommentedMap, CommentedSeq

from taintmap import catalog
from taintmap.loaders.yaml_lines import YamlDocument, item_line, key_line, load_yaml
from taintmap.model import (
    Edge,
    EdgeKind,
    GraphFragment,
    Location,
    Node,
    NodeKind,
    ParseWarning,
)
from taintmap.taxonomy import CarrierCategory, ControlCategory, SinkCategory

# GITHUB_TOKEN scopes and the sink a write grant gives.
# https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions
SCOPE_SINKS: dict[str, SinkCategory] = {
    "actions": SinkCategory.REPO_WRITE,
    "attestations": SinkCategory.REPO_WRITE,
    "checks": SinkCategory.REPO_WRITE,
    "contents": SinkCategory.REPO_WRITE,
    "deployments": SinkCategory.DEPLOY,
    "discussions": SinkCategory.REPO_WRITE,
    "id-token": SinkCategory.SECRET_READ,
    "issues": SinkCategory.REPO_WRITE,
    "models": SinkCategory.REPO_WRITE,
    "packages": SinkCategory.DEPLOY,
    "pages": SinkCategory.DEPLOY,
    "pull-requests": SinkCategory.REPO_WRITE,
    "repository-projects": SinkCategory.REPO_WRITE,
    "security-events": SinkCategory.REPO_WRITE,
    "statuses": SinkCategory.REPO_WRITE,
}

# Write scopes of the permissive default, used when a workflow sets no permissions. The repository
# setting may restrict the default, but that setting is not visible in the files, so taintmap
# assumes the permissive one. https://docs.github.com/en/actions/concepts/security/github_token
DEFAULT_WRITE_SCOPES = (
    "actions",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
)

TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})

_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_CONTEXT = re.compile(
    r"(?<![\w.])github"
    r"((?:\s*\.\s*[A-Za-z_][\w-]*|\s*\.\s*\*|\s*\[\s*(?:'[^']*'|\"[^\"]*\"|\d+|\*)\s*\])*)"
)
_SEGMENT = re.compile(r"\.\s*([A-Za-z_][\w-]*|\*)|\[\s*(?:'([^']*)'|\"([^\"]*)\"|(\d+|\*))\s*\]")
_SECRET = re.compile(
    r"(?<![\w.])secrets\s*(?:\.\s*([A-Za-z_][\w-]*)|\[\s*(?:'([^']+)'|\"([^\"]+)\")\s*\])"
)
_ASSOC_EQ = re.compile(
    r"author_association\s*==\s*['\"](\w+)['\"]|['\"](\w+)['\"]\s*==\s*[\w.\[\]'\"]*author_association"
)
_ASSOC_IN = re.compile(
    r"(?<![!\w])contains\(\s*fromJSON\(\s*'(\[[^\]]*\])'\s*\)\s*,\s*[\w.\[\]'\"]*author_association"
)
_LABEL_GATE = re.compile(
    r"(?<![!\w])contains\(\s*github\.event\.(?:issue|pull_request|discussion)\.labels\.\*\.name\s*,"
    r"|github\.event\.label\.name\s*=="
)
_SHELL_VAR_PREFIX = r"(?:\$\{?|\$env:|%)"


class GithubActionsParser:
    """Parser for ``.github/workflows/*.yml`` and ``*.yaml``."""

    name = "github_actions"

    def matches(self, path: Path) -> bool:
        parts = path.parts
        return (
            path.suffix.lower() in (".yml", ".yaml")
            and len(parts) >= 3
            and parts[-2] == "workflows"
            and parts[-3] == ".github"
        )

    def parse(self, path: Path, root: Path) -> GraphFragment:
        return parse_workflow(load_yaml(path, root))


def parse_workflow(doc: YamlDocument) -> GraphFragment:
    """Turn a loaded workflow into a fragment. Problems become warnings on the fragment."""
    return _Workflow(doc).build()


# -- expression helpers ---------------------------------------------------------------------------


def expressions(text: str) -> list[str]:
    """The bodies of every ``${{ ... }}`` in ``text``."""
    return [m.group(1) for m in _EXPRESSION.finditer(text)]


def context_paths(expression: str) -> list[str]:
    """``github`` context references in an expression, in dot form.

    ``github.event['issue'].title`` gives ``github.event.issue.title``.
    """
    paths = []
    for match in _CONTEXT.finditer(expression):
        segments = ["github"]
        for seg in _SEGMENT.finditer(match.group(1)):
            segments.append(next(g for g in seg.groups() if g is not None))
        paths.append(".".join(segments))
    return paths


def secret_names(text: str) -> list[str]:
    """Names of ``secrets.*`` referenced inside ``${{ }}`` in ``text``."""
    names = []
    for body in expressions(text):
        for match in _SECRET.finditer(body):
            names.append(next(g for g in match.groups() if g is not None))
    return sorted(set(names))


def _within(path: list[str], pattern: list[str]) -> bool:
    return len(path) >= len(pattern) and all(
        p in ("*", s) for p, s in zip(pattern, path, strict=False)
    )


def _encloses(path: list[str], pattern: list[str]) -> bool:
    """``path`` is a proper ancestor of ``pattern`` (e.g. ``toJSON(github.event)``)."""
    return len(path) < len(pattern) and all(
        p in ("*", s) for p, s in zip(pattern, path, strict=False)
    )


def untrusted_contexts(text: str) -> dict[str, set[str]]:
    """Map each catalogued trigger to the untrusted context paths in ``text`` it fills."""
    found: dict[str, set[str]] = {}
    contexts = catalog.gha_triggers().contexts
    for body in expressions(text):
        for path in context_paths(body):
            parts = path.split(".")
            for ctx in contexts:
                pattern = ctx.id.split(".")
                if _within(parts, pattern) or _encloses(parts, pattern):
                    for trigger in ctx.triggers:
                        found.setdefault(trigger, set()).add(path)
    return found


def trusted_actor_gate(condition: str) -> str | None:
    """Return ``"author_association"`` or ``"label"`` when an ``if:`` restricts who can run.

    Every ``||`` alternative must be such a check, otherwise anyone could satisfy the condition
    through another branch and the gate does not count.
    """
    text = condition.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    kinds: set[str] = set()
    for operand in text.split("||"):
        if _association_check(operand):
            kinds.add("author_association")
        elif _LABEL_GATE.search(operand):
            kinds.add("label")
        else:
            return None
    if not kinds:
        return None
    return "author_association" if "author_association" in kinds else "label"


def _association_check(operand: str) -> bool:
    for match in _ASSOC_EQ.finditer(operand):
        value = match.group(1) or match.group(2)
        if value in TRUSTED_ASSOCIATIONS:
            return True
    for match in _ASSOC_IN.finditer(operand):
        values = set(re.findall(r"\"(\w+)\"", match.group(1)))
        if values and values <= TRUSTED_ASSOCIATIONS:
            return True
    return False


def references_env(script: str, name: str) -> bool:
    """True when a shell script uses ``$NAME``, ``${NAME}``, ``$env:NAME`` or ``%NAME%``."""
    return re.search(_SHELL_VAR_PREFIX + re.escape(name) + r"(?!\w)", script) is not None


# -- the workflow walker --------------------------------------------------------------------------


@dataclass
class _EnvVar:
    name: str
    line: int
    taint: dict[str, set[str]]
    secrets: list[str]


@dataclass
class _Scope:
    """Inputs and sinks a job inherits: workflow and job env, secret sinks."""

    env: list[_EnvVar] = field(default_factory=list)
    secret_nodes: list[tuple[str, int]] = field(default_factory=list)


class _Workflow:
    def __init__(self, doc: YamlDocument) -> None:
        self.doc = doc
        self.file = doc.file
        self.base = f"gha:{doc.file}"
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.warnings: list[ParseWarning] = list(doc.warnings)
        self.sources: dict[str, str] = {}  # trigger name -> node id

    # -- output helpers ---------------------------------------------------------------------------

    def loc(self, line: int) -> Location:
        return Location(file=self.file, line=line)

    def warn(self, line: int, message: str) -> None:
        self.warnings.append(ParseWarning(file=self.file, line=line, message=message))

    def node(
        self,
        node_id: str,
        kind: NodeKind,
        category: str,
        label: str,
        line: int,
        **attrs: Any,
    ) -> str:
        self.nodes[node_id] = Node(
            id=node_id,
            kind=kind,
            category=category,
            label=label,
            location=self.loc(line),
            attrs=attrs,
        )
        return node_id

    def edge(self, src: str, dst: str, kind: EdgeKind, line: int) -> None:
        self.edges.append(Edge(src=src, dst=dst, kind=kind, location=self.loc(line)))

    def feed(self, taint: dict[str, set[str]], dst: str, line: int) -> None:
        for trigger in sorted(taint):
            if trigger in self.sources:
                self.edge(self.sources[trigger], dst, EdgeKind.PASSES_INPUT, line)

    def active(self, taint: dict[str, set[str]]) -> dict[str, set[str]]:
        """Only the triggers this workflow actually listens to."""
        return {t: paths for t, paths in taint.items() if t in self.sources}

    # -- walking ----------------------------------------------------------------------------------

    def build(self) -> GraphFragment:
        data = self.doc.data
        if data is None:
            return self.fragment()
        if not isinstance(data, CommentedMap):
            self.warn(1, "workflow is not a mapping")
            return self.fragment()
        self.triggers(data)

        scope = _Scope()
        workflow_id = f"{self.base}:workflow"
        scope.env = self.env_vars(data, workflow_id, scope.secret_nodes)

        jobs = data.get("jobs")
        if jobs is None:
            return self.fragment()
        if not isinstance(jobs, CommentedMap):
            self.warn(key_line(data, "jobs"), "jobs is not a mapping")
            return self.fragment()
        for name in jobs:
            self.job(data, jobs, str(name), scope)
        return self.fragment()

    def fragment(self) -> GraphFragment:
        return GraphFragment(
            nodes=sorted(self.nodes.values(), key=lambda n: n.id),
            edges=sorted(set(self.edges), key=Edge.sort_key),
            warnings=self.warnings,
        )

    def triggers(self, data: CommentedMap) -> None:
        if "on" not in data:
            return
        value = data["on"]
        listed: list[tuple[str, int, list[str]]] = []
        if isinstance(value, str):
            listed.append((value, key_line(data, "on"), []))
        elif isinstance(value, CommentedSeq):
            for i, item in enumerate(value):
                if isinstance(item, str):
                    listed.append((item, item_line(value, i), []))
        elif isinstance(value, CommentedMap):
            for key, config in value.items():
                types: list[str] = []
                if isinstance(config, CommentedMap) and isinstance(config.get("types"), list):
                    types = [str(t) for t in config["types"]]
                listed.append((str(key), key_line(value, key), types))
        for name, line, types in listed:
            trigger = catalog.gha_triggers().trigger(name)
            if trigger is None:
                continue
            attrs: dict[str, Any] = {
                "trigger": name,
                "source_url": trigger.source_url,
                "evidence": trigger.evidence.value,
            }
            if types:
                attrs["types"] = types
            self.sources[name] = self.node(
                f"{self.base}:on:{name}",
                NodeKind.SOURCE,
                trigger.source_category.value,
                f"on: {name}",
                line,
                **attrs,
            )

    def env_vars(
        self, owner_map: CommentedMap, owner_id: str, secret_nodes: list[tuple[str, int]]
    ) -> list[_EnvVar]:
        """Read an ``env:`` mapping; create secret sinks for ``secrets.*`` values."""
        env = owner_map.get("env")
        if not isinstance(env, CommentedMap):
            return []
        out = []
        for key, value in env.items():
            if not isinstance(value, str):
                continue
            line = key_line(env, key)
            names = secret_names(value)
            for secret in names:
                secret_nodes.append((self.secret(owner_id, "env", str(key), secret, line), line))
            out.append(_EnvVar(str(key), line, self.active(untrusted_contexts(value)), names))
        return out

    def secret(self, owner_id: str, section: str, key: str, name: str, line: int) -> str:
        return self.node(
            f"{owner_id}:{section}:{key}:secret:{name}",
            NodeKind.SINK,
            SinkCategory.SECRET_READ.value,
            f"secrets.{name}",
            line,
            secret=name,
            via=f"{section}.{key}",
        )

    def job(self, data: CommentedMap, jobs: CommentedMap, name: str, workflow: _Scope) -> None:
        job_id = f"{self.base}:job:{name}"
        job_line = key_line(jobs, name)
        job = jobs[name]
        self.node(
            job_id,
            NodeKind.CARRIER,
            CarrierCategory.WORKFLOW_STEP.value,
            f"job {name}",
            job_line,
            job=name,
        )
        if not isinstance(job, CommentedMap):
            self.warn(job_line, f'job "{name}" is not a mapping')
            return

        secret_nodes = list(workflow.secret_nodes)
        job_env = self.env_vars(job, job_id, secret_nodes)
        for var in [*workflow.env, *job_env]:
            self.feed(var.taint, job_id, var.line)
        inherited_env = [*workflow.env, *job_env]

        permission_nodes = self.permissions(data, job, job_id, job_line)
        controls = self.job_controls(job, job_id, name)

        steps = job.get("steps")
        step_ids: list[str] = []
        if isinstance(steps, CommentedSeq):
            for index, step in enumerate(steps):
                step_line = item_line(steps, index)
                if not isinstance(step, CommentedMap):
                    self.warn(step_line, f'step {index} of job "{name}" is not a mapping')
                    continue
                step_ids.append(self.step(job_id, name, index, step, step_line, inherited_env))
        elif steps is not None:
            self.warn(key_line(job, "steps"), f'steps of job "{name}" is not a list')

        holders = step_ids or [job_id]
        for holder in holders:
            for sink_id, line in [*permission_nodes, *secret_nodes]:
                self.edge(holder, sink_id, EdgeKind.RUNS_WITH, line)
        for control_id, line in controls:
            for guarded in {job_id, *step_ids}:
                self.edge(guarded, control_id, EdgeKind.GUARDED_BY, line)

    def permissions(
        self, data: CommentedMap, job: CommentedMap, job_id: str, job_line: int
    ) -> list[tuple[str, int]]:
        """Sinks granted by the job's effective token permissions, as (node id, line)."""
        if "permissions" in job:
            owner, declared = job, "job"
        elif "permissions" in data:
            owner, declared = data, "workflow"
        else:
            owner, declared = None, "default"

        writes: dict[str, int] = {}
        if owner is None:
            writes = dict.fromkeys(DEFAULT_WRITE_SCOPES, job_line)
        else:
            value = owner["permissions"]
            line = key_line(owner, "permissions")
            if value == "write-all":
                writes = dict.fromkeys(SCOPE_SINKS, line)
            elif isinstance(value, CommentedMap):
                for scope, level in value.items():
                    if level == "write":
                        if str(scope) in SCOPE_SINKS:
                            writes[str(scope)] = key_line(value, scope)
                        else:
                            self.warn(key_line(value, scope), f'unknown permission "{scope}"')
            elif value != "read-all":
                self.warn(line, "permissions has an unexpected value")

        by_sink: dict[SinkCategory, list[str]] = {}
        for scope in sorted(writes):
            by_sink.setdefault(SCOPE_SINKS[scope], []).append(scope)
        out = []
        for sink, scopes in sorted(by_sink.items()):
            line = min(writes[s] for s in scopes)
            label = "GITHUB_TOKEN " + ", ".join(f"{s}: write" for s in scopes)
            node_id = self.node(
                f"{job_id}:permission:{sink.value}",
                NodeKind.SINK,
                sink.value,
                label,
                line,
                scopes=scopes,
                declared=declared,
            )
            out.append((node_id, line))
        return out

    def job_controls(self, job: CommentedMap, job_id: str, name: str) -> list[tuple[str, int]]:
        out = []
        gate = self.gate(job, job_id)
        if gate is not None:
            out.append(gate)
        if "environment" in job:
            value = job["environment"]
            env_name = value.get("name") if isinstance(value, CommentedMap) else value
            line = key_line(job, "environment")
            out.append(
                (
                    self.node(
                        f"{job_id}:environment",
                        NodeKind.CONTROL,
                        ControlCategory.HUMAN_APPROVAL.value,
                        f"environment {env_name}" if env_name else "environment",
                        line,
                        environment=str(env_name) if env_name is not None else None,
                        declared=True,
                        verified=False,
                        note="required reviewers cannot be verified from the workflow file",
                    ),
                    line,
                )
            )
        return out

    def gate(self, owner: CommentedMap, owner_id: str) -> tuple[str, int] | None:
        condition = owner.get("if")
        if not isinstance(condition, str):
            return None
        kind = trusted_actor_gate(condition)
        if kind is None:
            return None
        line = key_line(owner, "if")
        node_id = self.node(
            f"{owner_id}:if:trusted_actor",
            NodeKind.CONTROL,
            ControlCategory.TRUSTED_ACTOR_GATE.value,
            f"if: {kind}",
            line,
            gate=kind,
            condition=" ".join(condition.split()),
        )
        return node_id, line

    def step(
        self,
        job_id: str,
        job_name: str,
        index: int,
        step: CommentedMap,
        line: int,
        inherited_env: list[_EnvVar],
    ) -> str:
        step_id = f"{job_id}:step:{index}"
        uses = step.get("uses") if isinstance(step.get("uses"), str) else None
        run = step.get("run") if isinstance(step.get("run"), str) else None
        action = catalog.ai_actions().find(uses) if uses else None

        attrs: dict[str, Any] = {"job": job_name, "index": index}
        if isinstance(step.get("name"), str):
            attrs["name"] = step["name"]
        if uses:
            attrs["uses"] = uses
        if action:
            attrs["ai_action"] = action.id
            attrs["source_url"] = action.source_url
            attrs["evidence"] = action.evidence.value
        label = attrs.get("name") or uses or "run"
        category = CarrierCategory.LLM_AGENT if action else CarrierCategory.WORKFLOW_STEP
        self.node(step_id, NodeKind.CARRIER, category.value, str(label), line, **attrs)
        self.edge(job_id, step_id, EdgeKind.PASSES_INPUT, line)

        untrusted: set[str] = set()
        with_map = step.get("with")
        if isinstance(with_map, CommentedMap):
            for key, value in with_map.items():
                if not isinstance(value, str):
                    continue
                key_ln = key_line(with_map, key)
                taint = self.active(untrusted_contexts(value))
                self.feed(taint, step_id, key_ln)
                untrusted.update(*taint.values())
                for secret in secret_names(value):
                    sink = self.secret(step_id, "with", str(key), secret, key_ln)
                    self.edge(step_id, sink, EdgeKind.RUNS_WITH, key_ln)

        step_secrets: list[tuple[str, int]] = []
        step_env = self.env_vars(step, step_id, step_secrets)
        for sink, sink_line in step_secrets:
            self.edge(step_id, sink, EdgeKind.RUNS_WITH, sink_line)
        for var in step_env:
            self.feed(var.taint, step_id, var.line)
            untrusted.update(*var.taint.values())

        if action and action.reads_event:
            uses_line = key_line(step, "uses")
            for trigger in sorted(self.sources):
                self.edge(self.sources[trigger], step_id, EdgeKind.PASSES_INPUT, uses_line)

        if run is not None:
            self.run_step(step, step_id, run, [*inherited_env, *step_env], untrusted)

        gate = self.gate(step, step_id)
        if gate is not None:
            self.edge(step_id, gate[0], EdgeKind.GUARDED_BY, gate[1])

        if untrusted:
            self.nodes[step_id] = self.nodes[step_id].model_copy(
                update={"attrs": {**attrs, "untrusted_contexts": sorted(untrusted)}}
            )
        return step_id

    def run_step(
        self,
        step: CommentedMap,
        step_id: str,
        run: str,
        visible_env: list[_EnvVar],
        untrusted: set[str],
    ) -> None:
        run_line = key_line(step, "run")
        taint = self.active(untrusted_contexts(run))
        self.feed(taint, step_id, run_line)
        untrusted.update(*taint.values())
        exec_id = self.node(
            f"{step_id}:run",
            NodeKind.SINK,
            SinkCategory.CODE_EXEC.value,
            "run: shell script",
            run_line,
            expression_injection=bool(taint),
        )
        self.edge(step_id, exec_id, EdgeKind.INVOKES, run_line)

        # Without interpolation, untrusted input can only reach the script through env: either a
        # $VAR reference or a variable the script ignores. Both keep it out of the shell syntax.
        isolated = sorted({var.name for var in visible_env if var.taint})
        if isolated and not taint:
            control_id = self.node(
                f"{step_id}:input_isolation",
                NodeKind.CONTROL,
                ControlCategory.INPUT_ISOLATION.value,
                "untrusted input passed through env",
                run_line,
                env=isolated,
                referenced=[name for name in isolated if references_env(run, name)],
            )
            self.edge(step_id, control_id, EdgeKind.GUARDED_BY, run_line)
