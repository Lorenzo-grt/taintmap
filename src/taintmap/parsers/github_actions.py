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
from typing import Any, Literal

from ruamel.yaml.comments import CommentedMap, CommentedSeq

from taintmap import catalog
from taintmap.catalog import AiAction
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

# Write scopes of the permissive default, used when a workflow sets no permissions.
# Since 2023-02-02, new personal repositories and organisations default to a read-only token, but
# existing ones keep their previous (often read/write) setting, and the setting is not visible in
# the files. taintmap therefore assumes write unless told otherwise
# (``default_token_permissions="read"``), and marks such sinks ``attrs.permissions_assumed``.
# https://github.blog/changelog/2023-02-02-github-actions-updating-the-default-github_token-permissions-to-read-only/
# https://docs.github.com/en/actions/concepts/security/github_token
DefaultTokenPermissions = Literal["write", "read"]
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
_CTX = r"(?<![\w.])github(?:\s*\.\s*[A-Za-z_][\w-]*|\s*\[\s*(?:'[^']*'|\"[^\"]*\")\s*\])+"
_ASSOC_EQ = re.compile(
    rf"(?P<lctx>{_CTX})\s*==\s*'(?P<lval>\w+)'|'(?P<rval>\w+)'\s*==\s*(?P<rctx>{_CTX})"
)
_ASSOC_IN = re.compile(
    r"(?<![!\w])contains\(\s*fromJSON\(\s*'(?P<list>\[[^\]]*\])'\s*\)\s*,\s*"
    rf"(?P<ctx>{_CTX})\s*\)"
)
_LABEL_GATE = re.compile(
    r"(?<![!\w])contains\(\s*github\.event\.(?:issue|pull_request|discussion)\.labels\.\*\.name\s*,"
    r"|github\.event\.label\.name\s*=="
)
_SHELL_VAR_PREFIX = r"(?:\$\{?|\$env:|%)"


class GithubActionsParser:
    """Parser for ``.github/workflows/*.yml`` and ``*.yaml``."""

    name = "github_actions"

    def __init__(self, default_token_permissions: DefaultTokenPermissions = "write") -> None:
        self.default_token_permissions = default_token_permissions

    def matches(self, path: Path) -> bool:
        parts = path.parts
        return (
            path.suffix.lower() in (".yml", ".yaml")
            and len(parts) >= 3
            and parts[-2] == "workflows"
            and parts[-3] == ".github"
        )

    def parse(self, path: Path, root: Path) -> GraphFragment:
        return parse_workflow(
            load_yaml(path, root), default_token_permissions=self.default_token_permissions
        )


def parse_workflow(
    doc: YamlDocument, *, default_token_permissions: DefaultTokenPermissions = "write"
) -> GraphFragment:
    """Turn a loaded workflow into a fragment. Problems become warnings on the fragment.

    ``default_token_permissions`` is what the token may do when a workflow sets no permissions.
    """
    return _Workflow(doc, default_token_permissions).build()


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


Taint = dict[str, dict[str | None, set[str]]]
"""trigger -> author of the input (``None`` when unknown) -> context paths."""


def untrusted_contexts(text: str) -> Taint:
    """Map each catalogued trigger to the untrusted context paths in ``text`` it fills, grouped
    by the payload object whose author wrote them."""
    found: Taint = {}
    contexts = catalog.gha_triggers().contexts
    for body in expressions(text):
        for path in context_paths(body):
            parts = path.split(".")
            for ctx in contexts:
                pattern = ctx.id.split(".")
                if _within(parts, pattern) or _encloses(parts, pattern):
                    for trigger in ctx.triggers:
                        found.setdefault(trigger, {}).setdefault(ctx.author, set()).add(path)
    return found


def taint_paths(taint: Taint) -> set[str]:
    """Every context path in a taint map."""
    return {path for by_author in taint.values() for paths in by_author.values() for path in paths}


@dataclass(frozen=True)
class Gate:
    """A trusted-actor gate read from an ``if:`` condition.

    ``checks`` lists the ``author_association`` contexts (dot form) that every alternative of the
    condition requires to be OWNER, MEMBER or COLLABORATOR. The gate only blocks input written by
    those authors: checking ``github.event.issue.author_association`` says nothing about who wrote
    ``github.event.comment.body``. A ``label`` gate has no checks and blocks input from any author,
    because only people with triage access can add labels.
    """

    kind: Literal["author_association", "label"]
    checks: tuple[str, ...] = ()


def trusted_actor_gate(condition: str) -> Gate | None:
    """Read a trusted-actor gate from an ``if:`` condition, or return ``None``.

    Every ``||`` alternative must be an association or label check, otherwise anyone could satisfy
    the condition through another branch. With several association alternatives, only the
    authors that all of them check count.
    """
    text = condition.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    common: set[str] | None = None
    for operand in text.split("||"):
        checked = association_checks(operand)
        if checked:
            common = checked if common is None else common & checked
        elif not _LABEL_GATE.search(operand):
            return None
    if common is None:
        return Gate("label")
    if not common:
        return None
    return Gate("author_association", tuple(sorted(common)))


def association_checks(operand: str) -> set[str]:
    """``author_association`` contexts that an operand requires to be a trusted association."""
    checked: set[str] = set()
    for match in _ASSOC_EQ.finditer(operand):
        if match.group("lctx"):
            ctx, value = match.group("lctx"), match.group("lval")
        else:
            ctx, value = match.group("rctx"), match.group("rval")
        path = _single_context(ctx)
        if path and path.endswith(".author_association") and value in TRUSTED_ASSOCIATIONS:
            checked.add(path)
    for match in _ASSOC_IN.finditer(operand):
        values = set(re.findall(r'"(\w+)"', match.group("list")))
        path = _single_context(match.group("ctx"))
        if (
            path
            and path.endswith(".author_association")
            and values
            and values <= TRUSTED_ASSOCIATIONS
        ):
            checked.add(path)
    return checked


def _single_context(text: str) -> str | None:
    paths = context_paths(text)
    return paths[0] if len(paths) == 1 else None


def references_env(script: str, name: str) -> bool:
    """True when a shell script uses ``$NAME``, ``${NAME}``, ``$env:NAME`` or ``%NAME%``."""
    return re.search(_SHELL_VAR_PREFIX + re.escape(name) + r"(?!\w)", script) is not None


# -- the workflow walker --------------------------------------------------------------------------


@dataclass
class _EnvVar:
    name: str
    line: int
    taint: Taint
    secrets: list[str]


@dataclass
class _Scope:
    """Inputs and sinks a job inherits: workflow and job env, secret sinks."""

    env: list[_EnvVar] = field(default_factory=list)
    secret_nodes: list[tuple[str, int]] = field(default_factory=list)


class _Workflow:
    def __init__(
        self, doc: YamlDocument, default_token_permissions: DefaultTokenPermissions
    ) -> None:
        self.doc = doc
        self.default_token_permissions = default_token_permissions
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

    def edge(self, src: str, dst: str, kind: EdgeKind, line: int, **attrs: Any) -> None:
        self.edges.append(Edge(src=src, dst=dst, kind=kind, location=self.loc(line), attrs=attrs))

    def feed(self, taint: Taint, dst: str, line: int) -> None:
        """One ``passes_input`` edge per trigger and author of the input.

        ``attrs.author_association`` is the context a trusted-actor gate must check to block it.
        """
        triggers = catalog.gha_triggers()
        for trigger in sorted(taint):
            if trigger not in self.sources:
                continue
            for author, paths in sorted(taint[trigger].items(), key=lambda kv: kv[0] or ""):
                self.edge(
                    self.sources[trigger],
                    dst,
                    EdgeKind.PASSES_INPUT,
                    line,
                    author=author,
                    author_association=triggers.association(author),
                    contexts=sorted(paths),
                )

    def active(self, taint: Taint) -> Taint:
        """Only the triggers this workflow actually listens to."""
        return {t: by_author for t, by_author in taint.items() if t in self.sources}

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
            edges=sorted({e.model_dump_json(): e for e in self.edges}.values(), key=Edge.sort_key),
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
                "author": trigger.author,
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

        permission_nodes, declared = self.permissions(data, job, job_id, job_line)
        job_node = self.nodes[job_id]
        self.nodes[job_id] = job_node.model_copy(
            update={"attrs": {**job_node.attrs, "permissions": declared}}
        )
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
    ) -> tuple[list[tuple[str, int]], dict[str, Any]]:
        """Sinks granted by the job's effective token permissions, as (node id, line), and the
        declared permissions for the job's attrs (used in fix text)."""
        if "permissions" in job:
            owner, declared = job, "job"
        elif "permissions" in data:
            owner, declared = data, "workflow"
        else:
            owner, declared = None, "default"

        writes: dict[str, int] = {}
        info: dict[str, Any] = {"declared": declared}
        if owner is None:
            info["assumed"] = self.default_token_permissions
            if self.default_token_permissions == "write":
                writes = dict.fromkeys(DEFAULT_WRITE_SCOPES, job_line)
        else:
            value = owner["permissions"]
            info["line"] = key_line(owner, "permissions")
            info["value"] = (
                {str(k): str(v) for k, v in value.items()}
                if isinstance(value, CommentedMap)
                else str(value)
            )
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
            if owner is None:
                label = f"GITHUB_TOKEN default {sink.value.removeprefix('sink.')} (assumed write)"
            else:
                label = "GITHUB_TOKEN " + ", ".join(f"{s}: write" for s in scopes)
            node_id = self.node(
                f"{job_id}:permission:{sink.value}",
                NodeKind.SINK,
                sink.value,
                label,
                line,
                scopes=scopes,
                declared=declared,
                permissions_assumed=owner is None,
            )
            out.append((node_id, line))
        return out, info

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
        gate = trusted_actor_gate(condition)
        if gate is None:
            return None
        line = key_line(owner, "if")
        node_id = self.node(
            f"{owner_id}:if:trusted_actor",
            NodeKind.CONTROL,
            ControlCategory.TRUSTED_ACTOR_GATE.value,
            f"if: {gate.kind}",
            line,
            gate=gate.kind,
            checks=list(gate.checks),
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
            with_values = step.get("with")
            if isinstance(with_values, CommentedMap):
                tool_config = {
                    name: with_values[name]
                    for name in action.tool_config_inputs
                    if isinstance(with_values.get(name), str)
                }
                if tool_config:
                    attrs["tool_config"] = tool_config
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
                untrusted |= taint_paths(taint)
                for secret in secret_names(value):
                    sink = self.secret(step_id, "with", str(key), secret, key_ln)
                    if action and str(key) in action.model_credential_inputs:
                        node = self.nodes[sink]
                        self.nodes[sink] = node.model_copy(
                            update={
                                "attrs": {
                                    **node.attrs,
                                    "model_credential": True,
                                    "model_credential_source_url": (
                                        action.model_credential_source_url
                                    ),
                                }
                            }
                        )
                    self.edge(step_id, sink, EdgeKind.RUNS_WITH, key_ln)

        step_secrets: list[tuple[str, int]] = []
        step_env = self.env_vars(step, step_id, step_secrets)
        for sink, sink_line in step_secrets:
            self.edge(step_id, sink, EdgeKind.RUNS_WITH, sink_line)
        for var in step_env:
            self.feed(var.taint, step_id, var.line)
            untrusted |= taint_paths(var.taint)

        if action and action.reads_event:
            uses_line = key_line(step, "uses")
            triggers = catalog.gha_triggers()
            for name in sorted(self.sources):
                trigger = triggers.trigger(name)
                author = trigger.author if trigger else None
                self.edge(
                    self.sources[name],
                    step_id,
                    EdgeKind.PASSES_INPUT,
                    uses_line,
                    author=author,
                    author_association=triggers.association(author),
                    reads_event=True,
                    evidence=(action.reads_event_evidence or action.evidence).value,
                    evidence_reason=action.reads_event_reason or action.evidence_reason,
                )

        if run is not None:
            self.run_step(step, step_id, run, [*inherited_env, *step_env], untrusted)

        if action:
            self.agent_exec(step_id, step, action, attrs.get("tool_config", {}))

        gate = self.gate(step, step_id)
        if gate is not None:
            self.edge(step_id, gate[0], EdgeKind.GUARDED_BY, gate[1])

        if untrusted:
            self.nodes[step_id] = self.nodes[step_id].model_copy(
                update={"attrs": {**attrs, "untrusted_contexts": sorted(untrusted)}}
            )
        return step_id

    def agent_exec(
        self, step_id: str, step: CommentedMap, action: AiAction, tool_config: dict[str, str]
    ) -> None:
        """A code-execution sink when the agent's tool config allows a shell tool.

        The sink is located at the ``with:`` input that allows the tool (for example the
        ``claude_args:`` line), because that line is what grants the agent command execution.
        """
        with_map = step["with"] if isinstance(step.get("with"), CommentedMap) else None
        for tool in action.code_exec_tools:
            pattern = re.compile(r"(?<![\w])" + re.escape(tool) + r"(?![\w])")
            granting = [name for name, value in tool_config.items() if pattern.search(value)]
            if granting and with_map is not None:
                line = key_line(with_map, granting[0])
                exec_id = self.node(
                    f"{step_id}:agent_exec",
                    NodeKind.SINK,
                    SinkCategory.CODE_EXEC.value,
                    f"agent tool {tool}",
                    line,
                    via_tool=tool,
                    via_input=granting[0],
                    evidence=(action.code_exec_evidence or action.evidence).value,
                    evidence_reason=action.code_exec_reason or action.evidence_reason,
                )
                self.edge(step_id, exec_id, EdgeKind.INVOKES, line)
                return

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
        untrusted |= taint_paths(taint)
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
