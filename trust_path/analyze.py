"""Find paths from untrusted input to secrets and credentials in workflows.

A path is reported as a Record(source, workflow, job, step, sink, detail). See
docs/model.md for the rules this module implements.
"""

import collections
import os
import re
import subprocess

from . import yamlsubset

Record = collections.namedtuple("Record", "source workflow job step sink detail")


class AnalysisError(Exception):
    pass


# Triggers whose runs hold the base repository's secrets and token while the
# triggering text (titles, bodies, comments, branch names) comes from anyone
# who can open an issue, comment or pull request.
UNTRUSTED_TRIGGERS = (
    "discussion", "discussion_comment", "issue_comment", "issues",
    "pull_request_review", "pull_request_review_comment", "pull_request_target",
)

# Upstream triggers that make a downstream `workflow_run` untrusted: the
# ones above, plus pull_request (fork code and branch names, without secrets
# upstream, but the downstream run has them).
UPSTREAM_UNTRUSTED = UNTRUSTED_TRIGGERS + ("pull_request",)

# Pull request fields are written by the pull request's author. Under
# pull_request_review(_comment), runs for fork pull requests get no secrets
# and a read-only token, so those fields count only under pull_request_target.
_PR = ("pull_request_target",)
_REVIEW = ("pull_request_review", "pull_request_review_comment")
_ISSUE = ("issues", "issue_comment")
_DISCUSSION = ("discussion", "discussion_comment")

# Attacker-controlled contexts, as regular expressions over a normalised
# context name (indexes written as .*), and the triggers whose event payload
# carries them.
UNTRUSTED_CONTEXTS = [
    (r"github\.head_ref", _PR),
    (r"github\.event\.pull_request\.(title|body)", _PR),
    (r"github\.event\.pull_request\.head\.(ref|label|repo\.default_branch)", _PR),
    (r"github\.event\.issue\.(title|body)", _ISSUE),
    (r"github\.event\.comment\.body",
     ("issue_comment", "pull_request_review_comment", "discussion_comment")),
    (r"github\.event\.review\.body", ("pull_request_review",)),
    (r"github\.event\.discussion\.(title|body)", _DISCUSSION),
    (r"github\.event\.workflow_run\.(head_branch|display_title)", ("workflow_run",)),
    (r"github\.event\.workflow_run\.head_commit\.(message|author\.(email|name))",
     ("workflow_run",)),
    (r"github\.event\.workflow_run\.head_repository\.description", ("workflow_run",)),
    (r"github\.event\.workflow_run\.pull_requests\.\*\.head\.ref", ("workflow_run",)),
    # The whole event payload, for example toJSON(github.event).
    (r"github\.event", UNTRUSTED_TRIGGERS + ("workflow_run",)),
    (r"github", UNTRUSTED_TRIGGERS + ("workflow_run",)),
]

# Values of actions/checkout `ref:` or `repository:` that select the pull
# request's head (fork) code rather than the base branch.
HEAD_REFS = re.compile(
    r"head\.sha|head\.ref|head_ref|head_sha|head_branch|head\.repo|head_repository"
    r"|merge_commit_sha|refs/pull/")
# Shell commands that fetch pull request code.
HEAD_FETCH = re.compile(r"\bgh\s+pr\s+checkout\b|\bpull/\$\{\{|\brefs/pull/")

# AI agent actions: given text, they act with the credentials they hold.
AGENT_ACTIONS = (
    "actions/ai-inference",
    "anthropics/claude-code-action",
    "anthropics/claude-code-base-action",
    "google-github-actions/run-gemini-cli",
    "openai/codex-action",
    "warpdotdev/oz-agent-action",
)

# The input by which an agent action lets users without write access start
# it. Left empty, these actions run only for users with write access.
AGENT_GATES = {
    "anthropics/claude-code-action": "allowed_non_write_users",
    "openai/codex-action": "allow-users",
}
_CLAUDE_FLAGS = re.compile(
    r"--(allowed-?tools|disallowed-?tools|permission-mode|dangerously-skip-permissions)"
    r"(?:(?:\s+|=)(\"[^\"]*\"|'[^']*'|[^\s-]\S*))?", re.I)
_CLAUDE_NAMES = {"allowedtools": "allowedTools", "disallowedtools": "disallowedTools"}

# Actions whose outputs list the names of the files a pull request changes.
# The author of the pull request chooses those names.
FILENAME_ACTIONS = (
    "ana06/get-changed-files",
    "jitterbit/get-changed-files",
    "tj-actions/changed-files",
)

# Actions that download artifacts from another workflow run.
ARTIFACT_ACTIONS = ("actions/download-artifact", "dawidd6/action-download-artifact")

# Token scopes whose write access is a sink. issues and discussions count
# because text written there is read by other workflows and AI agents that
# run on issue and discussion events: injected text can travel on.
WRITE_SCOPES = ("actions", "contents", "discussions", "id-token", "issues", "packages",
                "pull-requests")

_EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
_CONTEXT = re.compile(
    r"(?<![\w.-])(github|inputs|secrets|env|steps)((?:\.[A-Za-z_*][\w*-]*|\[[^\]]*\])*)")


def _norm(name):
    """github.event.commits[0].message -> github.event.commits.*.message"""
    return re.sub(r"\[[^\]]*\]", ".*", name)


def contexts(value):
    """Context names (github..., inputs..., secrets...) used inside the
    ${{ }} expressions of a string, a list or a mapping."""
    found = set()
    for text in _strings(value):
        for expr in _EXPR.findall(text):
            # ['name'] indexes become .name; other string literals are dropped.
            expr = re.sub(r"\[\s*'([\w-]+)'\s*\]", r".\1", expr)
            expr = re.sub(r"'[^']*'", "''", expr)
            for m in _CONTEXT.finditer(expr):
                found.add(_norm(m.group(1) + m.group(2)))
    return found


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k in sorted(value):
            for s in _strings(value[k]):
                yield s
    elif isinstance(value, list):
        for v in value:
            for s in _strings(v):
                yield s


def untrusted(names, trigger, tainted_inputs):
    """The untrusted contexts among `names` for a run started by `trigger`."""
    out = set()
    for name in names:
        if name.startswith("inputs."):
            if name.split(".")[1] in tainted_inputs:
                out.add(name)
            continue
        for pattern, triggers in UNTRUSTED_CONTEXTS:
            if trigger in triggers and re.match(pattern + r"$", name):
                out.add(name)
                break
    return out


def secret_names(value):
    """secrets.NAME references; the whole context (toJSON(secrets) or
    secrets[expr]) is written secrets.*"""
    names = set()
    for name in contexts(value):
        parts = name.split(".")
        if parts[0] == "secrets":
            names.add("secrets." + (parts[1] if len(parts) > 1 else "*"))
    return names


def _action(uses):
    """owner/repo of a `uses:` value, lower-cased; '' for docker:// and ./"""
    if not isinstance(uses, str) or uses.startswith(("docker://", "./")):
        return ""
    return "/".join(uses.split("@")[0].split("/")[:2]).lower()


def agent_detail(action, with_):
    """What the workflow sets on an agent action: who may start it (gate)
    and what it may do. Values are the workflow's own, not a judgement."""
    def text(key):
        return with_[key].strip() if isinstance(with_.get(key), str) else ""

    parts = []
    if action in AGENT_GATES:
        gate = text(AGENT_GATES[action])
        parts.append("gate=" + ("write-access" if not gate else "anyone" if gate == "*"
                                else "expression" if "${{" in gate else "listed-users"))
    else:
        parts.append("gate=not-modelled")
    if action.startswith("anthropics/"):
        flags = []
        for m in _CLAUDE_FLAGS.finditer(text("claude_args")):
            name = m.group(1).lower().replace("-tools", "tools")
            name = _CLAUDE_NAMES.get(name, name)
            if name == "dangerously-skip-permissions":
                flags.append(name)
            elif m.group(2):
                flags.append("%s=%s" % (name, m.group(2).strip("\"'")))
        parts.extend(sorted(set(flags)) or ["tools=action-default"])
        if text("settings"):
            parts.append("settings=set")
    elif action == "openai/codex-action":
        parts.append("sandbox=" + (text("sandbox") or "action-default"))
        if text("permission-profile"):
            parts.append("permission-profile=" + text("permission-profile"))
        parts.append("safety-strategy=" + (text("safety-strategy") or "drop-sudo"))
    return "; ".join(parts)


def triggers_of(wf):
    on = wf.get("on")
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict((t, None) for t in on if isinstance(t, str))
    if isinstance(on, dict):
        return on
    return {}


def _permissions(perms):
    """Write-scope sinks of a permissions value. None (no permissions key)
    means the repository's default token permissions, which the workflow
    files do not show."""
    if perms is None:
        return {"permissions:default"}
    if perms == "write-all":
        return set("permissions.%s:write" % s for s in WRITE_SCOPES)
    if isinstance(perms, dict):
        return set("permissions.%s:write" % s for s in WRITE_SCOPES if perms.get(s) == "write")
    return set()


def _label(step, index):
    for key in ("name", "id", "uses"):
        if isinstance(step.get(key), str) and step[key].strip():
            return step[key]
    return "step %d" % (index + 1)


def _check(doc):
    """Refuse a document that is not a workflow this module can walk."""
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        raise AnalysisError("not a workflow (no 'jobs' mapping)")
    for job_id, job in sorted(doc["jobs"].items()):
        if not isinstance(job, dict):
            raise AnalysisError("job %r is not a mapping" % job_id)
        if not isinstance(job.get("steps") or [], list):
            raise AnalysisError("steps of job %r are not a list" % job_id)
    return doc


Context = collections.namedtuple(
    "Context", "chain trigger tainted_inputs secrets_allowed caller_permissions")


def _git(root, *args):
    """Run git in root without a shell and return its standard output."""
    try:
        p = subprocess.run(["git"] + list(args), cwd=root, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"))
    except OSError as e:
        raise AnalysisError("cannot run git: %s" % e)
    if p.returncode:
        message = p.stderr.decode("utf-8", "replace").strip().splitlines()
        raise AnalysisError(message[-1] if message else "git %s failed" % args[0])
    return p.stdout


def _git_reader(root, ref):
    """name -> function returning the text of each file directly in
    .github/workflows at ref, read from git without a checkout."""
    try:
        _git(root, "rev-parse", "--git-dir")
    except AnalysisError:
        raise AnalysisError("%s: not a git repository" % root)
    try:
        if ref.startswith("-"):
            raise AnalysisError(ref)
        commit = _git(root, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
    except AnalysisError:
        raise AnalysisError("unknown ref %s" % ref)
    listing = _git(root, "ls-tree", "-z", "--full-tree", commit.decode().strip(), "--",
                   ".github/workflows/")
    files = {}
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, oid = meta.decode().split(" ")
        name = path.decode("utf-8", "replace").split("/")[-1]
        if kind != "blob":
            continue
        if mode == "120000":
            files[name] = None
        else:
            files[name] = lambda oid=oid: _git(root, "cat-file", "blob", oid).decode("utf-8")
    return files


def _dir_reader(root):
    """name -> function returning the text of each file directly in
    DIR/.github/workflows."""
    if not os.path.isdir(root):
        raise AnalysisError("%s: not a directory" % root)
    wdir = os.path.join(root, ".github", "workflows")

    def read(name):
        with open(os.path.join(wdir, name), encoding="utf-8") as f:
            return f.read()
    names = os.listdir(wdir) if os.path.isdir(wdir) else []
    return dict((name, lambda name=name: read(name)) for name in names)


class Repo(object):
    """The readable workflows of a repository, from the directory or, with
    `ref`, from git at that ref. Files that cannot be read are listed in
    `refused` as sorted (file, reason) pairs and left out."""

    def __init__(self, root, ref=None):
        self.root = root
        self.workflows = {}
        refused = {}
        files = _dir_reader(root) if ref is None else _git_reader(root, ref)
        for name in sorted(files):
            if not name.endswith((".yml", ".yaml")):
                continue
            rel = ".github/workflows/" + name
            if files[name] is None:
                refused[rel] = "a symbolic link, not read"
                continue
            try:
                self.workflows[rel] = _check(yamlsubset.load(files[name]()))
            except yamlsubset.YamlError as e:
                refused[rel] = "line %d: %s" % (e.line, e.message)
            except AnalysisError as e:
                refused[rel] = str(e)
            except (OSError, UnicodeDecodeError) as e:
                refused[rel] = str(e)
        # A call to a local reusable workflow that does not exist refuses the
        # caller; a call to one that was refused is skipped when analysing.
        for rel in sorted(self.workflows):
            for job_id, job in sorted(self.workflows[rel]["jobs"].items()):
                uses = job.get("uses")
                if isinstance(uses, str) and uses.startswith("./"):
                    target = uses[2:].split("@")[0]
                    if target not in self.workflows and target not in refused:
                        refused[rel] = "job %r calls %s, which is not in %s" % (
                            job_id, uses, ".github/workflows")
        for rel in refused:
            self.workflows.pop(rel, None)
        self.refused = sorted(refused.items())

    def name_of(self, rel):
        name = self.workflows[rel].get("name")
        return name if isinstance(name, str) else rel

    def contexts_for(self, rel, seen=()):
        """Every untrusted context a workflow can run in, through its own
        triggers or a chain of workflow_run triggers."""
        out = []
        triggers = triggers_of(self.workflows[rel])
        for t in sorted(triggers):
            if t in UNTRUSTED_TRIGGERS:
                out.append(Context(t, t, frozenset(), None, None))
        run = triggers.get("workflow_run")
        if "workflow_run" in triggers:
            wanted = run.get("workflows") if isinstance(run, dict) else None
            wanted = [wanted] if isinstance(wanted, str) else (wanted or [])
            for upstream in sorted(set(w for w in wanted if isinstance(w, str))):
                matches = [r for r in sorted(self.workflows) if self.name_of(r) == upstream]
                if not matches:
                    out.append(Context("unknown@%s>workflow_run" % upstream,
                                       "workflow_run", frozenset(), None, None))
                for up in matches:
                    if up in seen or up == rel:
                        continue
                    for t in sorted(triggers_of(self.workflows[up])):
                        if t in UPSTREAM_UNTRUSTED:
                            out.append(Context("%s@%s>workflow_run" % (t, up), "workflow_run",
                                               frozenset(), None, None))
                    for ctx in self.contexts_for(up, seen + (rel,)):
                        if ctx.trigger == "workflow_run":
                            out.append(Context("%s@%s>workflow_run" % (ctx.chain, up),
                                               "workflow_run", frozenset(), None, None))
        return out

    def analyse(self):
        records = set()
        for rel in sorted(self.workflows):
            for ctx in self.contexts_for(rel):
                self._workflow(rel, ctx, records, ())
        return sorted(records)

    def _workflow(self, rel, ctx, records, stack):
        wf = self.workflows[rel]
        for job_id in sorted(wf["jobs"]):
            job = wf["jobs"][job_id]
            if isinstance(job.get("uses"), str):
                self._call(rel, job_id, job, ctx, records, stack)
            else:
                self._job(rel, wf, job_id, job, ctx, records)

    def _job(self, rel, wf, job_id, job, ctx, records):
        steps = [s if isinstance(s, dict) else {} for s in job.get("steps") or []]
        shared_env = [wf.get("env"), job.get("env")]

        def allowed(names):
            if ctx.secrets_allowed is None:
                return names
            return set(n for n in names if n == "secrets.GITHUB_TOKEN"
                       or n[len("secrets."):] in ctx.secrets_allowed
                       or (n == "secrets.*" and ctx.secrets_allowed))

        perms = job["permissions"] if "permissions" in job else wf.get(
            "permissions", ctx.caller_permissions)
        job_sinks = _permissions(perms)
        env = job.get("environment")
        env = env.get("name") if isinstance(env, dict) else env
        if isinstance(env, str):
            job_sinks.add("environment:" + env)
        job_sinks |= allowed(secret_names(shared_env))

        def tainted(env):
            """Environment variable name -> the untrusted contexts its value
            expands. A variable only carries the text as data; it becomes an
            entry where a ${{ env.NAME }} expression pastes it into a step."""
            out = {}
            for key in sorted(env) if isinstance(env, dict) else ():
                out[key.upper()] = untrusted(contexts(env[key]), ctx.trigger, ctx.tainted_inputs)
            return out

        shared = {}
        for env in shared_env:
            shared.update(tainted(env))

        # Where untrusted input enters the job: (step index, source).
        entries = set()
        details = {}
        listers = set(s["id"].lower() for s in steps if isinstance(s.get("id"), str)
                      and _action(s.get("uses")) in FILENAME_ACTIONS)
        for i, step in enumerate(steps):
            variables = dict(shared, **tainted(step.get("env")))
            used = contexts([step.get("run"), step.get("with")])
            for name in untrusted(used, ctx.trigger, ctx.tainted_inputs):
                entries.add((i, name))
            for name in used:
                if name.startswith("env."):
                    for origin in variables.get(name[4:].upper(), ()):
                        entries.add((i, origin))
                part = name.lower().split(".")
                if part[0] == "steps" and len(part) > 3 and part[1] in listers and \
                        part[2] == "outputs" and not part[3].endswith("_count") and \
                        not part[3].startswith(("any_", "only_")):
                    entries.add((i, "changed file names"))
            action = _action(step.get("uses"))
            with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
            head = ctx.trigger not in _REVIEW
            if head and action == "actions/checkout" and any(
                    isinstance(with_.get(k), str) and HEAD_REFS.search(with_[k])
                    for k in ("ref", "repository")):
                entries.add((i, "checkout of pull request head"))
            if head and isinstance(step.get("run"), str) and HEAD_FETCH.search(step["run"]):
                entries.add((i, "fetch of pull request head"))
            if ctx.trigger == "workflow_run" and action in ARTIFACT_ACTIONS:
                entries.add((i, "artifact from upstream run"))
            if action in AGENT_ACTIONS:
                entries.add((i, "event text read by agent"))
                details[i] = agent_detail(action, with_)

        for start, what in sorted(entries):
            source = "%s:%s" % (ctx.chain, what)
            entry = details[start] if what == "event text read by agent" else "-"
            for sink in job_sinks:
                records.add(Record(source, rel, job_id, _label(steps[start], start), sink, entry))
            for i in range(start, len(steps)):
                step = steps[i]
                held = allowed(secret_names([step.get("run"), step.get("with"),
                                             step.get("env")]))
                for sink in held:
                    records.add(Record(source, rel, job_id, _label(step, i), sink, entry))
                action = _action(step.get("uses"))
                credential = held or job_sinks & {"permissions.id-token:write"} or \
                    allowed(secret_names(shared_env))
                if action in AGENT_ACTIONS and credential:
                    records.add(Record(source, rel, job_id, _label(step, i), "agent:" + action,
                                       details[i]))

    def _call(self, rel, job_id, job, ctx, records, stack):
        uses = job["uses"]
        with_ = job.get("with") if isinstance(job.get("with"), dict) else {}
        tainted = frozenset(k for k in sorted(with_) if untrusted(
            contexts(with_[k]), ctx.trigger, ctx.tainted_inputs))
        secrets = job.get("secrets")
        if secrets == "inherit":
            passed = None if ctx.secrets_allowed is None else ctx.secrets_allowed
        elif isinstance(secrets, dict):
            passed = frozenset(secrets)
        else:
            passed = frozenset()
        perms = job["permissions"] if "permissions" in job else self.workflows[rel].get(
            "permissions", ctx.caller_permissions)
        if not uses.startswith("./"):
            # A workflow in another repository: report what is handed to it.
            if tainted:
                sinks = ["secrets:inherit"] if secrets == "inherit" else sorted(
                    secret_names(secrets))
                sinks += sorted(_permissions(perms))
                for name in sorted(tainted):
                    for sink in sinks:
                        records.add(Record("%s:%s" % (ctx.chain, "with." + name), rel, job_id,
                                           uses, sink, "-"))
            return
        target = uses[2:].split("@")[0]
        if target not in self.workflows or target in stack:
            return
        inner = Context("%s@%s>workflow_call" % (ctx.chain, rel), ctx.trigger, tainted,
                        passed, perms)
        self._workflow(target, inner, records, stack + (rel,))
