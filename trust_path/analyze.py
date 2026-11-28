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

# Script lines that run the text of a variable as code (eval, sh -c) or write
# it to GITHUB_ENV, which sets variables for later steps.
SHELL_SINK = re.compile(
    r"(?:^|[\s;&|(`])eval\s"
    r"|(?:^|[\s;&|(`/])(?:ba|da|k|z)?sh\s+(?:-[a-z]+\s+)*-[a-z]*c\b"
    r"|\$\{?GITHUB_ENV\b")
_SHELL_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")


def shell_sink_variables(script, sink=None):
    """Names (upper-cased) of the variables a script evaluates or writes to
    GITHUB_ENV; with `sink`, of those on lines that `sink` matches."""
    names = set()
    if not isinstance(script, str):
        return names
    for line in script.replace("\\\n", " ").splitlines():
        if (sink or SHELL_SINK).search(line):
            names.update(m.upper() for m in _SHELL_VAR.findall(line))
    return names


# A script line that writes to GITHUB_OUTPUT, which sets the step's outputs.
OUTPUT_SINK = re.compile(r"\$\{?GITHUB_OUTPUT\b")

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
# Agent actions with no input or check of their own for who starts them:
# whoever can trigger the workflow starts the agent.
AGENT_UNGATED = (
    "actions/ai-inference",
    "anthropics/claude-code-base-action",
    "google-github-actions/run-gemini-cli",
)
# What an `if:` condition tests when it restricts who started the run.
_IF_TESTS = (
    ("actor", re.compile(r"github\.(triggering_)?actor\b|\b(sender|user)\.login\b")),
    ("author_association", re.compile(r"\bauthor_association\b")),
)
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
# run on issue and discussion events: injected text can travel on. checks and
# statuses count because a passing result can be posted for a required check
# on any commit; security-events because code scanning alerts can be dismissed.
WRITE_SCOPES = ("actions", "checks", "contents", "discussions", "id-token", "issues",
                "packages", "pull-requests", "security-events", "statuses")

_EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
_CONTEXT = re.compile(
    r"(?<![\w.-])(github|gitea|forgejo|forge|inputs|secrets|env|steps|needs)"
    r"((?:\.[A-Za-z_*][\w*-]*|\[[^\]]*\])*)")
# Gitea defines gitea as the github context, Forgejo forgejo and forge; neither name means
# anything on GitHub, so they are read as github everywhere.
_CONTEXT_ALIASES = {"gitea": "github", "forgejo": "github", "forge": "github"}

# Where each forge reads workflows: the first directory that exists is used, and the others
# are ignored. Gitea and Forgejo also read subdirectories; GitHub reads the directory only.
# (Gitea's server setting WORKFLOW_DIRS can change its list; the default is shown.)
FORGE_DIRS = {
    "github": (".github/workflows",),
    "gitea": (".gitea/workflows", ".github/workflows"),
    "forgejo": (".forgejo/workflows", ".gitea/workflows", ".github/workflows"),
}
FORGES = tuple(sorted(FORGE_DIRS))
# The automatic token under each name it is given in the secrets context.
TOKEN_SECRETS = ("secrets.GITHUB_TOKEN", "secrets.GITEA_TOKEN", "secrets.FORGEJO_TOKEN")


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
                found.add(_norm(_CONTEXT_ALIASES.get(m.group(1), m.group(1)) + m.group(2)))
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


# The Actions cache. A job that runs pull request code where the run belongs to the
# default branch (pull_request_target, issue_comment, workflow_run, ...) can save
# caches that a later push or release run restores. Caches are matched by the step
# that saves and restores them, not by key: the same `uses:` in both jobs.
CACHE_SETUP_ACTIONS = ("actions/setup-node", "actions/setup-python", "actions/setup-go",
                       "actions/setup-java", "actions/setup-dotnet", "ruby/setup-ruby")
NO_CACHE_ACTIONS = ("actions/checkout", "actions/upload-artifact", "actions/download-artifact",
                    "actions/github-script", "actions/labeler", "actions/upload-pages-artifact",
                    "actions/deploy-pages", "actions/configure-pages")
CACHE_READER_TRIGGERS = ("push", "schedule", "workflow_dispatch", "release", "merge_group",
                         "repository_dispatch")


def cache_step(step):
    """The `uses:` (lower case, without @ref) of a step that can save or restore the
    Actions cache, or None. That is actions/cache, a setup action with a `cache`
    input, or any other action except a few that do not use the cache: trust-path
    does not read an action's code, and a shared setup action is where caches
    usually are."""
    uses = step.get("uses")
    if not isinstance(uses, str) or uses.startswith("docker://"):
        return None
    name = uses.split("@")[0].lower()
    action = _action(uses)
    if action in NO_CACHE_ACTIONS:
        return None
    if action in CACHE_SETUP_ACTIONS:
        with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
        return name if with_.get("cache") else None
    return "actions/cache" if action == "actions/cache" else name


def _action(uses):
    """owner/repo of a `uses:` value, lower-cased; '' for docker:// and ./"""
    if not isinstance(uses, str) or uses.startswith(("docker://", "./")):
        return ""
    return "/".join(uses.split("@")[0].split("/")[:2]).lower()


_STEP_OUTPUT = re.compile(r"\bsteps\.([A-Za-z_][\w-]*)\.outputs\.")


def upstream_artifact(action, with_):
    """Whether a step downloads an artifact of another run. actions/download-artifact
    reads the current run's artifacts unless `run-id` is given; the other action
    always reads another run."""
    if action == "actions/download-artifact":
        return "run-id" in with_
    return action in ARTIFACT_ACTIONS


def head_checkouts(steps):
    """Indexes of the actions/checkout steps whose `ref:` or `repository:` selects
    the pull request's head, written out or carried by the output of an earlier
    step: an action other than actions/checkout given a head value in `with:`,
    or a script line that writes one, directly or through a variable from the
    step's `env:`, to GITHUB_OUTPUT."""
    carriers, out = set(), set()

    def head(text):
        return isinstance(text, str) and (HEAD_REFS.search(text) is not None or any(
            m.lower() in carriers for m in _STEP_OUTPUT.findall(text)))

    for i, step in enumerate(steps):
        with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
        if _action(step.get("uses")) == "actions/checkout":
            if any(head(with_.get(k)) for k in ("ref", "repository")):
                out.add(i)
            continue
        if not isinstance(step.get("id"), str):
            continue
        env = step.get("env") if isinstance(step.get("env"), dict) else {}
        head_vars = set(k.upper() for k, v in env.items() if head(v))
        run = step.get("run") if isinstance(step.get("run"), str) else ""
        lines = [l for l in run.replace("\\\n", " ").splitlines() if OUTPUT_SINK.search(l)]
        if any(head(v) for v in with_.values()) or any(
                head(l) or head_vars & set(m.upper() for m in _SHELL_VAR.findall(l))
                for l in lines):
            carriers.add(step["id"].lower())
    return out


def agent_detail(action, with_, conditions=()):
    """What the workflow sets on an agent action: who may start it (gate),
    what the job's and step's `if:` conditions test about the person who
    started the run, and what the agent may do. Values are the workflow's
    own, not a judgement; conditions are not evaluated."""
    def text(key):
        return with_[key].strip() if isinstance(with_.get(key), str) else ""

    parts = []
    if action in AGENT_GATES:
        gate = text(AGENT_GATES[action])
        parts.append("gate=" + ("write-access" if not gate else "anyone" if gate == "*"
                                else "expression" if "${{" in gate else "listed-users"))
    else:
        parts.append("gate=none" if action in AGENT_UNGATED else "gate=not-modelled")
    text_if = " ".join(c for c in conditions if isinstance(c, str))
    tests = [name for name, pattern in _IF_TESTS if pattern.search(text_if)]
    if tests:
        parts.append("if=" + "+".join(tests))
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


def _drop_trigger(wf, name):
    """Remove one event from a workflow's on: (a string, a list or a mapping)."""
    on = wf.get("on")
    if on == name:
        wf["on"] = {}
    elif isinstance(on, list):
        wf["on"] = [t for t in on if t != name]
    elif isinstance(on, dict):
        on.pop(name, None)


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


def _git_reader(root, ref, forge="github"):
    """(commit id, path -> function returning the text of each workflow file
    at ref), read from git without a checkout. The files are those of the
    first of the forge's workflow directories that exists at ref."""
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
    commit = commit.decode().strip()
    files = {}
    for wdir in FORGE_DIRS[forge]:
        args = ["ls-tree", "-z", "--full-tree"] + (["-r"] if forge != "github" else [])
        listing = _git(root, *(args + [commit, "--", wdir + "/"]))
        if not listing and not _git(root, "ls-tree", "--full-tree", commit, "--", wdir):
            continue  # no such directory: try the next one
        for entry in listing.split(b"\0"):
            if not entry:
                continue
            meta, path = entry.split(b"\t", 1)
            mode, kind, oid = meta.decode().split(" ")
            if kind != "blob":
                continue
            rel = path.decode("utf-8", "replace")
            if mode == "120000":
                files[rel] = None
            else:
                files[rel] = lambda oid=oid: _git(root, "cat-file", "blob", oid).decode("utf-8")
        break
    return commit, files


def _dir_reader(root, forge="github"):
    """path -> function returning the text of each workflow file under DIR, in
    the first of the forge's workflow directories that exists (a symbolic link
    maps to None)."""
    if not os.path.isdir(root):
        raise AnalysisError("%s: not a directory" % root)

    def read(rel):
        with open(os.path.join(root, *rel.split("/")), encoding="utf-8") as f:
            return f.read()
    for wdir in FORGE_DIRS[forge]:
        full = os.path.join(root, *wdir.split("/"))
        if not os.path.isdir(full):
            continue
        files = {}
        for top, dirs, names in os.walk(full):
            dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(top, d)))
            for name in names:
                rel = os.path.relpath(os.path.join(top, name), root).replace(os.sep, "/")
                files[rel] = None if os.path.islink(os.path.join(top, name)) else \
                    (lambda rel=rel: read(rel))
            if forge == "github":
                break  # GitHub reads the directory only
        return files
    return {}


def _job_order(jobs):
    """Job ids with every job after the jobs it needs; otherwise sorted.
    A needs cycle or a missing job is ignored (GitHub refuses both)."""
    order, done = [], set()

    def visit(job_id, path):
        if job_id in done or job_id in path or job_id not in jobs:
            return
        needs = jobs[job_id].get("needs") if isinstance(jobs[job_id], dict) else None
        for need in [needs] if isinstance(needs, str) else (needs if isinstance(needs, list) else []):
            if isinstance(need, str):
                visit(need, path + (job_id,))
        done.add(job_id)
        order.append(job_id)

    for job_id in sorted(jobs):
        visit(job_id, ())
    return order


class Repo(object):
    """The readable workflows of a repository, from the directory or, with
    `ref`, from git at that ref. Files that cannot be read are listed in
    `refused` as sorted (file, reason) pairs and left out. A job that calls a
    missing local workflow is listed there too, but its file is still read."""

    def __init__(self, root, ref=None, forge="github"):
        if forge not in FORGE_DIRS:
            raise AnalysisError("unknown forge %s (one of %s)" % (forge, ", ".join(FORGES)))
        self.root = root
        self.forge = forge
        self.workflows = {}
        self.commit = None  # with ref, the full id of the commit it names
        refused = {}
        if ref is None:
            files = _dir_reader(root, forge)
        else:
            self.commit, files = _git_reader(root, ref, forge)
        for rel in sorted(files):
            if not rel.endswith((".yml", ".yaml")):
                continue
            if files[rel] is None:
                refused[rel] = "a symbolic link, not read"
                continue
            try:
                wf = _check(yamlsubset.load(files[rel]()))
                if forge == "forgejo":
                    _drop_trigger(wf, "workflow_run")  # Forgejo has no workflow_run event
                self.workflows[rel] = wf
            except yamlsubset.YamlError as e:
                refused[rel] = "line %d: %s" % (e.line, e.message)
            except AnalysisError as e:
                refused[rel] = str(e)
            except (OSError, UnicodeDecodeError) as e:
                refused[rel] = str(e)
        for rel in refused:
            self.workflows.pop(rel, None)
        # A call to a local reusable workflow that does not exist is named like
        # a refused file, but only that job is skipped; the caller's other jobs
        # are still analysed. A call to one that was refused is skipped silently.
        missing = []
        for rel in sorted(self.workflows):
            for job_id, job in sorted(self.workflows[rel]["jobs"].items()):
                uses = job.get("uses")
                if isinstance(uses, str) and uses.startswith("./"):
                    target = uses[2:].split("@")[0]
                    if target not in self.workflows and target not in refused:
                        missing.append((rel, "job %r calls %s, which is not in %s" % (
                            job_id, uses, rel.rsplit("/", 1)[0])))
        self.refused = sorted(list(refused.items()) + missing)

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
        self._cache(records)
        return sorted(records)

    def _cache(self, records):
        """Paths through the Actions cache: a job that checks out or fetches pull
        request code in an untrusted run, and a job in a push, release or other
        default-branch run that uses the same cache step afterwards."""
        writers = []  # (source, workflow, job, cache step names)
        for rel in sorted(self.workflows):
            for ctx in self.contexts_for(rel):
                if ctx.trigger in _REVIEW:
                    continue
                for job_id, job in sorted(self.workflows[rel]["jobs"].items()):
                    steps = [x if isinstance(x, dict) else {} for x in job.get("steps") or []]
                    checkouts = head_checkouts(steps)
                    for i, step in enumerate(steps):
                        what = None
                        if i in checkouts:
                            what = "checkout of pull request head"
                        elif isinstance(step.get("run"), str) and HEAD_FETCH.search(step["run"]):
                            what = "fetch of pull request head"
                        if what:
                            names = set(filter(None, (cache_step(x) for x in steps[i + 1:])))
                            if names:
                                writers.append(("%s@%s>cache:%s" % (ctx.chain, rel, what),
                                                rel, job_id, names))
                            break
        if not writers:
            return
        for rel in sorted(self.workflows):
            wf = self.workflows[rel]
            if not set(triggers_of(wf)) & set(CACHE_READER_TRIGGERS):
                continue
            for job_id, job in sorted(wf["jobs"].items()):
                steps = [x if isinstance(x, dict) else {} for x in job.get("steps") or []]
                perms = job["permissions"] if "permissions" in job else wf.get("permissions")
                sinks = _permissions(perms)
                env = job.get("environment")
                env = env.get("name") if isinstance(env, dict) else env
                if isinstance(env, str):
                    sinks.add("environment:" + env)
                sinks |= secret_names([wf.get("env"), job.get("env")])
                for source, wrel, wjob, names in writers:
                    if (wrel, wjob) == (rel, job_id):
                        continue
                    for i, step in enumerate(steps):
                        name = cache_step(step)
                        if name not in names:
                            continue
                        held = set(sinks)
                        for later in steps[i:]:
                            held |= secret_names([later.get("run"), later.get("with"),
                                                  later.get("env")])
                        for sink in held:
                            records.add(Record(source, rel, job_id, _label(step, i), sink,
                                               "cache step " + name))
                        break

    def _workflow(self, rel, ctx, records, stack):
        wf = self.workflows[rel]
        # needs.JOB.outputs.NAME (lower case) -> the untrusted sources it carries.
        # Jobs run after the jobs they need, so their outputs are known first.
        outputs = {}
        for job_id in _job_order(wf["jobs"]):
            job = wf["jobs"][job_id]
            if isinstance(job.get("uses"), str):
                self._call(rel, job_id, job, ctx, records, stack)
            else:
                outputs.update(self._job(rel, wf, job_id, job, ctx, records, outputs))

    def _job(self, rel, wf, job_id, job, ctx, records, needed=None):
        """Record the paths in one job; return the job's outputs that carry
        untrusted sources, keyed needs.JOB.outputs.NAME."""
        needed = needed or {}
        steps = [s if isinstance(s, dict) else {} for s in job.get("steps") or []]
        shared_env = [wf.get("env"), job.get("env")]

        def allowed(names):
            if ctx.secrets_allowed is None:
                return names
            return set(n for n in names if n in TOKEN_SECRETS
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
            entry where a ${{ env.NAME }} expression pastes it into a step, or
            where the script evaluates it or writes it to GITHUB_ENV."""
            out = {}
            for key in sorted(env) if isinstance(env, dict) else ():
                out[key.upper()] = sources(contexts(env[key]))
            return out

        def sources(names):
            """Untrusted contexts among `names`, plus what the outputs of
            needed jobs among them carry."""
            out = untrusted(names, ctx.trigger, ctx.tainted_inputs)
            for name in names:
                out |= needed.get(name.lower(), set())
            return out

        shared = {}
        for env in shared_env:
            shared.update(tainted(env))

        # Where untrusted input enters the job: (step index, source).
        entries = set()
        details = {}
        written = {}  # step index -> sources its script writes to GITHUB_OUTPUT
        checkouts = head_checkouts(steps)
        listers = set(s["id"].lower() for s in steps if isinstance(s.get("id"), str)
                      and _action(s.get("uses")) in FILENAME_ACTIONS)
        for i, step in enumerate(steps):
            variables = dict(shared, **tainted(step.get("env")))
            used = contexts([step.get("run"), step.get("with")])
            for name in sources(used):
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
            for name in shell_sink_variables(step.get("run")):
                for origin in variables.get(name, ()):
                    entries.add((i, origin))
            written[i] = set(origin for name in shell_sink_variables(step.get("run"), OUTPUT_SINK)
                             for origin in variables.get(name, ()))
            action = _action(step.get("uses"))
            with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
            head = ctx.trigger not in _REVIEW
            if head and i in checkouts:
                entries.add((i, "checkout of pull request head"))
            if head and isinstance(step.get("run"), str) and HEAD_FETCH.search(step["run"]):
                entries.add((i, "fetch of pull request head"))
            if ctx.trigger == "workflow_run" and upstream_artifact(action, with_):
                entries.add((i, "artifact from upstream run"))
            if action in AGENT_ACTIONS:
                entries.add((i, "event text read by agent"))
                details[i] = agent_detail(action, with_, (job.get("if"), step.get("if")))

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

        # A job output carries what reaches the step it reads: every source that
        # entered at or before that step, as for the steps themselves, and the
        # untrusted variables that step writes to GITHUB_OUTPUT.
        index = dict((s["id"].lower(), i) for i, s in enumerate(steps) if isinstance(s.get("id"), str))
        carried = {}
        declared = job.get("outputs")
        for key in sorted(declared) if isinstance(declared, dict) else ():
            names = contexts(declared[key])
            found = sources(names)
            for name in names:
                part = name.lower().split(".")
                if part[0] == "steps" and len(part) > 2 and part[1] in index:
                    found |= set(what for start, what in entries if start <= index[part[1]])
                    found |= written[index[part[1]]]
            if found:
                carried["needs.%s.outputs.%s" % (job_id.lower(), key.lower())] = found
        return carried

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
