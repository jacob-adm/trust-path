# How trust-path finds paths

trust-path reads every `*.yml` and `*.yaml` file directly in `DIR/.github/workflows`. It does not
run anything, contact GitHub or read files outside that directory.

## Runs that carry untrusted input

A workflow is analysed once for each way it can run with untrusted input. This is the first part
of the record's source field, before the last `:`.

| Source prefix | Meaning |
| --- | --- |
| `pull_request_target`, `issues`, `issue_comment`, `pull_request_review`, `pull_request_review_comment`, `discussion`, `discussion_comment` | The workflow has this trigger. These runs get the base repository's secrets and token, and anyone who can open an issue, comment or pull request controls part of the event. |
| `T@A>workflow_run` | The workflow has a `workflow_run` trigger naming workflow `A` (matched by its `name:`, or its path when it has none), and `A` has trigger `T`. `T` is one of the triggers above, or `pull_request`: a `workflow_run` run gets secrets and a write token even when the run that triggered it did not. |
| `…@A>workflow_run@B>workflow_run` | A chain: `B` is itself run by `workflow_run` from an untrusted run of `A`. Chains of any length are followed, although GitHub runs at most three levels; a workflow already in the chain is not entered again. |
| `unknown@NAME>workflow_run` | The `workflow_run` trigger names a workflow that no file in the directory has. It is reported as untrusted rather than skipped. |
| `…@C>workflow_call` | The workflow is a local reusable workflow, called by `uses: ./.github/workflows/...` from workflow `C` running with untrusted input. The called workflow sees the caller's event. |

Other triggers, such as `push`, `pull_request`, `workflow_dispatch`, `repository_dispatch` and
`schedule`, are not sources on their own: their event data comes from people with write access or
from GitHub, and `pull_request` runs for fork pull requests get no secrets and a read-only token.

## Where untrusted input enters a job

Within each run, trust-path finds the steps where untrusted input enters a job. This is the part
of the source field after the last `:`.

| Source suffix | Meaning |
| --- | --- |
| a context name, such as `github.event.issue.title` | The step's `run:`, `with:` or `env:` uses this context in a `${{ }}` expression, and the trigger lets an outsider set it. The list is in `UNTRUSTED_CONTEXTS` in `trust_path/analyze.py`. A context in the workflow's or job's `env:` enters at the job's first step. |
| `inputs.NAME` | In a called workflow, an input the caller set from untrusted input. |
| `with.NAME` | A call to a reusable workflow in another repository with an input set from untrusted input. |
| `checkout of pull request head` | `actions/checkout` with a `ref:` or `repository:` that names the pull request's head (`head.sha`, `head.ref`, `head_ref`, `head_sha`, `head_branch`, `head.repo`, `head_repository`, `merge_commit_sha`, `refs/pull/`). |
| `fetch of pull request head` | A `run:` with `gh pr checkout`, `refs/pull/` or `pull/${{`. |
| `artifact from upstream run` | In a `workflow_run` run, `actions/download-artifact` or `dawidd6/action-download-artifact`. |
| `event text read by agent` | An AI agent action (list below). These actions can read the triggering issue, comment or pull request themselves, through the event or their tools, so trust-path treats them as receiving untrusted text in any untrusted run. |

Under `pull_request_review` and `pull_request_review_comment`, only the review and comment text
count: pull request fields and head checkouts are written by the pull request's author, and runs
for fork pull requests get no secrets and a read-only token.

## What untrusted input reaches

Once untrusted input enters a job at a step, trust-path treats that step and every later step of
the same job as reached: they share one runner, one workspace and one token. Other jobs are not
reached. The sink field names what is reached:

| Sink | Reported at |
| --- | --- |
| `secrets.NAME` | Each reached step whose `run:`, `with:` or `env:` uses it. A secret in the workflow's or job's `env:` is reported at the entry step. `secrets.*` means the whole context (`toJSON(secrets)` or a computed key). In a called workflow, only the secrets the caller passes (or all, with `secrets: inherit`), plus `GITHUB_TOKEN`. |
| `permissions.SCOPE:write` | The entry step, for `actions`, `contents`, `id-token`, `packages` and `pull-requests` set to `write` (or `write-all`) on the job, or on the workflow when the job sets none. A called workflow without permissions uses the calling job's. |
| `permissions:default` | The entry step, when neither the job nor the workflow (nor the caller) sets `permissions:`. The token then has the repository's default permissions, which the workflow files do not show and which can include write access. |
| `environment:NAME` | The entry step, when the job has `environment:`. |
| `agent:OWNER/REPO` | A reached AI agent action that holds a credential: a secret in its `with:` or `env:` or the job's `env:`, or `id-token: write`. |
| `secrets:inherit` | `secrets: inherit` on a call to a reusable workflow in another repository. |

For a call to a reusable workflow in another repository, which trust-path cannot read, the step
field is the `uses:` value, and the records list the secrets and permissions the call passes when
one of its inputs is set from untrusted input.

## AI agent actions

The actions trust-path treats as AI agents, each checked to exist on GitHub on 19 November 2026:

- `actions/ai-inference`
- `anthropics/claude-code-action`
- `anthropics/claude-code-base-action`
- `google-github-actions/run-gemini-cli`
- `openai/codex-action`
- `warpdotdev/oz-agent-action`

Matching is on `owner/repo`, case-insensitive, at any version.

## YAML

trust-path reads workflows with its own reader for the YAML that workflows use: block mappings and
sequences, plain and quoted scalars (also over several lines), `|` and `>` block scalars with `-`
or `+`, flow collections such as `[a, b]` and `{a: b}`, comments and a leading `---`. Every value is
read as text.

It refuses, with exit status 2 and the file and line, anchors (`&`), aliases (`*`), tags (`!`),
merge keys (`<<`), complex keys (`?`), directives (`%`), several documents in one file, tabs in
indentation, duplicate keys, block scalar indentation indicators (`|2`) and flow mapping keys
without a `:`. It never guesses at a construct it does not read.
