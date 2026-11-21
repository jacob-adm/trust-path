# How trust-path finds paths

trust-path reads every `*.yml` and `*.yaml` file directly in `DIR/.github/workflows`, or with
`--ref REF` the same files as they are in git at `REF`. It does not run anything (except git, with
`--ref`), contact GitHub or read files outside that directory. Local reusable workflows are read
from the same place: with `--ref`, at `REF`.

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
| a context name, such as `github.event.issue.title` | The step's `run:` or `with:` uses this context in a `${{ }}` expression, and the trigger lets an outsider set it. A context assigned to an environment variable in `env:` is not an entry by itself, because the script receives the text as data; it is an entry at a step whose `run:` or `with:` expands that variable with `${{ env.NAME }}`, or whose `run:` passes the variable to `eval` or `sh -c`, or writes it to `GITHUB_ENV`, on the same line. The list is in `UNTRUSTED_CONTEXTS` in `trust_path/analyze.py`. A context in the workflow's or job's `env:` enters at the job's first step. |
| `inputs.NAME` | In a called workflow, an input the caller set from untrusted input. |
| `with.NAME` | A call to a reusable workflow in another repository with an input set from untrusted input. |
| `checkout of pull request head` | `actions/checkout` with a `ref:` or `repository:` that names the pull request's head (`head.sha`, `head.ref`, `head_ref`, `head_sha`, `head_branch`, `head.repo`, `head_repository`, `merge_commit_sha`, `refs/pull/`). |
| `fetch of pull request head` | A `run:` with `gh pr checkout`, `refs/pull/` or `pull/${{`. |
| `artifact from upstream run` | In a `workflow_run` run, `actions/download-artifact` or `dawidd6/action-download-artifact`. |
| `changed file names` | The step's `run:` or `with:` expands an output of an earlier step that lists the files a pull request changes (`tj-actions/changed-files`, `Ana06/get-changed-files`, `jitterbit/get-changed-files`). The pull request's author chooses those names. Outputs that are counts or true/false values are not entries, and neither is an output assigned to an environment variable. |
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
| `permissions.SCOPE:write` | The entry step, for `actions`, `checks`, `contents`, `discussions`, `id-token`, `issues`, `packages`, `pull-requests`, `security-events` and `statuses` set to `write` (or `write-all`) on the job, or on the workflow when the job sets none. A called workflow without permissions uses the calling job's. `issues` and `discussions` count because injected text written there (a comment, a label, a new issue) is read by other workflows and AI agents that run on issue and discussion events, so it can travel on from there. `checks` and `statuses` count because they can post a passing result for a required check on any commit, so a pull request can be merged without its checks passing. `security-events` counts because it can dismiss code scanning alerts. |
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

### Agent detail

A record whose source is `event text read by agent`, or whose sink is `agent:OWNER/REPO`, carries
in its `detail` field what the workflow sets on that agent action. The values are the workflow's
own settings, copied as written. They are not a judgement of whether the path can be exploited.

| Part | Meaning |
| --- | --- |
| `gate=write-access` | `anthropics/claude-code-action` and `openai/codex-action` run only for users with write access unless an input opens them. That input (`allowed_non_write_users`, `allow-users`) is not set. A user with write access can still start the agent on text someone else wrote. |
| `gate=anyone` | The input is `*`: any user can start the agent. |
| `gate=listed-users` | The input names users. |
| `gate=expression` | The input is a `${{ }}` expression, which trust-path does not evaluate. |
| `gate=none` | `actions/ai-inference`, `anthropics/claude-code-base-action` and `google-github-actions/run-gemini-cli` have no input or check of their own for who starts them: whoever can trigger the workflow starts the agent. |
| `gate=not-modelled` | Another agent action; trust-path does not know how it decides who may start it. |
| `if=author_association`, `if=actor`, `if=actor+author_association` | The job's or the step's `if:` condition tests the author's association with the repository (`author_association`) or a user name (`github.actor`, `github.triggering_actor`, `sender.login`, `user.login`). The condition is not evaluated: it may restrict who starts the agent, or another part of it may still let everyone through. |
| `allowedTools=`, `disallowedTools=`, `permission-mode=`, `dangerously-skip-permissions` | The matching flags in `claude_args` of an Anthropic action. `tools=action-default` when none is set. `settings=set` when the `settings` input is used, which can also change permissions. |
| `sandbox=`, `permission-profile=`, `safety-strategy=` | The matching inputs of `openai/codex-action`. `sandbox=action-default` when unset; `safety-strategy=drop-sudo` is the action's default. |

The input names and defaults were read from each action's `action.yml` on 20 November 2026. The
actions listed under `gate=none` were checked the same day: no gating input in `action.yml` and no
author or permission check found in their code. Checks done by earlier steps are not read.

## YAML

trust-path reads workflows with its own reader for the YAML that workflows use: block mappings and
sequences, plain and quoted scalars (also over several lines, with escaped line breaks in
double-quoted scalars), `|` and `>` block scalars with `-` or `+` and an indentation indicator such
as `|2` or `>1-`, flow collections such as `[a, b]` and `{a: b}`, anchors (`&name`) with aliases (`*name`) on block
values and sequence items, comments and a leading `---`.
Every value is read as text.

It refuses a file, naming it and the line (exit status 2; the other files are still read), that
has tags (`!`), merge keys (`<<`), complex keys (`?`), an anchor or alias on a mapping key or inside a
flow collection, an alias with no anchor before it, aliases that expand to more than 100,000 values, directives
(`%`), several documents in one file, tabs in indentation, duplicate keys, a block scalar line less
indented than its block, unknown escapes in double-quoted scalars, nesting too deep to read (about
a thousand levels) and flow mapping keys without a `:`. It never guesses at a construct it does not
read.
