# Using it with other tools

This page shows the tested stack trust-path is part of, then what two similar tools cover.

The commands on this page use [trust-path](https://github.com/jacob-adm/trust-path),
[git-surface](https://github.com/jacob-adm/git-surface) and
[git-overlap](https://github.com/jacob-adm/git-overlap). trust-path and git-surface are not on PyPI
yet and install from GitHub:

```sh
pip install git+https://github.com/jacob-adm/trust-path
pip install git+https://github.com/jacob-adm/git-surface
pip install git-overlap
```

The examples come from a test repository whose `main` has a small Python module, its tests, a
`requirements.txt`, a changelog and a Markdown guide, and six branches as an agent might push
them: `agent/a` renames a function, `agent/b` changes the same line, `agent/c` adds a module that
calls the function by its old name, `agent/ci` adds a workflow that passes the pull request title
to a step holding a secret, `agent/deps` bumps a pinned version in `requirements.txt`, and
`agent/docs` adds an HTML comment to the guide. Every command was run on that repository and the
output shown is what it printed.

**Exit status.** `git overlap`, `git pairmerge`, `git surface`, `trust-path` and
`release-drift diff` and `source` exit like `grep`: 0 nothing found, 1 found, 2 error.
`git footprint` and `release-drift fetch` exit 0 on success. With `set -o pipefail`, a pipeline
in which any step found something exits 1: treat 1 as a finding, not a failure, and only 2 as an
error. In a `for` or `while` loop the status is that of the last command only, so read the
output.

## Before merging: what each branch changes

Three commands over the same list of branches, run in a clone that has them. None of them
changes the repository.

**1. What each branch changes that runs or is trusted** (git-overlap's `git footprint`, then
`git surface`):

```sh
git for-each-ref --format='%(refname:short)' refs/heads/agent/ | git footprint main | git surface main
```

```text
agent/ci	ci	A	.github/workflows/triage.yml
agent/deps	deps	M git-overlap 0.3.1->0.3.2	requirements.txt
agent/docs	hidden	<!-- line 4	docs/guide.md
```

`git surface` reads only the ref from each record and runs its own diff, so its report is the
same with or without `git footprint` in front. Its classes are `ci`, `deps`, `exec`, `hidden`,
`hook` and `install`; the `deps` detail shows `name old->new` for a pinned version.

**2. Paths from untrusted input to a secret, on branches that change CI** (`git surface`, then
`trust-path --ref`, which reads the workflows from git at the branch without checking it out):

```sh
git for-each-ref --format='%(refname:short)' refs/heads/agent/ | git surface main |
    awk -F'\t' '$2 == "ci" {print $1}' | uniq |
    while read -r ref; do echo "$ref:"; trust-path --ref "$ref"; done
```

```text
agent/ci:
pull_request_target:github.event.pull_request.title	.github/workflows/triage.yml	label	Label	permissions:default
pull_request_target:github.event.pull_request.title	.github/workflows/triage.yml	label	Label	secrets.TRIAGE_TOKEN
```

The pull request title, in a workflow triggered by `pull_request_target`, reaches the step that
holds `secrets.TRIAGE_TOKEN`, and the job runs with default token permissions.

**3. Conflicts between branches** (git-overlap):

```sh
git for-each-ref --format='%(refname:short)' refs/heads/agent/ | git footprint main | git overlap | git pairmerge --onto main
```

```text
agent/a	agent/b	conflict	CHANGELOG.md
agent/a	agent/b	conflict	app.py
agent/a	agent/b	conflict	tests/test_app.py
```

`git overlap` pairs the branches that change the same file and `git pairmerge` merges each pair in
memory, keeping those that conflict. With `--onto main`, a pair in which a branch also conflicts
with `main` is reported as `stale`: after one more commit to `CHANGELOG.md` on `main`, the same
pair gives `agent/a	agent/b	stale	CHANGELOG.md`.

**What it catches:** changes to CI, dependencies, build files, hooks and hidden content per branch,
paths from untrusted input to secrets and write permissions in changed workflows, and conflicting
or stale pairs. **What it does not catch:** nothing here runs the tests, so `agent/c`, which merges
cleanly but calls the function `agent/a` renames, is not reported.

## Similar tools

[zizmor](https://github.com/zizmorcore/zizmor) and [poutine](https://github.com/boostsecurityio/poutine)
are static analysers for GitHub Actions workflows. This section lists what each detects that is close
to what trust-path reports, and what trust-path adds. It was written from the documentation and
rule source on each project's main branch on 19 November 2026 (latest releases at that date:
zizmor 1.32.0, poutine 1.1.6). Both projects change often; check their current documentation.

trust-path is meant to run alongside them, not instead of them. Both check many things trust-path
does not look at, such as unpinned actions, known vulnerable actions, cache poisoning and
self-hosted runners.

### zizmor

zizmor runs a set of audits, each over one workflow or action file, and reports each finding at one
location in that file. The audits closest to trust-path:

| Audit | What it reports |
| --- | --- |
| `template-injection` | A `${{ }}` expansion of attacker-controllable context (for example `github.event.issue.title`) in a code context: `run:`, `actions/github-script` `script:`, and the action inputs in a list of known code sinks taken from CodeQL plus four more actions. In a reusable workflow, a string `inputs.*` value counts as attacker-controllable. |
| `dangerous-triggers` | Use of the `pull_request_target`, `workflow_run` and `issue_comment` triggers. |
| `dangerous-checkout` | `actions/checkout` with `allow-unsafe-pr-checkout: true` (main branch, not in a release yet). |
| `artipacked` | Credentials that `actions/checkout` persists on disk, and ways they can end up in uploaded artifacts. |
| `excessive-permissions` | Workflow or job permissions wider than needed, including unset (default) permissions. |
| `overprovisioned-secrets` | The whole `secrets` context exposed, for example `toJSON(secrets)`. |
| `secrets-inherit` | `secrets: inherit` when calling a reusable workflow. |
| `secrets-outside-env` | Secrets used in a job without an `environment:` (auditor persona only). |
| `github-env` | Writes to `GITHUB_ENV` and `GITHUB_PATH` in workflows with triggers such as `pull_request_target` and `workflow_run`. |
| `use-trusted-publishing` | Publishing with a stored token where trusted publishing (OIDC) is available. |

### poutine

poutine runs Rego rules over an inventory of a repository's workflows. The rules closest to
trust-path:

| Rule | What it reports |
| --- | --- |
| `injection` | An attacker-controllable expression from a fixed list (including `inputs.*` and `client_payload`) in `run:` or `actions/github-script` `script:`. |
| `untrusted_checkout_exec` | A checkout of fork code followed by a command known to execute that code (build tools, package managers), in workflows triggered by `pull_request_target`, `issues`, `issue_comment` or `workflow_call`, or by `workflow_run` when the parent workflow named in the trigger (one level, same repository) is triggered by `pull_request_target`, `pull_request`, `issues` or `issue_comment`. |
| `default_permissions_on_risky_events` | No `permissions:` set on a workflow triggered by events used to build forks. |
| `job_all_secrets` | A job with access to all secrets (`toJSON(secrets)` or dynamic keys). |
| `confused_deputy_auto_merge` | Auto-merge driven by a bot actor check on risky events. |
| `pr_runs_on_self_hosted` | Pull request jobs on self-hosted runners. |

### What trust-path adds

Neither tool, at the date above, does the following:

1. **Report the path, not the location.** Both tools report an untrusted input at the step where it
   is used, and separately report broad secrets or permissions. trust-path reports each pair: this
   source reaches this secret, `id-token: write`, write permission or environment, through this
   workflow, job and step.
2. **Follow a source across workflows.** trust-path follows `workflow_run` chains of any length
   between workflows in the repository, and follows inputs and the triggering event from a caller
   into a local reusable workflow (`uses: ./.github/workflows/...`). poutine follows one level of
   `workflow_run` for its checkout rule only; zizmor treats each file on its own.
3. **Treat AI agent actions as sinks.** Neither tool has rules for AI agent actions such as
   `anthropics/claude-code-action` or `google-github-actions/run-gemini-cli`, which act on the text
   they are given while holding API keys or tokens. trust-path reports an agent action that can
   receive untrusted text while it holds a secret or an OIDC token.

trust-path does not rank, score or explain its findings, and it does not cover the other checks
listed above.
