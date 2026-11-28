# Command

```
trust-path [--forge FORGE] [--json | --audit-json] [--baseline FILE] DIR
trust-path [--forge FORGE] [--json | --audit-json] [--baseline FILE] --ref REF [DIR]
```

`DIR` is a repository checkout. trust-path reads the workflow files in `DIR/.github/workflows`
and writes one record per path from untrusted input to a sink.

## Gitea and Forgejo

`--forge gitea` or `--forge forgejo` applies that forge's rules instead of GitHub's. Both forges
run workflows written in GitHub's syntax; what differs, and how trust-path follows it:

| | GitHub (default) | Gitea | Forgejo |
| --- | --- | --- | --- |
| Workflow directory | `.github/workflows` | the first that exists of `.gitea/workflows`, `.github/workflows` | the first that exists of `.forgejo/workflows`, `.gitea/workflows`, `.github/workflows` |
| Subdirectories | not read | read | read |
| Context names read as `github` | | `gitea` | `forgejo`, `forge` |
| `workflow_run` event | yes | yes | no: a workflow started only by it never runs |

Only the first directory that exists is read, as the forge does: in a Gitea repository with both
`.gitea/workflows` and `.github/workflows`, the files in `.github/workflows` never run and are not
read. The automatic token is followed under each of its names, `secrets.GITHUB_TOKEN`,
`secrets.GITEA_TOKEN` and `secrets.FORGEJO_TOKEN`. The context names `gitea`, `forgejo` and
`forge` are read as `github` whatever the forge, since none of them means anything else.

Sources: Gitea's [comparison with GitHub Actions](https://docs.gitea.com/usage/actions/comparison)
and [FAQ](https://docs.gitea.com/usage/actions/faq); Forgejo's
[Actions reference](https://forgejo.org/docs/latest/user/actions/reference/); and, for the
directories and events, the `ListWorkflows` code of each forge. Not modelled: a Gitea server's
`WORKFLOW_DIRS` setting (the default list is used), Gitea's different `permissions:` scopes
(the GitHub scopes are read), and Gitea ignoring `environment:`.

With `--ref REF`, trust-path reads the workflow directory from git at `REF` (a branch, tag or commit)
in the repository at `DIR`, which defaults to the current directory. Nothing is checked out and
the working tree is not read, so it can check a pull request's branch or an old release without
switching to it:

```sh
trust-path --ref origin/main
```

With `--baseline FILE`, trust-path leaves out the records listed in `FILE`, a JSON array as
written by `--json`. A record is left out only when all six fields match. The exit status and
every output form count only the records that are left. A `FILE` that cannot be read or is not
an array of records is an error (exit status 2). See [Records on popular repositories](noise.md)
for why and when to keep one.

## Output

Each record is one line of six tab-separated fields:

```
source	workflow	job	step	sink	detail
```

| Field | Content |
| --- | --- |
| source | How untrusted input gets in: the run (trigger, or chain of workflows) and, after the last `:`, where it enters the job. See [How trust-path finds paths](model.md). |
| workflow | The workflow file holding the sink, relative to `DIR`, for example `.github/workflows/release.yml`. |
| job | The job id. |
| step | The step's `name:`, else its `id:`, else its `uses:`, else `step N` (counting from 1). For a call to a reusable workflow in another repository, the `uses:` value. |
| sink | What untrusted input reaches: `secrets.NAME`, `permissions.SCOPE:write`, `permissions:default`, `environment:NAME`, `agent:OWNER/REPO` or `secrets:inherit`. |
| detail | For a record that enters at, or ends in, an AI agent action: what the workflow sets on that action, as `gate=...` followed by its tool or sandbox settings. See [AI agent actions](model.md#ai-agent-actions). `-` for every other record. |

Tabs and line breaks inside a field are replaced by spaces. Records are sorted and each appears
once, so the same files always give the same output.

`--json` writes the same records, in the same order, as a JSON array of objects with the keys
`source`, `workflow`, `job`, `step`, `sink` and `detail`.

## Audit result output

`--audit-json` writes one JSON object in the audit result format (`audit-result/1`), for a CI
job or an agent that runs several audit tools and reads their results the same way. Each
finding is a `--json` record with what a reader needs to act on it: a rule id, a severity, one
sentence that says what the path is, and the evidence to check it. For the `pr_title` test
fixture (`trust-path --audit-json tests/fixtures/pr_title`):

```json
{
  "errors": [],
  "exit": 1,
  "findings": [
    {
      "evidence": {
        "path": ".github/workflows/greet.yml"
      },
      "message": "Untrusted input from pull_request_target, entering as github.event.pull_request.title, reaches the secret BOT_TOKEN in .github/workflows/greet.yml, job greet, step Post greeting",
      "record": {
        "detail": "-",
        "job": "greet",
        "sink": "secrets.BOT_TOKEN",
        "source": "pull_request_target:github.event.pull_request.title",
        "step": "Post greeting",
        "workflow": ".github/workflows/greet.yml"
      },
      "rule": "trust-path.secret",
      "severity": "high"
    }
  ],
  "format": "audit-result/1",
  "target": {
    "kind": "repository",
    "name": "pr_title"
  },
  "tool": {
    "name": "trust-path",
    "version": "0.8.0"
  }
}
```

| Key | Value |
| --- | --- |
| `format` | `audit-result/1`. |
| `tool` | `trust-path` and its version. |
| `target` | `kind` `repository`; `name`, the name of `DIR` (the current directory without one); `ref`, REF as given with `--ref`. |
| `exit` | The exit status of the run, 0, 1 or 2. |
| `findings` | One object per record, in the same order as the other outputs. |
| `errors` | One object per error, with the `message` also written to standard error and, for a refused file or missing call, its `path`. |

Each finding has:

- `rule` and `severity`, fixed by the kind of sink, never by what the step does:

  | Sink | `rule` | `severity` |
  | --- | --- | --- |
  | `secrets.NAME` | `trust-path.secret` | `high` |
  | `secrets:inherit` | `trust-path.secrets-inherit` | `high` |
  | `permissions.id-token:write` | `trust-path.oidc-token` | `high` |
  | `permissions.SCOPE:write` (other scopes) | `trust-path.write-permission` | `high` |
  | `agent:OWNER/REPO` | `trust-path.agent` | `high` |
  | `environment:NAME` | `trust-path.environment` | `medium` |
  | `permissions:default` | `trust-path.default-permissions` | `medium` |

  An environment can require a reviewer before a job runs, and the default token permissions
  depend on the repository's settings, so those two are `medium`.
- `message`: where untrusted input comes from (a chain of runs reads `pull_request in
  .github/workflows/ci.yml, then workflow_run`), where it enters, what it reaches, and the
  workflow, job and step; then the agent detail in parentheses when there is one.
- `evidence`: `path`, the workflow file; with `--ref`, `ref` as given and `commit`, the full id
  of the commit it names. trust-path does not keep line numbers, so there is no `line`.
- `record`: the `--json` record, unchanged.

The object is written on every run, also on an error, so a reader always gets one object. With
a refused file, the paths found in the other files are kept and the exit status is 2. On any
other error, including a usage error such as `--json` with `--audit-json`, `findings` is empty,
`errors` holds the message and the exit status is 2.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | No path found. Also when `DIR/.github/workflows` does not exist. |
| 1 | At least one path found. |
| 2 | Error: `DIR` is not a directory, or, with `--ref`, not a git repository or `REF` is not a commit; or at least one workflow file was refused. Paths found in the other files are still written. |

A workflow file is refused when it cannot be read (with `--ref`, also when it is a symbolic link), uses YAML trust-path does not read, is not a
workflow (no `jobs:` mapping, a job that is not a mapping, steps that are not a list). A job that
calls a local reusable workflow that is not in the directory is treated the same way, except that
only that call is skipped: the other jobs in its file are still read. trust-path still reads every
other file and writes the paths it finds in them, then writes one line per refused file or missing
call to standard error:

```
trust-path: .github/workflows/a.yml: line 3: tags are not supported
```

A call to a refused reusable workflow is not followed, and a `workflow_run` trigger naming a
refused workflow is reported as `unknown@NAME`. So with status 2 the output can miss paths
through the refused files, but every path it shows is real.

## Example

The repository's test fixtures are small repositories. From a clone:

```sh
trust-path tests/fixtures/workflow_run_chain
```

```text
pull_request@.github/workflows/ci.yml>workflow_run@.github/workflows/stage.yml>workflow_run:github.event.workflow_run.head_branch	.github/workflows/publish.yml	publish	Tag	environment:pypi	-
pull_request@.github/workflows/ci.yml>workflow_run@.github/workflows/stage.yml>workflow_run:github.event.workflow_run.head_branch	.github/workflows/publish.yml	publish	Tag	permissions.id-token:write	-
```

`ci.yml` runs on pull requests, so a fork chooses the branch name. `stage.yml` runs on
`workflow_run` after `ci.yml`, and `publish.yml` runs on `workflow_run` after `stage.yml`. The
publish job puts `github.event.workflow_run.head_branch` into a shell command in the step `Tag`,
in a job that holds an OIDC token (`id-token: write`) and uses the `pypi` environment.
