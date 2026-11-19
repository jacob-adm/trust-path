# Command

```
trust-path [--json] DIR
```

`DIR` is a repository checkout. trust-path reads the workflow files in `DIR/.github/workflows`
and writes one record per path from untrusted input to a sink.

## Output

Each record is one line of five tab-separated fields:

```
source	workflow	job	step	sink
```

| Field | Content |
| --- | --- |
| source | How untrusted input gets in: the run (trigger, or chain of workflows) and, after the last `:`, where it enters the job. See [How trust-path finds paths](model.md). |
| workflow | The workflow file holding the sink, relative to `DIR`, for example `.github/workflows/release.yml`. |
| job | The job id. |
| step | The step's `name:`, else its `id:`, else its `uses:`, else `step N` (counting from 1). For a call to a reusable workflow in another repository, the `uses:` value. |
| sink | What untrusted input reaches: `secrets.NAME`, `permissions.SCOPE:write`, `permissions:default`, `environment:NAME`, `agent:OWNER/REPO` or `secrets:inherit`. |

Tabs and line breaks inside a field are replaced by spaces. Records are sorted and each appears
once, so the same files always give the same output.

`--json` writes the same records, in the same order, as a JSON array of objects with the keys
`source`, `workflow`, `job`, `step` and `sink`.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | No path found. Also when `DIR/.github/workflows` does not exist. |
| 1 | At least one path found. |
| 2 | Error: `DIR` is not a directory, a workflow file cannot be read, uses YAML trust-path does not read, is not a workflow (no `jobs:` mapping), or calls a local reusable workflow that is not in the directory. The message names the file and, for YAML, the line. Nothing is written to standard output. |

## Example

The repository's test fixtures are small repositories. From a clone:

```sh
trust-path tests/fixtures/workflow_run_chain
```

```text
pull_request@.github/workflows/ci.yml>workflow_run@.github/workflows/stage.yml>workflow_run:github.event.workflow_run.head_branch	.github/workflows/publish.yml	publish	Tag	environment:pypi
pull_request@.github/workflows/ci.yml>workflow_run@.github/workflows/stage.yml>workflow_run:github.event.workflow_run.head_branch	.github/workflows/publish.yml	publish	Tag	permissions.id-token:write
```

`ci.yml` runs on pull requests, so a fork chooses the branch name. `stage.yml` runs on
`workflow_run` after `ci.yml`, and `publish.yml` runs on `workflow_run` after `stage.yml`. The
publish job puts `github.event.workflow_run.head_branch` into a shell command in the step `Tag`,
in a job that holds an OIDC token (`id-token: write`) and uses the `pypi` environment.
