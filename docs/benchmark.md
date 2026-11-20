# Benchmark

`benchmark/run.py` runs trust-path on pinned commits of public repositories, and on a set of AI
agent workflows kept in this repository, and checks that its counts have not changed. When [zizmor](https://github.com/zizmorcore/zizmor) is installed, it also
shows, per workflow file, where the two tools report injection.

```sh
python3 benchmark/run.py
```

It needs git and network access to fetch the workflow files, and Python 3.9 or later. It never runs
workflow code. zizmor is optional; without it the comparison is skipped.

## What it runs on

`benchmark/corpus.json` lists each repository and the commit it is read at. The two listed are
training repositories whose workflows are vulnerable on purpose:
[messypoutine/gravy-overflow](https://github.com/messypoutine/gravy-overflow) and
[step-security/github-actions-goat](https://github.com/step-security/github-actions-goat).
`--corpus FILE` runs another list in the same format.

The third entry, `fixtures/agents`, is a directory in this repository with eight workflows written
for the benchmark. Each runs an AI agent action set up a different way: open to any user with no
tool limits, open with tool limits, left at the action's default gate, in a read-only sandbox, an
action with no gate of its own (once bare, once behind an `if:` that tests the author), and one that
holds no credential and so has nothing
to report. They sit under `benchmark/`, not in the repository's own `.github/workflows`, so GitHub
never runs them. `benchmark/agents-only.json` runs just this entry and needs no network.

## Output

For each repository:

```
gravy-overflow @ cbff1a67a804 (6 workflow files)
  trust-path: 71 records, 1 files refused, {'expression': 52, 'head-code': 19}
  trust-path: 0 files with an agent path, by gate {}
  injection, by workflow file: {'both': 3, 'trust-path only': 0, 'zizmor only': 0}
```

- **records** are trust-path records, grouped by how the input enters: `expression` (a context
  pasted into `run:` or `with:`), `head-code` (the pull request's head checked out or fetched),
  `artifact` and `agent`.
- **files with an agent path, by gate** counts the workflow files with an `agent` record under each
  gate value from the record's `detail` field, for example
  `{'anyone': 3, 'none': 2, 'write-access': 2}` for `fixtures/agents`.
- **injection, by workflow file** counts the files where trust-path reports an `expression` or
  `head-code` record and the files where zizmor reports `template-injection`, run as
  `zizmor --offline --no-config --persona auditor`.

The two tools answer different questions, so a file in one column only is not by itself an error
in the other tool. zizmor reports an expression pasted into a script whatever the job holds.
trust-path reports it only when the run can be started by an outsider and the job holds a secret,
a write permission, an environment or an agent.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | trust-path's counts match `benchmark/expected.json`. |
| 1 | They differ; the differing repositories are printed. |
| 2 | A repository could not be fetched or a tool failed. |

After a deliberate change to what trust-path reports, `--update` rewrites the expected file.
`--cache DIR` keeps the fetched workflows between runs.
