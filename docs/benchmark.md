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

`benchmark/corpus.json` lists each repository and the commit it is read at. Two are training
repositories whose workflows are vulnerable on purpose:
[messypoutine/gravy-overflow](https://github.com/messypoutine/gravy-overflow) and
[step-security/github-actions-goat](https://github.com/step-security/github-actions-goat). The
third is [TanStack/router](https://github.com/TanStack/router) at `b1c061a`, the commit on `main`
before the May 2026 worm, whose path ran through the Actions cache (see
[The Actions cache](model.md#the-actions-cache)). Four more are repositories at the commit
before a documented incident, listed in [Incidents](#incidents).
`--corpus FILE` runs another list in the same format.

`benchmark/popular.json` is a separate, held-out list: the 100 most-starred non-archived
repositories with workflows, pinned on 26 November 2026. It is not part of the default run and is
used to check that a change to the rules does not add records on ordinary repositories. With
0.6.1 it gives 179 records; following head refs through step outputs (0.7.0) adds none and
removes none.

```sh
python3 benchmark/run.py --corpus benchmark/popular.json --expected popular-expected.json --update
```

The last entry, `fixtures/agents`, is a directory in this repository with eight workflows written
for the benchmark. Each runs an AI agent action set up a different way: open to any user with no
tool limits, open with tool limits, left at the action's default gate, in a read-only sandbox, an
action with no gate of its own (once bare, once behind an `if:` that tests the author), and one that
holds no credential and so has nothing
to report. They sit under `benchmark/`, not in the repository's own `.github/workflows`, so GitHub
never runs them. `benchmark/agents-only.json` runs just this entry and needs no network.

## Incidents

Each repository below is read at a commit whose workflow files hold the path an attacker used,
as the project or a named investigator described it. trust-path was not changed for these
entries; a miss is recorded as a miss. Measured with trust-path 0.6.1 on 26 November 2026. A rule
added later for a miss is checked on the held-out list above, and the row says from which version
the path is reported.

| Repository and commit | Incident and source | Workflow used | trust-path |
| --- | --- | --- | --- |
| [TanStack/router](https://github.com/TanStack/router) `b1c061a` | May 2026 worm ([postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)) | `bundle-size.yml` poisons the Actions cache that `release.yml` restores | Reported (`cache`) |
| [nrwl/nx](https://github.com/nrwl/nx) `c916349` | August 2025, malicious Nx releases on npm ([postmortem](https://nx.dev/blog/s1ngularity-postmortem), [GHSL-2025-111](https://securitylab.github.com/advisories/GHSL-2025-111_nrwl_nx/)) | `pr-title-validation.yml`: `pull_request_target`, the pull request title and body pasted into `run:` | Reported (`expression`, `permissions:default`) |
| [Kong/kubernetes-ingress-controller](https://github.com/Kong/kubernetes-ingress-controller) `792ce60` | December 2024, unauthorized 3.4.0 image ([Kong](https://konghq.com/blog/product-releases/december-2024-unauthorized-kong-ingress-controller-3-4-0-build)) | `checks.yaml`: `pull_request_target` on every branch, calling reusable workflows that check out the pull request head with secrets | Reported (`head-code`, through `workflow_call`, to the called workflows' secrets) |
| [spotbugs/sonar-findbugs](https://github.com/spotbugs/sonar-findbugs) `e240bc1` | December 2024, maintainer token stolen, first step towards the tj-actions/changed-files compromise ([Unit 42](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)) | `sonarqube.yml`: `pull_request_target`, checks out `refs/pull/N/merge` and runs `./mvnw` with `PAT_TO_FORK` | Missed by 0.6.1: the checkout `ref:` is the output of a third-party action (`haya14busa/action-cond`) whose input holds the pull request ref. Reported from 0.7.0, which follows a head ref through step outputs (`head-code`, to `PAT_TO_FORK` and `SONAR_TOKEN`) |
| [ultralytics/ultralytics](https://github.com/ultralytics/ultralytics) `21162bd` | December 2024, malicious ultralytics 8.3.41 and 8.3.42 on PyPI ([Snyk](https://snyk.io/blog/ultralytics-ai-pwn-request-supply-chain-attack)) | `format.yml`: `pull_request_target` runs `ultralytics/actions@main`, whose own code expanded the branch name in a shell | **Missed.** The injection is in the action's code, which trust-path does not read (see [Limitations](limitations-and-security.md)) |

Kong's `checks.yaml` first runs a permission check that lets `dependabot[bot]` and
`renovate[bot]` through by `github.triggering_actor`; Kong names that exception as the way in.
trust-path does not read checks done in other jobs, so it reports the path whatever the check
says.

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
