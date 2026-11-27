# Running trust-path in CI

## GitHub Actions

Copy this file to `.github/workflows/trust-path.yml`. On every pull request it runs trust-path on
the workflows at the merge base and on the workflows in the pull request, and fails when the pull
request adds a path: a record that is not in the base branch's output. Paths that are already on
the base branch do not fail it, so the check can be turned on in a repository that has some; run
`trust-path .` to see those. It also fails when trust-path refuses a workflow file (exit status 2).
Make it a required status check in the branch rules.

```yaml
# Report paths from untrusted input to a secret or credential that the pull request adds
# to the workflows. Paths already on the base branch do not fail the check.
name: trust-path
on:
  pull_request:
permissions:
  contents: read
jobs:
  new-paths:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.13"
      - run: python -m pip install trust-path==0.8.1
      - name: Report new paths
        env:
          BASE_REF: ${{ github.base_ref }}
        run: |
          base=$(git merge-base "origin/$BASE_REF" HEAD)
          trust-path --ref "$base" . > "$RUNNER_TEMP/base.tsv" || [ $? -eq 1 ]
          trust-path . > "$RUNNER_TEMP/head.tsv" || [ $? -eq 1 ]
          export LC_ALL=C
          comm -13 <(sort "$RUNNER_TEMP/base.tsv") <(sort "$RUNNER_TEMP/head.tsv") > "$RUNNER_TEMP/new.tsv"
          cat "$RUNNER_TEMP/new.tsv"
          [ ! -s "$RUNNER_TEMP/new.tsv" ]
```

## pre-commit

The hook runs when a commit changes a file under `.github/workflows/`. It compares trust-path's
output for the staged workflows with its output for `HEAD` and fails on any added path. Add it to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: trust-path
        name: trust-path new paths
        language: python
        additional_dependencies: [trust-path==0.8.1]
        files: ^\.github/workflows/
        pass_filenames: false
        entry: >-
          sh -c 'd=$(mktemp -d);
          { trust-path --ref HEAD . || [ $? -eq 1 ]; } > "$d/old" || exit 2;
          { trust-path . || [ $? -eq 1 ]; } > "$d/new" || exit 2;
          LC_ALL=C sort -o "$d/old" "$d/old"; LC_ALL=C sort -o "$d/new" "$d/new";
          LC_ALL=C comm -13 "$d/old" "$d/new" > "$d/added"; cat "$d/added";
          ! test -s "$d/added"'
```

## Tested

Tested on 26 November 2026 in a test repository on GitHub, with trust-path 0.6.1:

| Pull request | Check |
| --- | --- |
| Adds the workflow shape of the TanStack compromise: a `pull_request_target` workflow that checks out the pull request and saves an npm cache through `actions/setup-node`, and a release workflow on `main` with `id-token: write` that restores it | Fails with one path, ending in `permissions.id-token:write` |
| Adds a `pull_request` workflow with `contents: read` | Passes |
| Changes no workflow (four pull requests) | Passes |

The pre-commit hook gave the same results on the same files with pre-commit 4.7.0.

Re-tested on 26 November 2026 with trust-path 0.7.0 in a local git
repository: the workflow's `Report new paths` script, run with `bash -e` against a bare `origin`
with one branch per case, and the pre-commit hook on the same files with pre-commit 4.7.0. Both
gave the same result for each case:

| Change | Check |
| --- | --- |
| The TanStack shape, as above | Fails with two paths, one ending in `permissions.id-token:write` |
| The sonar-findbugs shape: a `pull_request_target` workflow whose checkout `ref:` is the output of `haya14busa/action-cond` given `refs/pull/N/merge`, followed by a build with a secret | Fails with one path, ending in `secrets.PAT_TO_FORK` (trust-path 0.6.1 passes it) |
| Adds a `pull_request` workflow with `contents: read` | Passes |
| Changes no workflow | Passes (the hook is skipped) |

Re-tested on 27 November 2026 with trust-path 0.8.1, the version pinned above, in a test
repository on GitHub beside the git-surface and release-drift recipes. 0.8.1 adds `--audit-json`
and leaves the analysis of 0.7.0 unchanged.

| Pull request | Check |
| --- | --- |
| Adds a `pull_request_target` workflow that puts the pull request title in a step that has a secret | Fails with one path, ending in `secrets.BOT_TOKEN` |
| Adds a `pull_request` workflow with `contents: read` | Passes |
| Changes no workflow (four pull requests) | Passes |

The pre-commit hook, with pre-commit 4.7.0, failed the first commit with the same path and
passed the second.

## Notes

- Pin the version, as above, and raise it on purpose. A new release can add records, and a check
  that changes under you is not a reviewed check.
- The actions are pinned to a commit, with the release as a comment. Update the commit and the
  comment together.
- A `pull_request` workflow runs the copy of the workflow file in the pull request, so a pull
  request can change or remove the check. Require review of changes under `.github/`, for example
  with a `CODEOWNERS` entry; git-surface reports such changes as `ci`.
- The workflow needs no secret and only `contents: read`. It reads the repository and, where
  stated, downloads packages from the registry; it installs or runs nothing from them.
