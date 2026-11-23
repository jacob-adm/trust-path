# Limitations and security

## What trust-path reads and does

- It reads the files directly in `DIR/.github/workflows`, and nothing else. It does not run
  workflows or actions, does not contact GitHub, and writes nothing but its output.
- It runs git only with `--ref REF`: `git rev-parse` to check that `DIR` is a repository and `REF`
  names a commit, `git ls-tree` to list `.github/workflows` at that commit and `git cat-file` to
  read each file. git is started without a shell, with `LC_ALL=C`, in `DIR`; nothing is checked
  out and the working tree is not read or changed. git's own configuration for that repository
  still applies to these commands.
- It reports. It does not change workflows, block merges or decide whether a path is exploitable.
  A record means untrusted input can reach the sink under the rules in
  [How trust-path finds paths](model.md); whether that is a problem depends on what the steps do.

## What it does not see

- **Settings outside the files.** The repository's default token permissions, which secrets
  exist and where (repository, organisation, environment), environment protection rules, and the
  setting that sends secrets to fork pull request workflows in private repositories.
- **Composite and JavaScript actions.** It does not read the code of the actions a step uses,
  local (`uses: ./path`) or remote, so an action that reads the event payload itself is only
  modelled for the AI agent actions listed in [How trust-path finds paths](model.md).
- **Reusable workflows in other repositories.** It reports what a call passes to them, but does
  not follow the call.
- **Data passed between jobs other than job outputs.** Job outputs are followed (see
  [Job outputs](model.md#job-outputs)), except the outputs of a call to a reusable workflow.
  Artifacts within a run are not followed. Caches are followed from a job that runs pull request
  code to a default-branch job that uses the same cache step (see
  [The Actions cache](model.md#the-actions-cache)); cache keys are not compared, and pull request
  code that writes the cache without a cache step in its job, for example through the runner's
  cache token, is not modelled.
- **Unsafe use of an environment variable.** Untrusted text assigned to a variable in `env:` is
  reported only where a `run:` line names the variable together with `eval`, `sh -c` (or `bash`,
  `dash`, `ksh`, `zsh`) or `GITHUB_ENV`. The check reads lines, not shell syntax: it misses a
  variable copied to another variable first, or passed to a script or another interpreter that
  evaluates it, and it reports a variable on such a line even when it is a safe positional argument
  (`sh -c 'echo "$1"' _ "$TITLE"`).
- **Indirect flows inside a job.** Values written to `GITHUB_ENV`, `GITHUB_OUTPUT` or files are not
  tracked one by one. Instead, every step after the entry step in the same job counts as reached.
- **Conditions.** `if:` conditions, branch filters and `types:` filters are not evaluated, so a
  path guarded by a condition is still reported.
- **The checkout default.** `actions/checkout` v7 refuses fork pull request code under
  `pull_request_target` and `workflow_run` unless `allow-unsafe-pr-checkout: true` is set. trust-path
  reports a head checkout whatever the version and setting.
- **`workflow_run` names.** The `workflows:` list is matched exactly against workflow names; glob
  patterns are not expanded. A name with no match is reported as `unknown@NAME`.
- **Context list.** Untrusted contexts and AI agent actions come from fixed lists in
  `trust_path/analyze.py`. A context or agent action not in a list is not reported.

## YAML

The reader covers the YAML that workflows use and refuses the rest with exit status 2; see
[YAML](model.md#yaml). Anchors and aliases are read on block values and sequence items; an anchor on a mapping key or inside a flow collection is refused.
