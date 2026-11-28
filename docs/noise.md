# Records on popular repositories

How often trust-path reports a path in the workflows of ordinary, well-maintained repositories,
and how many of those paths an outsider can use as written. Measured on 27 November 2026 with
trust-path 0.8.1.

## Sample

`benchmark/popular.json`: the 100 most-starred non-archived repositories with workflows, each at
a pinned commit (26 November 2026). The run reads only `.github/workflows`:

```sh
python3 benchmark/run.py --corpus benchmark/popular.json --expected popular-expected.json --update
```

## Results

23 of the 100 repositories have at least one record (exit status 1), with 179 records in all.
Each record was read by hand against its workflow file and put in one of five groups:

| Group | Records | Meaning |
| --- | --- | --- |
| Open | 22 | Outsider input reaches the credential as written. All 22 are AI agent actions that anyone can start from an issue or comment (`gate=anyone`); most limit the agent's tools or run it in a read-only sandbox, which trust-path reports in `detail`. |
| Open, not verified | 17 | Pull request code runs, or can run, where it reaches the credential, but deciding needs more than the workflow files: cache keys set by the project's own files (15), or a `workflow_run` `branches:` filter as the only check, which a fork branch of the same name passes (2). |
| Guarded | 82 | A check trust-path does not evaluate keeps outsiders out: the agent action's own write-access check (`gate=write-access`, 62), an `if:` on `author_association`, the head repository or the branch, or a job that runs only after a maintainer check. |
| Data only | 52 | Outsider content reaches the job only as data: `toJSON` into a request body, text in a comment, an artifact read with `jq` and checked against the API, a pull request fetched as git objects and diffed but never run. |
| Wrong | 6 | The path does not exist: an artifact downloaded without `run-id` comes from the same run, not the upstream one (3), and a cache writer whose only checkout of the pull request is a sparse checkout of `README.md` (3). |

39 of the 179 records (22%) are open or open but not verified, in 4 of the 23 repositories. In
the other 19 repositories every record is guarded, data only or wrong. As an absolute check
(fail on any record), trust-path would fail 23 of these 100 repositories, 19 of them on records an
outsider cannot use as written.

Per-repository results are not published here: they describe live workflows of other projects.

## What this means for a required check

trust-path reports paths, not exploits, and does not evaluate `if:` conditions (see
[Limitations](limitations-and-security.md)). Most records on a well-run repository are paths its
maintainers already closed in a way trust-path does not read.

- Run it on changes, not on the whole repository. The workflow in [Running it in CI](ci.md) fails
  only on records a pull request adds, so the records already on the base branch do not fail it.
- Keep reviewed records in a baseline file. `--baseline FILE` leaves out the records listed in
  FILE, a JSON array written by `--json`. A record is left out only when all six fields match, so a
  change to its source, sink or `detail` (an agent's gate, for example) reports it again:

  ```sh
  trust-path --json . > .github/trust-path-baseline.json   # after reviewing each record
  trust-path --baseline .github/trust-path-baseline.json .
  ```

  The baseline is a file in the repository, so accepting a path is a change a reviewer sees.
