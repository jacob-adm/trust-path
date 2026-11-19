# Security

`trust-path` reads only the files directly in `DIR/.github/workflows`, with its own YAML reader
that refuses anything outside the subset workflows use. It never runs workflows or actions, does
not contact GitHub, and writes nothing but its output. It runs git only when given `--ref`, and
then only `git rev-parse`, `git ls-tree` and `git cat-file` in `DIR`, without a shell and without
checking anything out. See
[Limitations and security](docs/limitations-and-security.md).

## Reporting a vulnerability

Please report security problems privately, through GitHub's "Report a vulnerability" button on the
repository's Security tab. Please do not open a public issue. You can expect a reply within a week.
