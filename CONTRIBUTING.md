# Contributing

## Tests

```sh
python3 -m unittest discover -s tests
```

The suite covers the YAML reader (what it accepts and what it refuses), the path analysis on
fixture workflows (sources, entry points, sinks and AI agent actions), and the command's output,
JSON and exit status.

## Contributing

Changes reach `main` only through pull requests.

1. Fork the repository and create a branch.
2. Make the change with a test that fails without it, then run `python3 -m unittest discover -s tests`.
3. Open a pull request against `main`. CI runs the tests on Linux, macOS and Windows with Python
   3.9 and 3.13, runs trust-path on its own workflows, and builds the package; the required checks
   must pass before merging. Pull requests are merged with a merge commit.

Keep trust-path standard-library-only, and keep it reading files only: it never runs workflow code.
