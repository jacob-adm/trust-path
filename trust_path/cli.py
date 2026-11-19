"""Command line: trust-path [--json] DIR"""

import argparse
import json
import sys

from . import __version__
from .analyze import AnalysisError, Repo

FIELDS = ("source", "workflow", "job", "step", "sink")


def _clean(text):
    """Keep each record on one line with exactly five fields."""
    return " ".join(str(text).replace("\t", " ").split())


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="trust-path",
        description="List the paths by which untrusted input (pull request titles, issue "
                    "bodies, comments, fork code) can reach a secret, an OIDC token, a write "
                    "permission, an environment or an AI agent action in the GitHub Actions "
                    "workflows under DIR/.github/workflows. Exit status: 0 no path, 1 paths "
                    "found, 2 error.")
    parser.add_argument("dir", metavar="DIR", help="a repository checkout")
    parser.add_argument("--json", action="store_true", help="write a JSON array of records")
    parser.add_argument("--version", action="version", version="trust-path " + __version__)
    args = parser.parse_args(argv)
    try:
        repo = Repo(args.dir)
        records = repo.analyse()
    except AnalysisError as e:
        sys.stderr.write("trust-path: %s\n" % e)
        return 2
    rows = [[_clean(v) for v in r] for r in records]
    rows = sorted(set(tuple(r) for r in rows))
    if args.json:
        json.dump([dict(zip(FIELDS, r)) for r in rows], sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for r in rows:
            sys.stdout.write("\t".join(r) + "\n")
    for rel, reason in repo.refused:
        sys.stderr.write("trust-path: %s: %s\n" % (rel, _clean(reason)))
    if repo.refused:
        return 2
    return 1 if rows else 0


if __name__ == "__main__":
    sys.exit(main())
