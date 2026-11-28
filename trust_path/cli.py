"""Command line: trust-path [--json | --audit-json] [--ref REF] DIR"""

import argparse
import json
import sys

from . import __version__, audit
from .analyze import FORGES, AnalysisError, Repo

FIELDS = ("source", "workflow", "job", "step", "sink", "detail")


def _clean(text):
    """Keep each record on one line with exactly six fields."""
    return " ".join(str(text).replace("\t", " ").split())


class _Usage(Exception):
    """A usage error, raised instead of exiting when --audit-json was asked for."""


class _Parser(argparse.ArgumentParser):
    audit = False

    def error(self, message):
        if self.audit:
            self.print_usage(sys.stderr)
            sys.stderr.write("%s: error: %s\n" % (self.prog, message))
            raise _Usage(message)
        argparse.ArgumentParser.error(self, message)


def _write(doc):
    json.dump(doc, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = _Parser(
        prog="trust-path",
        description="List the paths by which untrusted input (pull request titles, issue "
                    "bodies, comments, fork code) can reach a secret, an OIDC token, a write "
                    "permission, an environment or an AI agent action in the GitHub Actions "
                    "workflows under DIR/.github/workflows (with --forge, Gitea's or "
                    "Forgejo's workflow directories). Exit status: 0 no path, 1 paths "
                    "found, 2 error.")
    parser.add_argument("dir", metavar="DIR", nargs="?",
                        help="a repository checkout (with --ref, a git repository; default .)")
    parser.add_argument("--ref", metavar="REF",
                        help="read the workflows from git at REF (a branch, tag or commit) "
                             "instead of from the files in DIR, without checking it out")
    parser.add_argument("--forge", choices=FORGES, default="github",
                        help="whose rules to apply: github (.github/workflows), gitea (the first "
                             "of .gitea/workflows and .github/workflows) or forgejo (the first of "
                             ".forgejo/workflows, .gitea/workflows and .github/workflows); "
                             "default github")
    form = parser.add_mutually_exclusive_group()
    form.add_argument("--json", action="store_true", help="write a JSON array of records")
    form.add_argument("--audit-json", action="store_true",
                      help="write one audit result object (format audit-result/1): each record "
                           "with a rule, a severity, a message and its evidence")
    parser.add_argument("--version", action="version", version="trust-path " + __version__)
    # Known before parsing, so that a usage error can still be written as one object.
    parser.audit = "--audit-json" in argv[:argv.index("--")] if "--" in argv else \
        "--audit-json" in argv
    try:
        args = parser.parse_args(argv)
        if args.dir is None and args.ref is None:
            parser.error("DIR is required without --ref")
    except _Usage as e:
        _write(audit.result(".", None, [], [(str(e), None)]))
        return 2
    try:
        repo = Repo(args.dir or ".", args.ref, args.forge)
        records = repo.analyse()
    except AnalysisError as e:
        sys.stderr.write("trust-path: %s\n" % e)
        if args.audit_json:
            _write(audit.result(args.dir or ".", args.ref, [], [(str(e), None)]))
        return 2
    rows = [[_clean(v) for v in r] for r in records]
    rows = sorted(set(tuple(r) for r in rows))
    if args.audit_json:
        findings = [audit.finding(dict(zip(FIELDS, r)), args.ref, repo.commit) for r in rows]
        errors = [("%s: %s" % (rel, _clean(reason)), rel) for rel, reason in repo.refused]
        _write(audit.result(args.dir or ".", args.ref, findings, errors))
    elif args.json:
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
