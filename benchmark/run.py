# SPDX-License-Identifier: Apache-2.0
"""Run trust-path, and zizmor when it is installed, on pinned commits of
public repositories and on the agent workflows kept beside this script, and
compare what they report per workflow file.

    python3 benchmark/run.py [--corpus FILE] [--expected FILE] [--cache DIR] [--update]

Exit status: 0 the trust-path counts match the expected file, 1 they differ,
2 a repository could not be fetched or a tool failed.
"""

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ZIZMOR = ["zizmor", "--offline", "--no-config", "--persona", "auditor", "--format", "json"]
_WORKFLOW = re.compile(r"workflows/([\w.-]+\.ya?ml)")


def category(source):
    """The kind of entry a trust-path source field names."""
    what = source.rsplit(":", 1)[-1]
    if ">cache:" in source:
        return "cache"
    if what == "event text read by agent":
        return "agent"
    if what.endswith("of pull request head"):
        return "head-code"
    if what == "artifact from upstream run":
        return "artifact"
    return "expression"


def summarise(records, refused):
    """The counts kept in the expected file for one repository."""
    by = collections.Counter(category(r["source"]) for r in records)
    return {"records": len(records), "refused": refused, "by_category": dict(sorted(by.items())),
            "agent_files_by_gate": agent_gates(records)}


def agent_gates(records):
    """Number of workflow files with an agent path, for each gate value."""
    gates = collections.defaultdict(set)
    for r in records:
        if category(r["source"]) == "agent":
            gate = r.get("detail", "").split(";")[0].replace("gate=", "") or "unknown"
            gates[gate].add(os.path.basename(r["workflow"]))
    return dict((g, len(files)) for g, files in sorted(gates.items()))


def injection_files(records):
    """Workflow files where trust-path reports pasted text or fork code."""
    return set(os.path.basename(r["workflow"]) for r in records
               if category(r["source"]) in ("expression", "head-code"))


def agent_files(records):
    return set(os.path.basename(r["workflow"]) for r in records
               if category(r["source"]) == "agent")


def zizmor_files(findings, ident="template-injection"):
    """Workflow files where zizmor reports a finding of kind `ident`."""
    out = set()
    for f in findings:
        if f.get("ident") == ident:
            out.update(_WORKFLOW.findall(json.dumps(f.get("locations", []))))
    return out


def compare(ours, theirs):
    return {"both": len(ours & theirs), "trust-path only": len(ours - theirs),
            "zizmor only": len(theirs - ours)}


def _run(cmd, cwd=None, ok=(0,)):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    if p.returncode not in ok:
        raise RuntimeError("%s: exit %d: %s" % (" ".join(cmd[:2]), p.returncode,
                                                p.stderr.strip()[:200]))
    return p


def fetch(url, commit, dest):
    """Check out .github/workflows of `url` at `commit` into `dest`."""
    if os.path.isdir(os.path.join(dest, ".github", "workflows")):
        return
    os.makedirs(dest)
    _run(["git", "init", "-q"], dest)
    _run(["git", "fetch", "-q", "--depth", "1", "--filter=blob:none", url, commit], dest)
    _run(["git", "checkout", "-q", "FETCH_HEAD", "--", ".github/workflows"], dest)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--corpus", default=os.path.join(HERE, "corpus.json"))
    parser.add_argument("--expected", default=os.path.join(HERE, "expected.json"))
    parser.add_argument("--cache", help="directory to keep the fetched workflows in")
    parser.add_argument("--update", action="store_true", help="rewrite the expected file")
    args = parser.parse_args(argv)
    with open(args.corpus) as f:
        corpus = json.load(f)
    cache = args.cache or tempfile.mkdtemp()
    have_zizmor = shutil.which("zizmor") is not None
    actual = {}
    try:
        if have_zizmor:
            print("zizmor: %s" % _run(["zizmor", "--version"]).stdout.strip())
        else:
            print("zizmor: not installed, comparison skipped")
        for repo in corpus:
            if "path" in repo:  # workflows kept beside the corpus file
                name, at = os.path.basename(repo["path"]), "local"
                dest = os.path.join(os.path.dirname(os.path.abspath(args.corpus)), repo["path"])
            else:
                name, at = repo["url"].rstrip("/").split("/")[-1], repo["commit"][:12]
                dest = os.path.join(cache, name + "-" + at)
                fetch(repo["url"], repo["commit"], dest)
            p = _run([sys.executable, "-m", "trust_path", "--json", dest],
                     cwd=os.path.dirname(HERE), ok=(0, 1, 2))
            records = json.loads(p.stdout)
            refused = len(p.stderr.splitlines())
            actual[name] = summarise(records, refused)
            files = os.listdir(os.path.join(dest, ".github", "workflows"))
            print("\n%s @ %s (%d workflow files)" % (name, at, len(files)))
            print("  trust-path: %(records)d records, %(refused)d files refused, "
                  "%(by_category)s" % actual[name])
            print("  trust-path: %d files with an agent path, by gate %s" % (
                len(agent_files(records)), actual[name]["agent_files_by_gate"]))
            if have_zizmor:
                findings = json.loads(_run(ZIZMOR + [dest], ok=tuple(range(15))).stdout or "[]")
                print("  injection, by workflow file: %s" % compare(
                    injection_files(records), zizmor_files(findings)))
    except (RuntimeError, OSError, ValueError) as e:
        sys.stderr.write("benchmark: %s\n" % e)
        return 2
    finally:
        if not args.cache:
            shutil.rmtree(cache, ignore_errors=True)
    if args.update:
        with open(args.expected, "w") as f:
            json.dump(actual, f, indent=2, sort_keys=True)
            f.write("\n")
        return 0
    with open(args.expected) as f:
        expected = json.load(f)
    if actual != expected:
        print("\nDIFFERENT from %s:" % args.expected)
        for name in sorted(set(actual) | set(expected)):
            if actual.get(name) != expected.get(name):
                print("  %s: expected %s, got %s" % (name, expected.get(name), actual.get(name)))
        return 1
    print("\ntrust-path counts match %s" % os.path.basename(args.expected))
    return 0


if __name__ == "__main__":
    sys.exit(main())
