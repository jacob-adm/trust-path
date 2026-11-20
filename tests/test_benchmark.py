import contextlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "benchmark_run", os.path.join(ROOT, "benchmark", "run.py"))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)

WORKFLOW = """\
on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
        env:
          T: ${{ secrets.T }}
"""


def rec(source, workflow=".github/workflows/a.yml"):
    return {"source": source, "workflow": workflow}


class PureTests(unittest.TestCase):
    def test_category(self):
        self.assertEqual(bench.category("issues:event text read by agent"), "agent")
        self.assertEqual(bench.category("pull_request_target:checkout of pull request head"),
                         "head-code")
        self.assertEqual(bench.category("pull_request_target:fetch of pull request head"),
                         "head-code")
        self.assertEqual(bench.category("a@b>workflow_run:artifact from upstream run"), "artifact")
        self.assertEqual(bench.category("issues:github.event.issue.title"), "expression")

    def test_summarise(self):
        records = [rec("issues:github.event.issue.title"), rec("issues:event text read by agent")]
        self.assertEqual(bench.summarise(records, 1), {
            "records": 2, "refused": 1, "by_category": {"agent": 1, "expression": 1},
            "agent_files_by_gate": {"unknown": 1}})

    def test_agent_gates_count_files(self):
        def agent(workflow, detail):
            return {"source": "issues:event text read by agent", "workflow": workflow,
                    "detail": detail}
        records = [agent("a.yml", "gate=anyone; tools=action-default"),
                   agent("a.yml", "gate=anyone; tools=action-default"),
                   agent("b.yml", "gate=anyone; sandbox=read-only"),
                   agent("c.yml", "gate=write-access"),
                   {"source": "issues:github.event.issue.title", "workflow": "d.yml",
                    "detail": "-"}]
        self.assertEqual(bench.agent_gates(records), {"anyone": 2, "write-access": 1})

    def test_files_and_compare(self):
        records = [rec("issues:github.event.issue.title", ".github/workflows/a.yml"),
                   rec("issues:event text read by agent", ".github/workflows/b.yml")]
        self.assertEqual(bench.injection_files(records), {"a.yml"})
        self.assertEqual(bench.agent_files(records), {"b.yml"})
        findings = [
            {"ident": "template-injection",
             "locations": [{"symbolic": {"key": {"Local": {"given_path": "x/.github/workflows/c.yaml"}}}}]},
            {"ident": "unpinned-uses",
             "locations": [{"symbolic": {"key": {"Local": {"given_path": "x/.github/workflows/a.yml"}}}}]},
        ]
        self.assertEqual(bench.zizmor_files(findings), {"c.yaml"})
        self.assertEqual(bench.compare({"a.yml", "b.yml"}, {"b.yml", "c.yml"}),
                         {"both": 1, "trust-path only": 1, "zizmor only": 1})


class LocalCorpusTests(unittest.TestCase):
    def test_shipped_agent_workflows_match_the_expected_file(self):
        """The agent workflows beside the script need no network."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        here = os.path.join(ROOT, "benchmark")
        corpus = os.path.join(here, "agents-only.json")
        with open(os.path.join(here, "expected.json")) as f:
            expected = {"agents": json.load(f)["agents"]}
        with open(os.path.join(tmp, "expected.json"), "w") as f:
            json.dump(expected, f)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bench.main(["--corpus", corpus, "--expected",
                               os.path.join(tmp, "expected.json")])
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(expected["agents"]["agent_files_by_gate"],
                         {"anyone": 3, "none": 2, "write-access": 2})


class RunTests(unittest.TestCase):
    """main() on a workflow already in the cache, so nothing is fetched."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        commit = "0123456789abcdef0123"
        wdir = os.path.join(self.tmp, "cache", "repo-" + commit[:12], ".github", "workflows")
        os.makedirs(wdir)
        with open(os.path.join(wdir, "w.yml"), "w") as f:
            f.write(WORKFLOW)
        self.corpus = os.path.join(self.tmp, "corpus.json")
        with open(self.corpus, "w") as f:
            json.dump([{"url": "https://example.invalid/owner/repo", "commit": commit}], f)
        self.expected = os.path.join(self.tmp, "expected.json")

    def run_main(self, *extra):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bench.main(["--corpus", self.corpus, "--expected", self.expected,
                               "--cache", os.path.join(self.tmp, "cache")] + list(extra))
        return code, out.getvalue()

    def test_update_then_match_then_differ(self):
        self.assertEqual(self.run_main("--update")[0], 0)
        with open(self.expected) as f:
            self.assertEqual(json.load(f), {"repo": {
                "records": 2, "refused": 0, "by_category": {"expression": 2},
                "agent_files_by_gate": {}}})
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("trust-path counts match", out)
        with open(self.expected, "w") as f:
            json.dump({"repo": {"records": 3, "refused": 0, "by_category": {"expression": 3},
                                "agent_files_by_gate": {}}}, f)
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("DIFFERENT", out)
