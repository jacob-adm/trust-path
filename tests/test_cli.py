import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")


def run(*args):
    env = dict(os.environ, PYTHONPATH=ROOT)
    p = subprocess.run([sys.executable, "-m", "trust_path"] + list(args), cwd=ROOT, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return p.returncode, p.stdout, p.stderr


def records(name):
    code, out, err = run(os.path.join(FIXTURES, name))
    return code, [tuple(line.split("\t")) for line in out.splitlines()], err


class PathTests(unittest.TestCase):
    def test_pr_title_reaches_secret(self):
        code, recs, _ = records("pr_title")
        self.assertEqual(code, 1)
        self.assertEqual(recs, [(
            "pull_request_target:github.event.pull_request.title",
            ".github/workflows/greet.yml", "greet", "Post greeting", "secrets.BOT_TOKEN")])

    def test_head_checkout_reaches_later_secret(self):
        code, recs, _ = records("head_checkout")
        self.assertEqual(code, 1)
        self.assertEqual(recs, [(
            "pull_request_target:checkout of pull request head",
            ".github/workflows/build.yml", "build", "Install", "secrets.NPM_TOKEN")])

    def test_workflow_run_chain_reaches_publish_job(self):
        code, recs, _ = records("workflow_run_chain")
        self.assertEqual(code, 1)
        source = ("pull_request@.github/workflows/ci.yml>workflow_run@.github/workflows/stage.yml"
                  ">workflow_run:github.event.workflow_run.head_branch")
        self.assertEqual(recs, [
            (source, ".github/workflows/publish.yml", "publish", "Tag", "environment:pypi"),
            (source, ".github/workflows/publish.yml", "publish", "Tag",
             "permissions.id-token:write"),
        ])

    def test_agent_given_issue_body_with_api_key(self):
        code, recs, _ = records("agent")
        self.assertEqual(code, 1)
        step = "anthropics/claude-code-action@v1"
        wf = ".github/workflows/triage.yml"
        self.assertEqual(recs, [
            ("issues:event text read by agent", wf, "triage", step,
             "agent:anthropics/claude-code-action"),
            ("issues:event text read by agent", wf, "triage", step, "secrets.ANTHROPIC_API_KEY"),
            ("issues:github.event.issue.body", wf, "triage", step,
             "agent:anthropics/claude-code-action"),
            ("issues:github.event.issue.body", wf, "triage", step, "secrets.ANTHROPIC_API_KEY"),
        ])

    def test_reusable_workflow_input(self):
        code, recs, _ = records("reusable")
        self.assertEqual(code, 1)
        source = "issue_comment@.github/workflows/on-comment.yml>workflow_call:inputs.text"
        wf = ".github/workflows/reply.yml"
        self.assertEqual(recs, [
            (source, wf, "reply", "Reply", "permissions.pull-requests:write"),
            (source, wf, "reply", "Reply", "secrets.token"),
        ])

    def test_safe_workflows_report_nothing(self):
        code, recs, err = records("safe")
        self.assertEqual((code, recs, err), (0, [], ""))

    def test_own_workflows_report_nothing(self):
        self.assertEqual(run("."), (0, "", ""))


class OutputTests(unittest.TestCase):
    def test_json_matches_text(self):
        code, out, _ = run("--json", os.path.join(FIXTURES, "agent"))
        self.assertEqual(code, 1)
        _, recs, _ = records("agent")
        self.assertEqual([tuple(r[k] for k in ("source", "workflow", "job", "step", "sink"))
                          for r in json.loads(out)], recs)

    def test_json_empty(self):
        self.assertEqual(run("--json", os.path.join(FIXTURES, "safe")), (0, "[]\n", ""))

    def test_deterministic(self):
        # Same output on every run and whatever order files are created in.
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        outputs = set()
        for order in (sorted, lambda xs: sorted(xs, reverse=True)):
            dest = os.path.join(tmp, str(len(outputs)), ".github", "workflows")
            os.makedirs(dest)
            for fixture in order(["workflow_run_chain", "agent", "reusable", "pr_title"]):
                src = os.path.join(FIXTURES, fixture, ".github", "workflows")
                for name in order(os.listdir(src)):
                    shutil.copy(os.path.join(src, name), os.path.join(dest, name))
            for _ in range(2):
                code, out, _ = run(os.path.dirname(os.path.dirname(dest)))
                self.assertEqual(code, 1)
                outputs.add(out)
        self.assertEqual(len(outputs), 1)
        lines = outputs.pop().splitlines()
        self.assertEqual(lines, sorted(lines))
        self.assertEqual(len(lines), len(set(lines)))


class ErrorTests(unittest.TestCase):
    def test_unsupported_yaml_is_refused(self):
        code, out, err = run(os.path.join(FIXTURES, "anchors"))
        self.assertEqual((code, out), (2, ""))
        self.assertIn("a.yml:3: anchors, aliases and tags are not supported", err)

    def test_missing_reusable_workflow(self):
        code, out, err = run(os.path.join(FIXTURES, "missing_call"))
        self.assertEqual((code, out), (2, ""))
        self.assertIn("gone.yml", err)

    def test_not_a_directory(self):
        code, _, err = run(os.path.join(FIXTURES, "no-such-dir"))
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def test_no_workflows(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.assertEqual(run(tmp), (0, "", ""))


if __name__ == "__main__":
    unittest.main()
