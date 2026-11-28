import json
import os
import shutil
import stat
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
            ".github/workflows/greet.yml", "greet", "Post greeting", "secrets.BOT_TOKEN", "-")])

    def test_head_checkout_reaches_later_secret(self):
        code, recs, _ = records("head_checkout")
        self.assertEqual(code, 1)
        self.assertEqual(recs, [(
            "pull_request_target:checkout of pull request head",
            ".github/workflows/build.yml", "build", "Install", "secrets.NPM_TOKEN", "-")])

    def test_workflow_run_chain_reaches_publish_job(self):
        code, recs, _ = records("workflow_run_chain")
        self.assertEqual(code, 1)
        source = ("pull_request@.github/workflows/ci.yml>workflow_run@.github/workflows/stage.yml"
                  ">workflow_run:github.event.workflow_run.head_branch")
        self.assertEqual(recs, [
            (source, ".github/workflows/publish.yml", "publish", "Tag", "environment:pypi", "-"),
            (source, ".github/workflows/publish.yml", "publish", "Tag",
             "permissions.id-token:write", "-"),
        ])

    def test_agent_given_issue_body_with_api_key(self):
        code, recs, _ = records("agent")
        self.assertEqual(code, 1)
        step = "anthropics/claude-code-action@v1"
        wf = ".github/workflows/triage.yml"
        agent = "gate=anyone; tools=action-default"
        self.assertEqual(recs, [
            ("issues:event text read by agent", wf, "triage", step,
             "agent:anthropics/claude-code-action", agent),
            ("issues:event text read by agent", wf, "triage", step, "permissions.issues:write",
             agent),
            ("issues:event text read by agent", wf, "triage", step, "secrets.ANTHROPIC_API_KEY",
             agent),
            ("issues:event text read by agent", wf, "triage", step, "secrets.GITHUB_TOKEN",
             agent),
            ("issues:github.event.issue.body", wf, "triage", step,
             "agent:anthropics/claude-code-action", agent),
            ("issues:github.event.issue.body", wf, "triage", step, "permissions.issues:write", "-"),
            ("issues:github.event.issue.body", wf, "triage", step, "secrets.ANTHROPIC_API_KEY",
             "-"),
            ("issues:github.event.issue.body", wf, "triage", step, "secrets.GITHUB_TOKEN", "-"),
        ])

    def test_reusable_workflow_input(self):
        code, recs, _ = records("reusable")
        self.assertEqual(code, 1)
        source = "issue_comment@.github/workflows/on-comment.yml>workflow_call:inputs.text"
        wf = ".github/workflows/reply.yml"
        self.assertEqual(recs, [
            (source, wf, "reply", "Reply", "permissions.pull-requests:write", "-"),
            (source, wf, "reply", "Reply", "secrets.token", "-"),
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
        self.assertEqual([tuple(r[k] for k in ("source", "workflow", "job", "step", "sink", "detail"))
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


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        _, out, _ = run("--json", os.path.join(FIXTURES, "agent"))
        self.records = json.loads(out)

    def baseline(self, doc):
        path = os.path.join(self.tmp, "baseline.json")
        with open(path, "w") as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))
        return path

    def test_all_records_in_baseline_exit_zero(self):
        path = self.baseline(self.records)
        self.assertEqual(run("--baseline", path, os.path.join(FIXTURES, "agent")), (0, "", ""))
        code, out, _ = run("--audit-json", "--baseline", path, os.path.join(FIXTURES, "agent"))
        self.assertEqual((code, json.loads(out)["findings"]), (0, []))

    def test_record_not_in_baseline_is_reported(self):
        kept, rest = self.records[0], self.records[1:]
        code, out, _ = run("--json", "--baseline", self.baseline(rest),
                           os.path.join(FIXTURES, "agent"))
        self.assertEqual((code, json.loads(out)), (1, [kept]))

    def test_changed_field_is_reported_again(self):
        changed = [dict(r, detail=r["detail"] + "x") for r in self.records]
        code, out, _ = run("--json", "--baseline", self.baseline(changed),
                           os.path.join(FIXTURES, "agent"))
        self.assertEqual((code, json.loads(out)), (1, self.records))

    def test_unreadable_baseline_is_an_error(self):
        for doc in ("not json", '{"a": 1}', "[1]"):
            code, out, err = run("--baseline", self.baseline(doc), os.path.join(FIXTURES, "agent"))
            self.assertEqual((code, out), (2, ""), doc)
            self.assertIn("--baseline", err)
        code, _, err = run("--baseline", os.path.join(self.tmp, "missing.json"),
                           os.path.join(FIXTURES, "agent"))
        self.assertEqual(code, 2)


class ErrorTests(unittest.TestCase):
    def test_unsupported_yaml_is_refused(self):
        code, out, err = run(os.path.join(FIXTURES, "tags"))
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(err, "trust-path: .github/workflows/a.yml: line 3: tags are not supported\n")

    def test_missing_reusable_workflow(self):
        code, out, err = run(os.path.join(FIXTURES, "missing_call"))
        self.assertEqual((code, out), (2, ""))
        self.assertIn("gone.yml", err)

    def test_refused_file_does_not_hide_other_paths(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copytree(os.path.join(FIXTURES, "pr_title", ".github"), os.path.join(tmp, ".github"))
        wdir = os.path.join(tmp, ".github", "workflows")
        for name, text in (("a.yml", "x: !!str 1\n"), ("b.yml", "on: push\n")):
            with open(os.path.join(wdir, name), "w") as f:
                f.write(text)
        code, out, err = run(tmp)
        self.assertEqual(code, 2)
        self.assertEqual(out, run(os.path.join(FIXTURES, "pr_title"))[1])
        self.assertTrue(out)
        self.assertEqual(err.splitlines(), [
            "trust-path: .github/workflows/a.yml: line 1: tags are not supported",
            "trust-path: .github/workflows/b.yml: not a workflow (no 'jobs' mapping)"])
        code, out, _ = run("--json", tmp)
        self.assertEqual(code, 2)
        self.assertEqual(len(json.loads(out)), 1)

    def test_not_a_directory(self):
        code, _, err = run(os.path.join(FIXTURES, "no-such-dir"))
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def test_no_workflows(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.assertEqual(run(tmp), (0, "", ""))


def git(repo, *args):
    """Run git in a scratch repository, ignoring the user's configuration and hooks."""
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, LC_ALL="C")
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"] + list(args),
                   cwd=repo, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def remove_tree(path):
    """shutil.rmtree that also removes read-only files (git objects on Windows)."""
    def retry(func, name, _exc):
        os.chmod(name, stat.S_IWRITE)
        func(name)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry)
    else:
        shutil.rmtree(path, onerror=retry)


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class RefTests(unittest.TestCase):
    CALLER = ("on: pull_request_target\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"
              "    with:\n      t: ${{ github.event.pull_request.title }}\n"
              "    secrets: inherit\n")
    CALLED = ("on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  d:\n"
              "    permissions: {}\n    steps:\n      - run: echo \"${{ inputs.t }}\" %s\n")

    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self.addCleanup(remove_tree, self.repo)
        git(self.repo, "init", "-q")
        self.write("caller.yml", self.CALLER)
        self.write("called.yml", self.CALLED % "${{ secrets.OLD }}")
        git(self.repo, "add", ".github")
        git(self.repo, "commit", "-q", "-m", "one")
        git(self.repo, "tag", "one")
        self.write("called.yml", self.CALLED % "${{ secrets.NEW }}")
        git(self.repo, "commit", "-q", "-am", "two")
        # The working tree differs from both commits.
        self.write("called.yml", self.CALLED % "${{ secrets.WORKTREE }}")

    def write(self, name, text):
        wdir = os.path.join(self.repo, ".github", "workflows")
        if not os.path.isdir(wdir):
            os.makedirs(wdir)
        with open(os.path.join(wdir, name), "w") as f:
            f.write(text)

    def sinks(self, *args):
        code, out, err = run(*args)
        self.assertEqual((code, err), (1, ""))
        return sorted(set(line.split("\t")[4] for line in out.splitlines()))

    def test_reads_workflows_and_called_workflows_at_ref(self):
        self.assertEqual(self.sinks("--ref", "one", self.repo), ["secrets.OLD"])
        self.assertEqual(self.sinks("--ref", "HEAD", self.repo), ["secrets.NEW"])
        self.assertEqual(self.sinks(self.repo), ["secrets.WORKTREE"])

    def test_does_not_check_out(self):
        run("--ref", "one", self.repo)
        with open(os.path.join(self.repo, ".github", "workflows", "called.yml")) as f:
            self.assertIn("WORKTREE", f.read())

    def test_dir_defaults_to_current_directory(self):
        env = dict(os.environ, PYTHONPATH=ROOT)
        p = subprocess.run([sys.executable, "-m", "trust_path", "--ref", "one"], cwd=self.repo,
                           env=env, stdout=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn("secrets.OLD", p.stdout)

    def test_unknown_ref(self):
        code, out, err = run("--ref", "no-such-ref", self.repo)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("unknown ref no-such-ref", err)
        code, _, err = run("--ref=--output=x", self.repo)
        self.assertEqual(code, 2)
        self.assertIn("unknown ref", err)

    def test_not_a_repository(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        code, out, err = run("--ref", "HEAD", tmp)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("not a git repository", err)

    def test_dir_is_required_without_ref(self):
        self.assertEqual(run()[0], 2)

    @unittest.skipIf(os.name == "nt", "symbolic links need privileges on Windows")
    def test_symbolic_link_at_ref_is_refused(self):
        os.symlink("caller.yml", os.path.join(self.repo, ".github", "workflows", "link.yml"))
        git(self.repo, "add", ".github")
        git(self.repo, "commit", "-q", "-m", "three")
        code, _, err = run("--ref", "HEAD", self.repo)
        self.assertEqual(code, 2)
        self.assertEqual(err, "trust-path: .github/workflows/link.yml: a symbolic link, not read\n")


if __name__ == "__main__":
    unittest.main()
