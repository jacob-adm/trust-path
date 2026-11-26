"""trust-path --audit-json: one audit result object built from the --json records."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from trust_path import __version__, audit
from tests.test_cli import FIXTURES, ROOT, remove_tree, run

TOP = {"format", "tool", "target", "exit", "findings", "errors"}
FINDING = {"rule", "severity", "message", "evidence", "record"}


def audit_run(test, *args):
    code, out, err = run("--audit-json", *args)
    doc = json.loads(out)
    test.assertEqual(set(doc), TOP)
    test.assertEqual(doc["format"], "audit-result/1")
    test.assertEqual(doc["tool"], {"name": "trust-path", "version": __version__})
    test.assertEqual(doc["target"]["kind"], "repository")
    for f in doc["findings"]:
        test.assertEqual(set(f), FINDING)
        test.assertRegex(f["rule"], r"\Atrust-path\.[a-z-]+\Z")
        test.assertIn(f["severity"], ("high", "medium"))
        test.assertEqual(f["evidence"]["path"], f["record"]["workflow"])
    want = 2 if doc["errors"] else (1 if doc["findings"] else 0)
    test.assertEqual((doc["exit"], code), (want, want))
    return doc, err


class FixtureTests(unittest.TestCase):
    def test_records_match_json_for_every_fixture(self):
        for name in sorted(os.listdir(FIXTURES)):
            path = os.path.join(FIXTURES, name)
            with self.subTest(name):
                jcode, jout, jerr = run("--json", path)
                doc, err = audit_run(self, path)
                self.assertEqual([f["record"] for f in doc["findings"]], json.loads(jout))
                self.assertEqual((doc["exit"], err), (jcode, jerr))

    def test_default_and_json_output_unchanged(self):
        path = os.path.join(FIXTURES, "pr_title")
        self.assertEqual(run(path), (1, "pull_request_target:github.event.pull_request.title\t"
                                        ".github/workflows/greet.yml\tgreet\tPost greeting\t"
                                        "secrets.BOT_TOKEN\t-\n", ""))
        code, out, _ = run("--json", path)
        self.assertEqual(code, 1)
        self.assertNotIn("severity", out)

    def test_pr_title(self):
        doc, _ = audit_run(self, os.path.join(FIXTURES, "pr_title"))
        self.assertEqual(doc["target"], {"kind": "repository", "name": "pr_title"})
        self.assertEqual([(f["rule"], f["severity"], f["message"], f["evidence"])
                          for f in doc["findings"]], [(
            "trust-path.secret", "high",
            "Untrusted input from pull_request_target, entering as "
            "github.event.pull_request.title, reaches the secret BOT_TOKEN in "
            ".github/workflows/greet.yml, job greet, step Post greeting",
            {"path": ".github/workflows/greet.yml"})])

    def test_chain(self):
        doc, _ = audit_run(self, os.path.join(FIXTURES, "workflow_run_chain"))
        self.assertEqual([(f["rule"], f["severity"]) for f in doc["findings"]],
                         [("trust-path.environment", "medium"), ("trust-path.oidc-token", "high")])
        self.assertTrue(doc["findings"][0]["message"].startswith(
            "Untrusted input from pull_request in .github/workflows/ci.yml, then workflow_run "
            "in .github/workflows/stage.yml, then workflow_run, entering as "
            "github.event.workflow_run.head_branch, reaches the environment pypi in "))

    def test_agent_detail_in_message(self):
        doc, _ = audit_run(self, os.path.join(FIXTURES, "agent"))
        agent = [f for f in doc["findings"] if f["rule"] == "trust-path.agent"]
        self.assertTrue(agent)
        self.assertTrue(agent[0]["message"].endswith("(gate=anyone; tools=action-default)"))

    def test_nothing_found(self):
        doc, err = audit_run(self, os.path.join(FIXTURES, "safe"))
        self.assertEqual((doc["findings"], doc["errors"], err), ([], [], ""))

    def test_refused_file_is_an_error_with_its_path(self):
        doc, err = audit_run(self, os.path.join(FIXTURES, "tags"))
        self.assertEqual(doc["errors"], [{"message": ".github/workflows/a.yml: line 3: tags are "
                                                     "not supported",
                                          "path": ".github/workflows/a.yml"}])
        self.assertIn("tags are not supported", err)

    def test_not_a_directory(self):
        doc, err = audit_run(self, os.path.join(FIXTURES, "nope"))
        self.assertEqual(doc["findings"], [])
        self.assertEqual(len(doc["errors"]), 1)
        self.assertIn("not a directory", doc["errors"][0]["message"])
        self.assertIn("not a directory", err)

    def test_usage_errors_still_write_the_object(self):
        for args, text in ((("--json",), "not allowed with argument"),
                           ((), "DIR is required without --ref"),
                           (("--bogus", "."), "unrecognized arguments: --bogus")):
            with self.subTest(args):
                doc, err = audit_run(self, *args)
                self.assertEqual(doc["findings"], [])
                self.assertIn(text, doc["errors"][0]["message"])
                self.assertIn("usage: trust-path", err)

    def test_usage_error_without_the_flag_is_unchanged(self):
        code, out, err = run("--bogus", ".")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("unrecognized arguments: --bogus", err)


class RefTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="trust-path-audit-")
        self.addCleanup(remove_tree, self.dir)
        shutil.copytree(os.path.join(FIXTURES, "pr_title", ".github"),
                        os.path.join(self.dir, ".github"))
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        for cmd in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "x"]):
            subprocess.run(["git", "-C", self.dir] + cmd, check=True, env=env)
        self.commit = subprocess.run(["git", "-C", self.dir, "rev-parse", "HEAD"], check=True,
                                     stdout=subprocess.PIPE, universal_newlines=True
                                     ).stdout.strip()

    def test_ref_and_commit_in_evidence(self):
        doc, _ = audit_run(self, "--ref", "HEAD", self.dir)
        self.assertEqual(doc["target"], {"kind": "repository", "ref": "HEAD",
                                         "name": os.path.basename(self.dir)})
        self.assertEqual(doc["findings"][0]["evidence"],
                         {"path": ".github/workflows/greet.yml", "ref": "HEAD",
                          "commit": self.commit})

    def test_unknown_ref(self):
        doc, err = audit_run(self, "--ref", "nope", self.dir)
        self.assertEqual(doc["errors"], [{"message": "unknown ref nope"}])
        self.assertEqual(doc["target"]["ref"], "nope")
        self.assertEqual(err, "trust-path: unknown ref nope\n")


class ClassifyTests(unittest.TestCase):
    def test_every_sink_kind(self):
        cases = {
            "secrets.NPM_TOKEN": ("secret", "the secret NPM_TOKEN"),
            "secrets:inherit": ("secrets-inherit",
                                "every secret of the caller (secrets: inherit)"),
            "permissions.contents:write": ("write-permission", "write permission on contents"),
            "permissions.id-token:write": ("oidc-token", "an OIDC token (id-token: write)"),
            "permissions:default": ("default-permissions",
                                    "the GITHUB_TOKEN with the repository's default "
                                    "permissions"),
            "environment:pypi": ("environment", "the environment pypi"),
            "agent:openai/codex-action": ("agent", "the AI agent action openai/codex-action"),
        }
        for sink, want in cases.items():
            with self.subTest(sink):
                self.assertEqual(audit.classify(sink), want)
                self.assertIn(want[0], audit.RULES)


class DocsTests(unittest.TestCase):
    def test_documented_example_is_real_output(self):
        code, out, _ = run("--audit-json", os.path.join(FIXTURES, "pr_title"))
        got = json.loads(out)
        with open(os.path.join(ROOT, "docs", "commands.md"), encoding="utf-8") as handle:
            text = handle.read()
        block = text.split("## Audit result output", 1)[1].split("```json\n", 1)[1]
        documented = json.loads(block.split("```", 1)[0])
        # The page shows the version the flag ships in; the rest must match exactly.
        documented["tool"]["version"] = got["tool"]["version"]
        self.assertEqual(documented, got)


if __name__ == "__main__":
    unittest.main()
