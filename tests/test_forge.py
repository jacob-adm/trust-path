"""Gitea and Forgejo Actions: where each forge reads workflows, its context and
token names, and the events it does not have."""
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from trust_path.analyze import AnalysisError, Repo

# A pull request body reaching a secret: one path wherever it is analysed.
INJECT = """
    on: pull_request_target
    permissions: {}
    jobs:
      j:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{ %s.event.pull_request.body }}"
            env:
              T: ${{ secrets.T }}
    """
CLEAN = """
    on: push
    permissions: {}
    jobs:
      j:
        runs-on: ubuntu-latest
        steps:
          - run: echo hello
    """


def analyse(forge, files):
    """Records as (source, workflow) pairs for a repository of the given
    path=text files, analysed with the forge's rules."""
    tmp = tempfile.mkdtemp()
    try:
        for rel, text in files.items():
            path = os.path.join(tmp, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(textwrap.dedent(text))
        return sorted(set((r[0], r[1]) for r in Repo(tmp, forge=forge).analyse()))
    finally:
        shutil.rmtree(tmp)


class ContextTests(unittest.TestCase):
    def test_forge_context_names_read_as_github(self):
        for name in ("gitea", "forgejo", "forge"):
            with self.subTest(name):
                recs = analyse("github", {".github/workflows/w.yml": INJECT % name})
                self.assertEqual(recs, [("pull_request_target:github.event.pull_request.body",
                                         ".github/workflows/w.yml")])

    def test_forge_token_secrets_reach_a_called_workflow(self):
        # The automatic token reaches a called workflow without being passed, under each name.
        for token in ("GITHUB_TOKEN", "GITEA_TOKEN", "FORGEJO_TOKEN"):
            with self.subTest(token):
                recs = analyse("gitea", {
                    ".gitea/workflows/caller.yml": """
                        on: pull_request_target
                        jobs:
                          call:
                            uses: ./.gitea/workflows/called.yml
                        """,
                    ".gitea/workflows/called.yml": """
                        on: workflow_call
                        permissions: {}
                        jobs:
                          j:
                            runs-on: ubuntu-latest
                            steps:
                              - run: echo "${{ github.event.pull_request.title }}"
                                env:
                                  T: ${{ secrets.%s }}
                        """ % token})
                self.assertEqual(len(recs), 1, recs)


class DirectoryTests(unittest.TestCase):
    def test_the_first_existing_directory_is_used(self):
        files = {".forgejo/workflows/f.yml": INJECT % "github",
                 ".gitea/workflows/g.yml": INJECT % "github",
                 ".github/workflows/h.yml": INJECT % "github"}
        self.assertEqual([r[1] for r in analyse("github", files)], [".github/workflows/h.yml"])
        self.assertEqual([r[1] for r in analyse("gitea", files)], [".gitea/workflows/g.yml"])
        self.assertEqual([r[1] for r in analyse("forgejo", files)], [".forgejo/workflows/f.yml"])

    def test_an_existing_directory_hides_the_next_even_without_findings(self):
        files = {".gitea/workflows/clean.yml": CLEAN, ".github/workflows/h.yml": INJECT % "github"}
        self.assertEqual(analyse("gitea", files), [])
        self.assertEqual(len(analyse("github", files)), 1)

    def test_falls_back_to_github_workflows(self):
        files = {".github/workflows/h.yml": INJECT % "gitea"}
        self.assertEqual([r[1] for r in analyse("gitea", files)], [".github/workflows/h.yml"])
        self.assertEqual([r[1] for r in analyse("forgejo", files)], [".github/workflows/h.yml"])

    def test_gitea_and_forgejo_read_subdirectories_github_does_not(self):
        self.assertEqual([r[1] for r in analyse("gitea", {
            ".gitea/workflows/sub/w.yml": INJECT % "gitea"})], [".gitea/workflows/sub/w.yml"])
        self.assertEqual([r[1] for r in analyse("forgejo", {
            ".forgejo/workflows/a/b.yaml": INJECT % "forgejo"})], [".forgejo/workflows/a/b.yaml"])
        self.assertEqual(analyse("github", {".github/workflows/sub/w.yml": INJECT % "github"}), [])

    def test_unknown_forge_is_an_error(self):
        with self.assertRaises(AnalysisError):
            Repo(tempfile.gettempdir(), forge="gitlab")


class GitRefTests(unittest.TestCase):
    """With --ref the same rules apply to the tree at the ref."""

    def test_ref_uses_the_forge_directories(self):
        tmp = tempfile.mkdtemp()
        try:
            for rel, text in ((".gitea/workflows/sub/w.yml", INJECT % "gitea"),
                              (".github/workflows/h.yml", INJECT % "github")):
                path = os.path.join(tmp, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(textwrap.dedent(text))
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
            for args in (["init", "-q"], ["add", "."],
                         ["-c", "user.name=t", "-c", "user.email=t@example.invalid",
                          "commit", "-q", "-m", "w"]):
                subprocess.run(["git"] + args, cwd=tmp, env=env, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            got = lambda forge: sorted(set(r[1] for r in Repo(tmp, "HEAD", forge).analyse()))
            self.assertEqual(got("gitea"), [".gitea/workflows/sub/w.yml"])
            self.assertEqual(got("forgejo"), [".gitea/workflows/sub/w.yml"])
            self.assertEqual(got("github"), [".github/workflows/h.yml"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class EventTests(unittest.TestCase):
    CHAIN = {
        "build.yml": """
            name: build
            on: pull_request
            jobs:
              b:
                runs-on: ubuntu-latest
                steps:
                  - run: make
            """,
        "after.yml": """
            on:
              workflow_run:
                workflows: [build]
                types: [completed]
            permissions: {}
            jobs:
              a:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ github.event.workflow_run.head_branch }}"
                    env:
                      T: ${{ secrets.T }}
            """,
    }

    def test_forgejo_has_no_workflow_run(self):
        for forge, wdir, want in (("github", ".github/workflows", 1),
                                  ("gitea", ".gitea/workflows", 1),
                                  ("forgejo", ".forgejo/workflows", 0)):
            with self.subTest(forge):
                files = dict((wdir + "/" + n, t) for n, t in self.CHAIN.items())
                self.assertEqual(len(analyse(forge, files)), want)


if __name__ == "__main__":
    unittest.main()
