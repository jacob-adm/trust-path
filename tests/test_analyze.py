import os
import shutil
import tempfile
import textwrap
import unittest

from trust_path.analyze import AnalysisError, Repo


def analyse(**workflows):
    """Analyse a repository made of the given name=text workflow files and
    return its records as (source, workflow, job, step, sink) tuples; with
    detail=True, as (source, workflow, job, step, sink, detail) tuples."""
    width = 6 if workflows.pop("detail", False) else 5
    tmp = tempfile.mkdtemp()
    try:
        wdir = os.path.join(tmp, ".github", "workflows")
        os.makedirs(wdir)
        for name, text in workflows.items():
            with open(os.path.join(wdir, name + ".yml"), "w") as f:
                f.write(textwrap.dedent(text))
        return sorted(set(tuple(r)[:width] for r in Repo(tmp).analyse()))
    finally:
        shutil.rmtree(tmp)


def details(recs):
    return sorted(set(r[5] for r in recs))


AGENT = """
    on: issue_comment
    permissions:
      id-token: write
    jobs:
      j:
        runs-on: ubuntu-latest
        steps:
          - uses: %s
            with:
%s
    """


def agent(uses, *inputs):
    lines = "\n".join("              " + line for line in inputs or ("x: y",))
    return details(analyse(w=AGENT % (uses, lines), detail=True))


class AgentDetailTests(unittest.TestCase):
    def test_default_gate_is_write_access(self):
        self.assertEqual(agent("anthropics/claude-code-action@v1"),
                         ["gate=write-access; tools=action-default"])
        self.assertEqual(agent("openai/codex-action@v1"),
                         ["gate=write-access; sandbox=action-default; safety-strategy=drop-sudo"])

    def test_gate_open_to_anyone(self):
        self.assertEqual(agent("anthropics/claude-code-action@v1", 'allowed_non_write_users: "*"'),
                         ["gate=anyone; tools=action-default"])
        self.assertEqual(agent("openai/codex-action@v1", 'allow-users: "*"', "sandbox: read-only"),
                         ["gate=anyone; sandbox=read-only; safety-strategy=drop-sudo"])

    def test_gate_listed_users_and_expression(self):
        self.assertEqual(agent("anthropics/claude-code-action@v1", "allowed_non_write_users: a,b"),
                         ["gate=listed-users; tools=action-default"])
        self.assertEqual(agent("openai/codex-action@v1", "allow-users: ${{ vars.USERS }}"),
                         ["gate=expression; sandbox=action-default; safety-strategy=drop-sudo"])

    def test_gate_of_other_actions(self):
        self.assertEqual(agent("google-github-actions/run-gemini-cli@v0"), ["gate=none"])
        self.assertEqual(agent("actions/ai-inference@v1"), ["gate=none"])
        self.assertEqual(agent("anthropics/claude-code-base-action@v1"),
                         ["gate=none; tools=action-default"])
        self.assertEqual(agent("warpdotdev/oz-agent-action@v1"), ["gate=not-modelled"])

    CONDITION = """
        on: issue_comment
        permissions:
          id-token: write
        jobs:
          j:
            runs-on: ubuntu-latest%s
            steps:
              - uses: google-github-actions/run-gemini-cli@v0%s
        """

    def conditions(self, job="", step=""):
        job = job and "\n            if: " + job
        step = step and "\n                if: " + step
        return details(analyse(w=self.CONDITION % (job, step), detail=True))

    def test_if_conditions_that_test_who_started_the_run(self):
        self.assertEqual(self.conditions(), ["gate=none"])
        self.assertEqual(self.conditions(
            job="contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), "
                "github.event.comment.author_association)"),
            ["gate=none; if=author_association"])
        self.assertEqual(self.conditions(step="${{ github.actor == 'octocat' }}"),
                         ["gate=none; if=actor"])
        self.assertEqual(self.conditions(
            job="github.event.sender.login == 'octocat'",
            step="github.event.comment.author_association == 'OWNER'"),
            ["gate=none; if=actor+author_association"])

    def test_other_if_conditions_are_not_reported(self):
        self.assertEqual(self.conditions(job="github.event_name == 'issue_comment'"),
                         ["gate=none"])
        self.assertEqual(self.conditions(step="contains(github.event.comment.body, '@bot')"),
                         ["gate=none"])

    def test_claude_tool_flags(self):
        self.assertEqual(agent(
            "anthropics/claude-code-action@v1", "claude_args: |",
            "  --permission-mode auto", '  --disallowedTools "WebFetch,Write"',
            "  --allowed-tools=Read", "  --model some-model", "settings: s.json"),
            ["gate=write-access; allowedTools=Read; disallowedTools=WebFetch,Write; "
             "permission-mode=auto; settings=set"])
        self.assertEqual(agent("anthropics/claude-code-action@v1",
                               "claude_args: --dangerously-skip-permissions --max-turns 3"),
                         ["gate=write-access; dangerously-skip-permissions"])

    def test_codex_profile_and_strategy(self):
        self.assertEqual(agent("openai/codex-action@v1", "permission-profile: triage",
                               "safety-strategy: unsafe"),
                         ["gate=write-access; sandbox=action-default; permission-profile=triage; "
                          "safety-strategy=unsafe"])

    def test_other_records_have_no_detail(self):
        recs = analyse(detail=True, w="""
            on: pull_request_target
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ github.event.pull_request.title }}"
                    env:
                      T: ${{ secrets.T }}
            """)
        self.assertEqual(details(recs), ["-"])


def sinks(recs):
    return sorted(set(r[4] for r in recs))


class SourceTests(unittest.TestCase):
    def test_pull_request_fields_only_under_pull_request_target(self):
        wf = """
            on: [%s]
            permissions: {}
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ github.event.pull_request.body }}"
                    env:
                      T: ${{ secrets.T }}
            """
        self.assertEqual(len(analyse(w=wf % "pull_request_target")), 1)
        for trigger in ("pull_request", "pull_request_review", "push", "workflow_dispatch"):
            self.assertEqual(analyse(w=wf % trigger), [], trigger)

    def test_review_body_counts_under_review_trigger(self):
        recs = analyse(w="""
            on: pull_request_review
            permissions: {}
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ github.event.review.body }}"
                    env:
                      T: ${{ secrets.T }}
            """)
        self.assertEqual(recs[0][0], "pull_request_review:github.event.review.body")

    def test_whole_event_and_index_forms(self):
        recs = analyse(w="""
            on: issue_comment
            permissions: {}
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - run: echo '${{ toJSON(github.event) }}' "${{ github['event']['comment']['body'] }}"
                    env:
                      T: ${{ secrets.T }}
            """)
        self.assertEqual(sorted(r[0] for r in recs), [
            "issue_comment:github.event", "issue_comment:github.event.comment.body"])

    def test_string_literal_is_not_a_context(self):
        recs = analyse(w="""
            on: issues
            permissions: {}
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ format('github.event.issue.title') }}"
                    env:
                      T: ${{ secrets.T }}
            """)
        self.assertEqual(recs, [])

    ENV = """
        on: issues
        permissions: {}
        jobs:
          j:
            runs-on: ubuntu-latest
            env:
              TITLE: ${{ github.event.issue.title }}
            steps:
              - name: first
                run: %s
              - name: second
                run: %s
                env:
                  T: ${{ secrets.T }}%s
        """

    def test_env_variable_alone_is_not_an_entry(self):
        # The recommended pattern: the text reaches the script as data.
        self.assertEqual(analyse(w=self.ENV % ("true", 'echo "$TITLE"', "")), [])
        self.assertEqual(analyse(w=self.ENV % (
            "true", 'echo "$BODY"', "\n                  BODY: ${{ github.event.issue.body }}")), [])

    def test_env_expression_is_an_entry_where_it_is_expanded(self):
        recs = analyse(w=self.ENV % ("true", "echo ${{ env.TITLE }}", ""))
        self.assertEqual([(r[0], r[3], r[4]) for r in recs],
                         [("issues:github.event.issue.title", "second", "secrets.T")])
        recs = analyse(w=self.ENV % ("echo ${{ env.title }}", "./x", ""))
        self.assertEqual([(r[0], r[3], r[4]) for r in recs],
                         [("issues:github.event.issue.title", "second", "secrets.T")])

    def test_step_env_expression_and_override(self):
        recs = analyse(w=self.ENV % (
            "true", "echo ${{ env.BODY }}",
            "\n                  BODY: ${{ github.event.issue.body }}"))
        self.assertEqual([(r[0], r[3], r[4]) for r in recs],
                         [("issues:github.event.issue.body", "second", "secrets.T")])
        # A step that sets the variable to a fixed value no longer carries the title.
        self.assertEqual(analyse(w=self.ENV % (
            "true", "echo ${{ env.TITLE }}", "\n                  TITLE: fixed")), [])

    FILES = """
        on: %s
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - id: Changed
                uses: %s
              - name: list
                run: for f in ${{ steps.changed.outputs.%s }}; do echo "$f"; done
                env:
                  T: ${{ secrets.T }}%s
        """

    def test_changed_file_names_are_an_entry(self):
        for action in ("tj-actions/changed-files@v40", "Ana06/get-changed-files@v2",
                       "jitterbit/get-changed-files@v1"):
            recs = analyse(w=self.FILES % ("pull_request_target", action, "all_changed_files", ""))
            self.assertEqual([(r[0], r[3], r[4]) for r in recs], [
                ("pull_request_target:changed file names", "list", "permissions:default"),
                ("pull_request_target:changed file names", "list", "secrets.T")])

    def test_changed_file_counts_and_other_steps_are_not(self):
        for output in ("all_changed_files_count", "any_changed", "only_modified"):
            self.assertEqual(analyse(w=self.FILES % (
                "pull_request_target", "tj-actions/changed-files@v40", output, "")), [])
        self.assertEqual(analyse(w=self.FILES % (
            "pull_request_target", "actions/setup-python@v5", "all_changed_files", "")), [])

    def test_changed_file_names_through_env_are_data(self):
        text = (self.FILES % ("pull_request_target", "tj-actions/changed-files@v40", "x", "")
                ).replace("${{ steps.changed.outputs.x }}", '"$FILES"').replace(
            "T: ${{ secrets.T }}",
            "T: ${{ secrets.T }}\n                  FILES: ${{ steps.changed.outputs.all }}")
        self.assertEqual(analyse(w=text), [])

    def test_secret_before_entry_is_not_reached(self):
        recs = analyse(w="""
            on: pull_request_target
            permissions: {}
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - run: ./setup
                    env:
                      EARLY: ${{ secrets.EARLY }}
                  - run: gh pr checkout ${{ github.event.pull_request.number }}
                  - run: make
                    env:
                      LATE: ${{ secrets.LATE }}
            """)
        self.assertEqual([(r[0], r[4]) for r in recs],
                         [("pull_request_target:fetch of pull request head", "secrets.LATE")])

    def test_other_jobs_are_not_reached(self):
        recs = analyse(w="""
            on: issues
            permissions: {}
            jobs:
              a:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ github.event.issue.title }}"
              b:
                runs-on: ubuntu-latest
                steps:
                  - run: ./x
                    env:
                      T: ${{ secrets.T }}
            """)
        self.assertEqual(recs, [])


class SinkTests(unittest.TestCase):
    STEP = """
            on: issues
            %s
            jobs:
              j:
                runs-on: ubuntu-latest
                %s
                steps:
                  - run: echo "${{ github.event.issue.title }}"
            """

    def test_unset_permissions_are_the_default_token(self):
        self.assertEqual(sinks(analyse(w=self.STEP % ("", ""))), ["permissions:default"])

    def test_empty_and_read_permissions_are_not_sinks(self):
        self.assertEqual(analyse(w=self.STEP % ("permissions: {}", "")), [])
        self.assertEqual(analyse(w=self.STEP % ("permissions: read-all", "")), [])

    def test_job_permissions_replace_workflow_permissions(self):
        recs = analyse(w=self.STEP % ("permissions: write-all", "permissions: {contents: write}"))
        self.assertEqual(sinks(recs), ["permissions.contents:write"])

    def test_write_all(self):
        self.assertEqual(sinks(analyse(w=self.STEP % ("permissions: write-all", ""))), [
            "permissions.actions:write", "permissions.contents:write",
            "permissions.discussions:write", "permissions.id-token:write",
            "permissions.issues:write", "permissions.packages:write",
            "permissions.pull-requests:write"])

    def test_issues_and_discussions_write(self):
        recs = analyse(w=self.STEP % ("permissions: {issues: write, discussions: write}", ""))
        self.assertEqual(sinks(recs), ["permissions.discussions:write",
                                       "permissions.issues:write"])

    def test_environment_mapping(self):
        recs = analyse(w=self.STEP % ("permissions: {}", "environment: {name: prod, url: x}"))
        self.assertEqual(sinks(recs), ["environment:prod"])

    def test_all_secrets(self):
        recs = analyse(w=self.STEP % ("permissions: {}", "env:\n                  S: ${{ toJSON(secrets) }}"))
        self.assertEqual(sinks(recs), ["secrets.*"])

    def test_agent_without_credential_is_not_an_agent_sink(self):
        recs = analyse(w="""
            on: issues
            permissions: {}
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/ai-inference@v1
                    with:
                      prompt: ${{ github.event.issue.body }}
            """)
        self.assertEqual(recs, [])

    def test_agent_with_oidc_token(self):
        recs = analyse(w="""
            on: issue_comment
            permissions:
              id-token: write
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - uses: google-github-actions/run-gemini-cli@v0
            """)
        self.assertEqual(recs, [
            ("issue_comment:event text read by agent", ".github/workflows/w.yml", "j",
             "google-github-actions/run-gemini-cli@v0", "agent:google-github-actions/run-gemini-cli"),
            ("issue_comment:event text read by agent", ".github/workflows/w.yml", "j",
             "google-github-actions/run-gemini-cli@v0", "permissions.id-token:write"),
        ])


class CrossWorkflowTests(unittest.TestCase):
    DOWNSTREAM = """
        on:
          workflow_run:
            workflows: [%s]
        permissions: {}
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
                with:
                  run-id: ${{ github.event.workflow_run.id }}
              - run: ./deploy
                env:
                  KEY: ${{ secrets.KEY }}
        """

    def test_artifact_from_pull_request_run(self):
        recs = analyse(up="name: Build\non: pull_request\njobs: {}\n",
                       down=self.DOWNSTREAM % "Build")
        self.assertEqual([r[0] for r in recs], [
            "pull_request@.github/workflows/up.yml>workflow_run:artifact from upstream run"])

    def test_trusted_upstream(self):
        recs = analyse(up="name: Build\non: push\njobs: {}\n", down=self.DOWNSTREAM % "Build")
        self.assertEqual(recs, [])

    def test_unknown_upstream_is_reported(self):
        recs = analyse(down=self.DOWNSTREAM % "Elsewhere")
        self.assertEqual([r[0] for r in recs],
                         ["unknown@Elsewhere>workflow_run:artifact from upstream run"])

    def test_workflow_run_cycle_terminates(self):
        wf = """
            name: %s
            on:
              workflow_run:
                workflows: [%s]
            permissions: {}
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ github.event.workflow_run.head_branch }}"
                    env:
                      T: ${{ secrets.T }}
            """
        self.assertEqual(analyse(a=wf % ("A", "B"), b=wf % ("B", "A")), [])

    def test_secrets_inherit_and_caller_permissions(self):
        recs = analyse(caller="""
            on: pull_request_target
            jobs:
              call:
                permissions:
                  contents: write
                uses: ./.github/workflows/callee.yml
                secrets: inherit
            """, callee="""
            on: workflow_call
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: refs/pull/${{ github.event.number }}/merge
                  - run: make
                    env:
                      ANY: ${{ secrets.ANY }}
            """)
        self.assertEqual(sorted(set((r[0], r[1], r[4]) for r in recs)), [
            ("pull_request_target@.github/workflows/caller.yml>workflow_call:"
             "checkout of pull request head", ".github/workflows/callee.yml",
             "permissions.contents:write"),
            ("pull_request_target@.github/workflows/caller.yml>workflow_call:"
             "checkout of pull request head", ".github/workflows/callee.yml", "secrets.ANY"),
        ])

    def test_secret_not_passed_is_not_held(self):
        recs = analyse(caller="""
            on: issues
            permissions: {}
            jobs:
              call:
                uses: ./.github/workflows/callee.yml
                with:
                  t: ${{ github.event.issue.title }}
            """, callee="""
            on:
              workflow_call:
                inputs:
                  t:
                    type: string
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ inputs.t }}"
                    env:
                      S: ${{ secrets.S }}
            """)
        self.assertEqual(recs, [])

    def test_remote_reusable_workflow(self):
        recs = analyse(caller="""
            on: issues
            jobs:
              call:
                permissions: {}
                uses: example/shared/.github/workflows/x.yml@v1
                with:
                  title: ${{ github.event.issue.title }}
                secrets:
                  token: ${{ secrets.TOKEN }}
            """)
        self.assertEqual(recs, [(
            "issues:with.title", ".github/workflows/caller.yml", "call",
            "example/shared/.github/workflows/x.yml@v1", "secrets.TOKEN")])


def refused(**workflows):
    """The (file, reason) pairs Repo refuses among the given workflows."""
    tmp = tempfile.mkdtemp()
    try:
        wdir = os.path.join(tmp, ".github", "workflows")
        os.makedirs(wdir)
        for name, text in workflows.items():
            with open(os.path.join(wdir, name + ".yml"), "w") as f:
                f.write(textwrap.dedent(text))
        return Repo(tmp).refused
    finally:
        shutil.rmtree(tmp)


class ErrorTests(unittest.TestCase):
    def test_not_a_directory(self):
        with self.assertRaises(AnalysisError):
            Repo(os.path.join(os.path.dirname(__file__), "no-such-dir"))

    def test_not_a_workflow(self):
        self.assertEqual(refused(w="on: push\n"),
                         [(".github/workflows/w.yml", "not a workflow (no 'jobs' mapping)")])

    def test_yaml_error_names_file_and_line(self):
        self.assertEqual(refused(w="on: push\njobs:\n  a: !!map {}\n"), [(
            ".github/workflows/w.yml", "line 3: tags are not supported")])

    def test_readable_files_are_still_analysed(self):
        good = """
            on: issues
            jobs:
              a:
                steps:
                  - run: echo "${{ github.event.issue.title }}" ${{ secrets.T }}
        """
        recs = analyse(bad="on: [\n", good=good)
        self.assertEqual(sinks(recs), ["permissions:default", "secrets.T"])

    def test_malformed_jobs_and_steps_are_refused(self):
        self.assertEqual(refused(j="on: push\njobs:\n  a: x\n",
                                 s="on: push\njobs:\n  a:\n    steps: x\n"), [
            (".github/workflows/j.yml", "job 'a' is not a mapping"),
            (".github/workflows/s.yml", "steps of job 'a' are not a list")])

    def test_missing_call_is_named_and_the_callers_other_jobs_still_analysed(self):
        call = """
            on: issues
            jobs:
              b:
                uses: ./.github/workflows/lost.yml
              c:
                uses: ./.github/workflows/gone.yml
              d:
                steps:
                  - run: echo "${{ github.event.issue.body }}"
        """
        self.assertEqual(refused(call=call, ok="on: push\njobs: {}\n"), [
            (".github/workflows/call.yml",
             "job 'b' calls ./.github/workflows/lost.yml, which is not in .github/workflows"),
            (".github/workflows/call.yml",
             "job 'c' calls ./.github/workflows/gone.yml, which is not in .github/workflows")])
        self.assertEqual(sinks(analyse(call=call)), ["permissions:default"])

    def test_call_into_refused_workflow_is_skipped(self):
        call = """
            on: issues
            jobs:
              c:
                uses: ./.github/workflows/bad.yml
              d:
                steps:
                  - run: echo "${{ github.event.issue.body }}"
        """
        self.assertEqual(sinks(analyse(call=call, bad="on: [\n")), ["permissions:default"])

if __name__ == "__main__":
    unittest.main()
