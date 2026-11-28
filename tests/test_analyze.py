import os
import shutil
import tempfile
import textwrap
import unittest

from trust_path.analyze import AnalysisError, Repo, shell_sink_variables


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

    def test_env_variable_evaluated_or_written_to_github_env_is_an_entry(self):
        for script in ('eval "$TITLE"', "sh -c \"$TITLE\"", "bash -ec \"${TITLE}\"",
                       'x; eval "echo $TITLE"', 'echo "T=$TITLE" >> "$GITHUB_ENV"',
                       'echo "T=${TITLE}" >> $GITHUB_ENV'):
            recs = analyse(w=self.ENV % ("true", script, ""))
            self.assertEqual([(r[0], r[3], r[4]) for r in recs],
                             [("issues:github.event.issue.title", "second", "secrets.T")], script)
        # A variable set to a fixed value, or echoed, is still data.
        for script in ('eval "$OTHER"', 'echo "$TITLE"', 'echo "T=$OTHER" >> "$GITHUB_ENV"',
                       'evaluate "$TITLE"', 'flash -c "$TITLE"'):
            self.assertEqual(analyse(w=self.ENV % ("true", script, "")), [], script)
        # A continued line is one line.
        self.assertEqual(shell_sink_variables('echo "T=$TITLE" \\\n  >> "$GITHUB_ENV"\necho "$B"'),
                         {"TITLE", "GITHUB_ENV"})

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

    OUTPUTS = """
        on: issues
        permissions: {}
        jobs:
          use:
            needs: [read]
            runs-on: ubuntu-latest
            steps:
              - name: deploy
                run: %s
                env:
                  T: ${{ secrets.T }}%s
          read:
            runs-on: ubuntu-latest
            outputs:
              t: %s
            steps:
              - id: s
                run: %s
                env:
                  TITLE: ${{ github.event.issue.title }}
              - id: fixed
                run: echo "f=1" >> "$GITHUB_OUTPUT"
        """
    TITLE_TO_DEPLOY = [("issues:github.event.issue.title", ".github/workflows/w.yml", "use", "deploy", "secrets.T")]

    def test_job_output_carries_untrusted_text_to_a_later_job(self):
        # The variable is written to GITHUB_OUTPUT; the job output reads that step.
        write = 'echo "t=$TITLE" >> "$GITHUB_OUTPUT"'
        out = "${{ steps.s.outputs.t }}"
        self.assertEqual(analyse(w=self.OUTPUTS % ('echo "${{ needs.read.outputs.t }}"', "", out, write)),
                         self.TITLE_TO_DEPLOY)
        # Through env: data until the script evaluates it.
        env = "\n                  X: ${{ needs.read.outputs.t }}"
        self.assertEqual(analyse(w=self.OUTPUTS % ('eval "$X"', env, out, write)), self.TITLE_TO_DEPLOY)
        self.assertEqual(analyse(w=self.OUTPUTS % ('echo "$X"', env, out, write)), [])
        # A job output set from the untrusted context directly.
        self.assertEqual(analyse(w=self.OUTPUTS % (
            'echo "${{ needs.read.outputs.t }}"', "", "${{ github.event.issue.title }}", "true")),
            self.TITLE_TO_DEPLOY)

    def test_job_output_from_fixed_text_is_not_an_entry(self):
        use = 'echo "${{ needs.read.outputs.t }}"'
        # The step only echoes the variable, or the output reads a step without untrusted input.
        self.assertEqual(analyse(w=self.OUTPUTS % (use, "", "${{ steps.s.outputs.t }}", 'echo "$TITLE"')), [])
        self.assertEqual(analyse(w=self.OUTPUTS % (
            use, "", "${{ steps.fixed.outputs.f }}", 'echo "t=$TITLE" >> "$GITHUB_OUTPUT"')), [])

    def test_job_output_reads_every_source_up_to_its_step(self):
        # An injection in step s reaches every later step, so outputs of s and later steps carry it.
        use = 'echo "${{ needs.read.outputs.t }}"'
        for out in ("${{ steps.s.outputs.t }}", "${{ steps.fixed.outputs.f }}"):
            self.assertEqual(analyse(w=self.OUTPUTS % (use, "", out, "echo ${{ github.event.issue.title }}")),
                             self.TITLE_TO_DEPLOY, out)

    def test_job_outputs_chain_through_jobs(self):
        recs = analyse(w="""
            on: issues
            permissions: {}
            jobs:
              c:
                needs: b
                runs-on: ubuntu-latest
                steps:
                  - run: echo "${{ needs.b.outputs.u }}"
                    env:
                      T: ${{ secrets.T }}
              b:
                needs: [a]
                runs-on: ubuntu-latest
                outputs:
                  u: ${{ needs.a.outputs.t }}
                steps:
                  - run: true
              a:
                runs-on: ubuntu-latest
                outputs:
                  t: ${{ github.event.issue.body }}
                steps:
                  - run: true
            """)
        self.assertEqual(recs, [("issues:github.event.issue.body", ".github/workflows/w.yml", "c", "step 1", "secrets.T")])

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


HEAD_VIA_OUTPUT = """
    on: pull_request_target
    permissions: {}
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
%s
          - uses: actions/checkout@v4
            with:
              ref: ${{ steps.pick.outputs.value }}
          - run: ./mvnw verify
            env:
              TOKEN: ${{ secrets.PAT }}
    """


class HeadThroughStepOutputTests(unittest.TestCase):
    """A checkout ref passed through the output of an earlier step, as in
    spotbugs/sonar-findbugs before December 2024."""

    def records(self, pick):
        return analyse(w=HEAD_VIA_OUTPUT % textwrap.indent(textwrap.dedent(pick), " " * 10))

    def test_action_given_the_pull_request_ref(self):
        recs = self.records("""
            - uses: haya14busa/action-cond@v1
              id: pick
              with:
                cond: ${{ github.event_name == 'pull_request_target' }}
                if_true: refs/pull/${{ github.event.pull_request.number }}/merge
                if_false: ${{ github.ref }}
            """)
        self.assertEqual(recs, [("pull_request_target:checkout of pull request head",
                                 ".github/workflows/w.yml", "build", "step 3", "secrets.PAT")])

    def test_script_writing_the_head_sha_to_github_output(self):
        recs = self.records("""
            - id: pick
              run: echo "value=${{ github.event.pull_request.head.sha }}" >> "$GITHUB_OUTPUT"
            """)
        self.assertEqual(sinks(recs), ["secrets.PAT"])

    def test_script_writing_a_head_variable_from_env(self):
        recs = self.records("""
            - id: pick
              env:
                HEAD: ${{ github.event.pull_request.head.ref }}
              run: |
                echo "picking"
                echo "value=$HEAD" >> $GITHUB_OUTPUT
            """)
        self.assertEqual(sinks(recs), ["secrets.PAT"])

    def test_output_chained_through_two_steps(self):
        recs = self.records("""
            - uses: some/action@v1
              id: first
              with:
                ref: ${{ github.event.pull_request.head.sha }}
            - uses: other/action@v1
              id: pick
              with:
                value: ${{ steps.first.outputs.result }}
            """)
        self.assertEqual(sinks(recs), ["secrets.PAT"])

    def test_output_from_a_base_ref_is_not_head(self):
        recs = self.records("""
            - id: pick
              env:
                HEAD: ${{ github.event.pull_request.head.ref }}
              run: |
                echo "head is $HEAD"
                echo "value=${{ github.base_ref }}" >> $GITHUB_OUTPUT
            """)
        self.assertEqual(recs, [])

    def test_checkout_of_another_steps_output_with_no_head_value(self):
        recs = self.records("""
            - uses: haya14busa/action-cond@v1
              id: pick
              with:
                if_true: main
                if_false: ${{ github.ref }}
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
            "permissions.actions:write", "permissions.checks:write",
            "permissions.contents:write", "permissions.discussions:write",
            "permissions.id-token:write", "permissions.issues:write",
            "permissions.packages:write", "permissions.pull-requests:write",
            "permissions.security-events:write", "permissions.statuses:write"])

    def test_checks_statuses_and_security_events_write(self):
        recs = analyse(w=self.STEP % (
            "permissions: {checks: write, statuses: write, security-events: write, deployments: write}", ""))
        self.assertEqual(sinks(recs), ["permissions.checks:write",
                                       "permissions.security-events:write",
                                       "permissions.statuses:write"])

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

    def test_artifact_of_the_same_run_is_not_upstream(self):
        down = self.DOWNSTREAM.replace(
            "                with:\n                  run-id: ${{ github.event.workflow_run.id }}\n", "")
        self.assertNotIn("run-id", down)
        recs = analyse(up="name: Build\non: pull_request\njobs: {}\n", down=down % "Build")
        self.assertEqual(recs, [])

    def test_other_download_action_is_upstream_without_run_id(self):
        down = self.DOWNSTREAM.replace(
            "actions/download-artifact@v4\n                with:\n"
            "                  run-id: ${{ github.event.workflow_run.id }}",
            "dawidd6/action-download-artifact@v6")
        self.assertIn("dawidd6", down)
        recs = analyse(up="name: Build\non: pull_request\njobs: {}\n", down=down % "Build")
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

SPARSE = """
    on: pull_request_target
    jobs:
      check:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              ref: ${{ github.event.pull_request.head.sha }}
%s
          - run: ./check
            env:
              KEY: ${{ secrets.KEY }}
"""


class SparseCheckoutTests(unittest.TestCase):
    """A head checkout that writes only documents to the workspace runs no pull
    request code; any other sparse checkout still does."""

    def records(self, with_):
        return analyse(w=SPARSE % textwrap.indent(textwrap.dedent(with_).strip("\n"), " " * 14))

    def test_documents_only_is_not_an_entry(self):
        self.assertEqual(self.records("""
            sparse-checkout: README.md
            sparse-checkout-cone-mode: false
            """), [])
        self.assertEqual(self.records("""
            sparse-checkout: |
              README.md
              docs/CHANGES.txt
            sparse-checkout-cone-mode: false
            """), [])

    def test_other_sparse_checkouts_are_entries(self):
        for with_ in ("sparse-checkout: README.md",  # cone mode: top-level files too
                      "sparse-checkout: README.md\nsparse-checkout-cone-mode: true",
                      "sparse-checkout: |\n  README.md\n  check\nsparse-checkout-cone-mode: false",
                      "sparse-checkout: docs\nsparse-checkout-cone-mode: false",
                      "sparse-checkout: '*.md'\nsparse-checkout-cone-mode: false",
                      "sparse-checkout: ../x.md\nsparse-checkout-cone-mode: false"):
            self.assertEqual(sorted(set(r[0] for r in self.records(with_))),
                             ["pull_request_target:checkout of pull request head"], with_)

    def test_documents_only_writer_has_no_cache_path(self):
        writer = (CACHE_WRITER % "org/config/.github/setup@main").replace(
            "/merge\n", "/merge\n              sparse-checkout: README.md\n"
            "              sparse-checkout-cone-mode: false\n")
        self.assertIn("sparse-checkout", writer)
        recs = analyse(bench=writer, release=CACHE_READER % ("push", "org/config/.github/setup@main"))
        self.assertEqual([r for r in recs if ">cache:" in r[0]], [])


if __name__ == "__main__":
    unittest.main()


CACHE_WRITER = """
    on: pull_request_target
    permissions:
      contents: read
    jobs:
      bench:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              ref: refs/pull/${{ github.event.pull_request.number }}/merge
          - uses: %s
          - run: npm run build
"""

CACHE_READER = """
    on:
      %s:
        branches: [main]
    permissions:
      id-token: write
    jobs:
      release:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: %s
          - run: npm publish
"""


class CacheTest(unittest.TestCase):
    """Untrusted pull request code that can save a cache, restored by a later
    default-branch run that holds credentials (the TanStack worm, May 2026)."""

    def cache_records(self, writer_step, reader_step, trigger="push"):
        recs = analyse(bench=CACHE_WRITER % writer_step,
                       release=CACHE_READER % (trigger, reader_step), detail=True)
        return [r for r in recs if ">cache:" in r[0]]

    def test_shared_setup_action_reaches_release_credentials(self):
        recs = self.cache_records("org/config/.github/setup@main",
                                  "org/config/.github/setup@main")
        self.assertEqual(recs, [(
            "pull_request_target@.github/workflows/bench.yml>cache:checkout of pull request head",
            ".github/workflows/release.yml", "release", "org/config/.github/setup@main",
            "permissions.id-token:write", "cache step org/config/.github/setup")])

    def test_actions_cache_and_setup_with_cache_input(self):
        self.assertTrue(self.cache_records("actions/cache@v4", "actions/cache/restore@v4"))
        node = "actions/setup-node@v4\n            with:\n              cache: npm"
        self.assertTrue(self.cache_records(node, node))

    def test_setup_without_cache_input_is_not_a_cache_step(self):
        self.assertEqual(self.cache_records("actions/setup-node@v4", "actions/setup-node@v4"), [])

    def test_different_steps_do_not_share_a_cache(self):
        self.assertEqual(self.cache_records("org/a/setup@main", "org/b/setup@main"), [])

    def test_reader_must_be_a_default_branch_run(self):
        self.assertEqual(self.cache_records("org/config/.github/setup@main",
                                            "org/config/.github/setup@main",
                                            trigger="pull_request"), [])

    def test_no_pull_request_code_no_cache_path(self):
        writer = (CACHE_WRITER % "org/config/.github/setup@main").replace(
            "            with:\n              ref: refs/pull/${{ github.event.pull_request.number }}/merge\n",
            "")
        recs = analyse(bench=writer, release=CACHE_READER % ("push", "org/config/.github/setup@main"))
        self.assertEqual([r for r in recs if ">cache:" in r[0]], [])
