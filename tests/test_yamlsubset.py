import textwrap
import unittest

from trust_path.yamlsubset import YamlError, load


def y(text):
    return load(textwrap.dedent(text))


class SupportedTests(unittest.TestCase):
    def test_workflow_shape(self):
        doc = y("""
            # comment
            name: ci
            on:
              push:
              pull_request:
                branches: [main, "release/*"]
            jobs:
              test:
                runs-on: ${{ matrix.os }}   # trailing comment
                steps:
                - uses: actions/checkout@v4
                - name: Run
                  run: echo "a: b" # not part of the value
                  env: {A: '1', B: "x#y"}
            """)
        self.assertEqual(doc, {
            "name": "ci",
            "on": {"push": None, "pull_request": {"branches": ["main", "release/*"]}},
            "jobs": {"test": {
                "runs-on": "${{ matrix.os }}",
                "steps": [{"uses": "actions/checkout@v4"},
                          {"name": "Run", "run": 'echo "a: b"', "env": {"A": "1", "B": "x#y"}}],
            }},
        })

    def test_scalars_stay_strings(self):
        self.assertEqual(y("a: 3.10\nb: true\nc: ~\nd:\ne: 'on'\n"),
                         {"a": "3.10", "b": "true", "c": None, "d": None, "e": "on"})

    def test_literal_and_folded_blocks(self):
        doc = y("""
            lit: |
              one
                two

              # not a comment
            strip: |-
              x
            fold: >
              a
              b

              c
            next: 1
            """)
        self.assertEqual(doc["lit"], "one\n  two\n\n# not a comment\n")
        self.assertEqual(doc["strip"], "x")
        self.assertEqual(doc["fold"], "a b\nc\n")
        self.assertEqual(doc["next"], "1")

    def test_multi_line_plain_and_quoted(self):
        doc = y("""
            if: github.event_name == 'push' &&
              github.ref == 'refs/heads/main'
            q: "one
              two \\u00e9\\t"
            s: 'it''s'
            """)
        self.assertEqual(doc["if"], "github.event_name == 'push' && github.ref == 'refs/heads/main'")
        self.assertEqual(doc["q"], "one two \u00e9\t")
        self.assertEqual(doc["s"], "it's")

    def test_nested_sequences_and_multi_line_flow(self):
        doc = y("""
            m:
              - - a
                - b
              - [c, {d: e,
                  f: [g]}]
            """)
        self.assertEqual(doc, {"m": [["a", "b"], ["c", {"d": "e", "f": ["g"]}]]})

    def test_document_markers(self):
        self.assertEqual(y("---\na: 1\n...\n"), {"a": "1"})


class RefusedTests(unittest.TestCase):
    def refused(self, text, line, message):
        with self.assertRaises(YamlError) as cm:
            y(text)
        self.assertEqual((cm.exception.line, cm.exception.message), (line, message))

    def test_anchor_alias_tag(self):
        msg = "anchors, aliases and tags are not supported"
        self.refused("a: &x 1\n", 1, msg)
        self.refused("a: 1\nb: *x\n", 2, msg)
        self.refused("a: !!str 1\n", 1, msg)
        self.refused("a:\n  - *x\n", 2, msg)

    def test_other_constructs(self):
        self.refused("a: 1\n<<: {b: 2}\n", 2, "merge keys are not supported")
        self.refused("? a\n: 1\n", 1, "complex mapping keys are not supported")
        self.refused("%YAML 1.2\n---\na: 1\n", 1, "directives are not supported")
        self.refused("a: 1\n---\nb: 2\n", 2, "several documents in one file are not supported")
        self.refused("a:\n\tb: 1\n", 2, "tabs in indentation are not supported")
        self.refused("a: 1\na: 2\n", 2, "duplicate key 'a'")
        self.refused("a: |2\n  x\n", 1, "block scalar header '|2' is not supported")

    def test_deep_nesting(self):
        self.refused("a: " + "[" * 3000 + "]" * 3000 + "\n", 1, "nesting is too deep")
        deep = "".join(" " * n + "k%d:\n" % n for n in range(1500))
        with self.assertRaises(YamlError) as cm:
            load(deep)
        self.assertEqual(cm.exception.message, "nesting is too deep")

    def test_malformed(self):
        self.refused("a: [1, 2\n", 1, "unterminated flow collection")
        self.refused("a: 'x\n", 1, "unterminated quoted string")
        self.refused("a: 1\n   b: 2\n", 2, "unexpected indentation")


if __name__ == "__main__":
    unittest.main()
