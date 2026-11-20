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

    def test_tab_after_indentation_is_text(self):
        self.assertEqual(load("a: |\n  x\n  \ty\nb: 1\n"), {"a": "x\n\ty\n", "b": "1"})
        self.assertEqual(load("a: \"x\n\t y\"\n"), {"a": "x y"})

    def test_document_markers(self):
        self.assertEqual(y("---\na: 1\n...\n"), {"a": "1"})

    def test_encodings_and_line_ends(self):
        self.assertEqual(load("\ufeffa: b\n"), {"a": "b"})
        self.assertEqual(load("a: |\r\n  x\r\n  y\r\nb: c\r\n"), {"a": "x\ny\n", "b": "c"})
        self.assertEqual(load("a: b\rc: d\r"), {"a": "b", "c": "d"})
        self.assertEqual(load("\u043a\u043b\u044e\u0447: \u5024\n\"\u00e9\": ok\n"),
                         {"\u043a\u043b\u044e\u0447": "\u5024", "\u00e9": "ok"})

    def test_long_line(self):
        self.assertEqual(load("a: " + "x" * 1000000 + "\n"), {"a": "x" * 1000000})

    def test_block_scalar_indentation(self):
        self.assertEqual(y("a: >\n  x\n    y\n  z\n"), {"a": "x\n  y\nz\n"})
        self.assertEqual(y("a: |\n\n  x\n"), {"a": "\nx\n"})
        self.assertEqual(y("a:\n  - |\n      x\n       y\n"), {"a": ["x\n y\n"]})


class AnchorTests(unittest.TestCase):
    def test_scalar(self):
        self.assertEqual(load("a: &x 1\nb: *x\n"), {"a": "1", "b": "1"})
        self.assertEqual(load("- &x a\n- *x # again\n"), ["a", "a"])
        self.assertEqual(load("a: &x |\n  hi\nb: *x\n"), {"a": "hi\n", "b": "hi\n"})

    def test_mapping_and_sequence_values(self):
        self.assertEqual(load("a: &x\n  b: c\nd: *x\n"), {"a": {"b": "c"}, "d": {"b": "c"}})
        self.assertEqual(load("a: &x # note\n  b: c\nd: *x\n"), {"a": {"b": "c"}, "d": {"b": "c"}})
        self.assertEqual(load("a: &x\n- 1\n- 2\nb: *x\n"), {"a": ["1", "2"], "b": ["1", "2"]})
        self.assertEqual(load("a: &x [1, 2]\nb: *x\n"), {"a": ["1", "2"], "b": ["1", "2"]})

    def test_reused_step(self):
        step = {"uses": "actions/checkout@v4", "with": {"ref": "main"}}
        self.assertEqual(load(textwrap.dedent("""\
            first:
              - &checkout
                uses: actions/checkout@v4
                with:
                  ref: main
              - run: make
            second:
              - *checkout
            """)), {"first": [step, {"run": "make"}], "second": [step]})

    def test_anchor_can_be_redefined(self):
        self.assertEqual(load("a: &x 1\nb: *x\nc: &x 2\nd: *x\n"),
                         {"a": "1", "b": "1", "c": "2", "d": "2"})


class SpecTests(unittest.TestCase):
    """Expected values from the examples in the YAML 1.2.2 specification."""

    def test_escaped_line_breaks(self):
        # Example 7.5, double-quoted line breaks.
        self.assertEqual(load('a: "folded \nto a space,\t\n \nto a line feed, or \t\\\n'
                              ' \\ \tnon-content"\n'),
                         {"a": "folded to a space,\nto a line feed, or \t \tnon-content"})
        # Example 7.6, double-quoted lines.
        self.assertEqual(load('a: " 1st non-empty\n\n 2nd non-empty \n\t3rd non-empty "\n'),
                         {"a": " 1st non-empty\n2nd non-empty 3rd non-empty "})
        self.assertEqual(load('a: "x\\\n\n  y"\n'), {"a": "x\ny"})
        self.assertEqual(load('a: "x\\\\\n  y"\n'), {"a": "x\\ y"})
        self.assertEqual(load('a: "x\\ \n  y"\n'), {"a": "x  y"})

    def test_block_indentation_indicators(self):
        # Example 8.1, block scalar header.
        self.assertEqual(load("- | # Empty header\n literal\n- >1 # Indentation indicator\n"
                              "  folded\n- |+ # Chomping indicator\n keep\n\n"
                              "- >1- # Both indicators\n  strip\n"),
                         ["literal\n", " folded\n", "keep\n\n", " strip"])
        # Example 8.2, block indentation indicator (without its tab item).
        self.assertEqual(load("- |\n detected\n- >\n \n  \n  # detected\n- |1\n  explicit\n"),
                         ["detected\n", "\n\n# detected\n", " explicit\n"])
        self.assertEqual(load("a:\n  b: |2-\n     x\n    y\n\n  c: >-2\n     z\n"),
                         {"a": {"b": " x\ny", "c": " z"}})
        self.assertEqual(load("a: |2+\n\n   x\n\nb: 1\n"), {"a": "\n x\n\n", "b": "1"})
        self.assertEqual(load("- a: |1\n    x\n"), [{"a": " x\n"}])

    def test_chomping_final_line_break(self):
        # Example 8.4.
        self.assertEqual(load("strip: |-\n  text\nclip: |\n  text\nkeep: |+\n  text\n"),
                         {"strip": "text", "clip": "text\n", "keep": "text\n"})
        # Example 8.6, empty scalar chomping.
        self.assertEqual(load("strip: >-\n\nclip: >\n\nkeep: |+\n\n"),
                         {"strip": "", "clip": "", "keep": "\n"})

    def test_block_at_end_of_file_without_line_break(self):
        # The final line has no line break, so clip and keep add none.
        self.assertEqual(load("a: |\n  x"), {"a": "x"})
        self.assertEqual(load("a: >\n  x\n  y"), {"a": "x y"})
        self.assertEqual(load("a: |+\n  x"), {"a": "x"})
        self.assertEqual(load("a: |+\n  x\n\n"), {"a": "x\n\n"})
        self.assertEqual(load("a: |+\n  x\n\n  "), {"a": "x\n\n"})
        self.assertEqual(load("a: |-\n  x"), {"a": "x"})
        self.assertEqual(load("a: |\n  x\n\n"), {"a": "x\n"})


class RefusedTests(unittest.TestCase):
    def refused(self, text, line, message):
        with self.assertRaises(YamlError) as cm:
            y(text)
        self.assertEqual((cm.exception.line, cm.exception.message), (line, message))

    def test_tags_and_unsupported_anchor_positions(self):
        self.refused("a: !!str 1\n", 1, "tags are not supported")
        self.refused("a: [&x b, *x]\n", 1, "anchors, aliases, tags and complex keys are not supported")
        self.refused("&x a: b\n", 1, "anchors, aliases and tags on mapping keys are not supported")
        self.refused("a: & 1\n", 1, "expected a name after '&'")

    def test_alias_errors(self):
        self.refused("a: 1\nb: *x\n", 2, "alias 'x' has no anchor before it")
        self.refused("a:\n  - *x\n", 2, "alias 'x' has no anchor before it")
        self.refused("a: &x 1\nb: *x y\n", 2, "unexpected content after alias 'x'")

    def test_alias_expansion_is_bounded(self):
        text = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
        for i in range(8):
            new, old = chr(98 + i), chr(97 + i)
            text += "%s: &%s\n" % (new, new) + ("  - *%s\n" % old) * 10
        with self.assertRaises(YamlError) as cm:
            load(text)
        self.assertEqual(cm.exception.message, "aliases expand to too many values")

    def test_other_constructs(self):
        self.refused("a: 1\n<<: {b: 2}\n", 2, "merge keys are not supported")
        self.refused("? a\n: 1\n", 1, "complex mapping keys are not supported")
        self.refused("%YAML 1.2\n---\na: 1\n", 1, "directives are not supported")
        self.refused("a: 1\n---\nb: 2\n", 2, "several documents in one file are not supported")
        self.refused("a:\n\tb: 1\n", 2, "tabs in indentation are not supported")
        self.refused("a: |\n\tx\n", 2, "tabs in indentation are not supported")
        self.refused("a: |\n  x\n \ty\n", 3, "tabs in indentation are not supported")
        self.refused("a: 1\na: 2\n", 2, "duplicate key 'a'")
        self.refused("a: |0\n  x\n", 1, "block scalar header '|0' is not supported")
        self.refused("a: |2\n x\n", 2, "block scalar line is less indented than the first")

    def test_deep_nesting(self):
        self.refused("a: " + "[" * 3000 + "]" * 3000 + "\n", 1, "nesting is too deep")
        deep = "".join(" " * n + "k%d:\n" % n for n in range(1500))
        with self.assertRaises(YamlError) as cm:
            load(deep)
        self.assertEqual(cm.exception.message, "nesting is too deep")

    def test_malformed(self):
        self.refused("a: [1, 2\n", 1, "unterminated flow collection")
        self.refused("a: 'x\n", 1, "unterminated quoted string")
        self.refused("a:\n  b: |\n      deep\n    shallow\n", 4,
                     "block scalar line is less indented than the first")
        self.refused("a: 1\n   b: 2\n", 2, "unexpected indentation")


if __name__ == "__main__":
    unittest.main()
