"""A YAML reader for the subset of YAML that GitHub Actions workflows use.

Supported: block mappings and sequences, plain, single-quoted and
double-quoted scalars (also over several lines), literal (|) and folded (>)
block scalars, flow sequences and mappings, and comments.

Every scalar is returned as a str; an empty value is None. YAML features
outside the subset (anchors, aliases, tags, complex keys, merge keys,
directives, several documents, tabs in indentation) raise YamlError instead
of being guessed at.
"""

import re


class YamlError(Exception):
    def __init__(self, line, message):
        Exception.__init__(self, "line %d: %s" % (line, message))
        self.line = line
        self.message = message


_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n",
            "v": "\v", "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"',
            "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": " ",
            "P": " "}
_HEX = {"x": 2, "u": 4, "U": 8}


def load(text):
    """Parse one YAML document and return dicts, lists, str and None."""
    parser = _Parser(text)
    try:
        return parser.document()
    except RecursionError:
        raise YamlError(parser.i + 1, "nesting is too deep")


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _is_marker(line):
    """True for a '---' or '...' document marker line."""
    return line[:3] in ("---", "...") and line[3:4] in ("", " ")


def _is_blank(line):
    s = line.strip()
    return not s or s.startswith("#")


def _strip_comment(s):
    """Remove a trailing ' #...' comment from a plain (unquoted) value."""
    if s.startswith("#"):
        return ""
    m = re.search(r"\s#", s)
    return (s[:m.start()] if m else s).rstrip()


def _find_colon(s):
    """Index of the ': ' (or final ':') that ends a mapping key, or -1."""
    if s[:1] in ("\"", "'"):
        end = _quote_end(s, 0)
        if end < 0:
            return -1
        rest = s[end + 1:]
        if rest.lstrip().startswith(":"):
            i = end + 1 + (len(rest) - len(rest.lstrip()))
            nxt = s[i + 1:i + 2]
            return i if nxt in ("", " ") else -1
        return -1
    if s[:1] in ("[", "{"):
        return -1
    for m in re.finditer(r":(?= |$)", s):
        if " #" in s[:m.start()]:
            return -1
        return m.start()
    return -1


def _quote_end(s, start):
    """Index of the quote closing the quoted scalar at s[start], or -1."""
    q = s[start]
    i = start + 1
    while i < len(s):
        c = s[i]
        if q == '"' and c == "\\":
            i += 2
            continue
        if c == q:
            if q == "'" and s[i + 1:i + 2] == "'":
                i += 2
                continue
            return i
        i += 1
    return -1


def _fold(parts):
    """Fold trimmed lines into one value: a line break becomes a space, and
    each blank line becomes a newline."""
    out = ""
    blanks = 0
    for n, part in enumerate(parts):
        if part == "" and n:
            blanks += 1
            continue
        if n:
            out += "\n" * blanks if blanks else " "
        out += part
        blanks = 0
    return out


def _unquote(raw, lineno):
    """Value of a complete quoted scalar (raw includes both quotes)."""
    q, body = raw[0], raw[1:-1]
    lines = body.split("\n")
    if len(lines) > 1:
        if q == '"' and any(re.search(r"(?<!\\)(\\\\)*\\$", ln) for ln in lines[:-1]):
            raise YamlError(lineno, "escaped line breaks in double-quoted strings are not supported")
        lines = ([lines[0].rstrip(" \t")] + [ln.strip(" \t") for ln in lines[1:-1]]
                 + [lines[-1].lstrip(" \t")])
    folded = _fold(lines)
    if q == "'":
        return folded.replace("''", "'")
    out = []
    i = 0
    while i < len(folded):
        c = folded[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        e = folded[i + 1:i + 2]
        if e in _ESCAPES:
            out.append(_ESCAPES[e])
            i += 2
        elif e in _HEX:
            digits = folded[i + 2:i + 2 + _HEX[e]]
            if len(digits) != _HEX[e] or not re.match(r"^[0-9A-Fa-f]+$", digits):
                raise YamlError(lineno, "bad escape in double-quoted string")
            out.append(chr(int(digits, 16)))
            i += 2 + _HEX[e]
        else:
            raise YamlError(lineno, "unknown escape \\%s in double-quoted string" % e)
    return "".join(out)


class _Parser(object):
    def __init__(self, text):
        if text.startswith("﻿"):
            text = text[1:]
        self.lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.i = 0
        for n, line in enumerate(self.lines):
            if line.lstrip(" ").startswith("\t") and line.strip():
                raise YamlError(n + 1, "tabs in indentation are not supported")

    def err(self, message, n=None):
        raise YamlError((self.i if n is None else n) + 1, message)

    def peek(self):
        """Skip blank and comment lines; return the next line or None."""
        while self.i < len(self.lines) and _is_blank(self.lines[self.i]):
            self.i += 1
        return self.lines[self.i] if self.i < len(self.lines) else None

    def document(self):
        line = self.peek()
        if line is not None and line.startswith("%"):
            self.err("directives are not supported")
        if line is not None and line.rstrip() == "---":
            self.i += 1
        elif line is not None and line.startswith("---"):
            self.err("content on the '---' line is not supported")
        if self.peek() is None:
            return None
        node = self.block(0)
        line = self.peek()
        if line is not None and line.rstrip() == "...":
            self.i += 1
            line = self.peek()
        if line is not None:
            if _is_marker(line):
                self.err("several documents in one file are not supported")
            self.err("unexpected content")
        return node

    def block(self, min_indent):
        line = self.peek()
        if line is None or _indent(line) < min_indent:
            return None
        ind = _indent(line)
        body = line[ind:]
        if body == "-" or body.startswith("- "):
            return self.sequence(ind)
        if _find_colon(body) >= 0 or body == "?" or body.startswith("? "):
            return self.mapping(ind)
        return self.scalar_value(self.i, ind, ind - 1)

    def mapping(self, ind):
        result = {}
        while True:
            line = self.peek()
            if line is None or _indent(line) < ind or _is_marker(line):
                return result
            if _indent(line) > ind:
                self.err("unexpected indentation")
            body = line[ind:]
            if body.startswith("- ") or body == "-":
                return result
            if body.startswith("? ") or body == "?":
                self.err("complex mapping keys are not supported")
            c = _find_colon(body)
            if c < 0:
                self.err("expected 'key: value'")
            key_text = body[:c].strip()
            if key_text[:1] in ("&", "*", "!"):
                self.err("anchors, aliases and tags are not supported")
            key = _unquote(key_text, self.i + 1) if key_text[:1] in ("'", '"') else key_text
            if key == "<<":
                self.err("merge keys are not supported")
            if key in result:
                self.err("duplicate key %r" % key)
            rest = body[c + 1:]
            if _strip_comment(rest.strip()) == "":
                self.i += 1
                nxt = self.peek()
                if nxt is not None and _indent(nxt) > ind:
                    result[key] = self.block(ind + 1)
                elif nxt is not None and _indent(nxt) == ind and (
                        nxt[ind:].startswith("- ") or nxt[ind:].rstrip() == "-"):
                    result[key] = self.sequence(ind)
                else:
                    result[key] = None
            else:
                col = ind + c + 1 + (len(rest) - len(rest.lstrip(" ")))
                result[key] = self.scalar_value(self.i, col, ind)

    def sequence(self, ind):
        result = []
        while True:
            line = self.peek()
            if line is None or _indent(line) < ind or _is_marker(line):
                return result
            if _indent(line) > ind:
                self.err("unexpected indentation")
            body = line[ind:]
            if not (body.startswith("- ") or body.rstrip() == "-"):
                return result
            rest = body[1:]
            if _strip_comment(rest.strip()) == "":
                self.i += 1
                result.append(self.block(ind + 1))
                continue
            col = ind + 1 + (len(rest) - len(rest.lstrip(" ")))
            # Read the item as if it started on its own line at its column.
            self.lines[self.i] = " " * col + rest.lstrip(" ")
            result.append(self.block(col))

    def scalar_value(self, start, col, parent_indent):
        """Parse the value at column `col` of line `start`; following lines
        indented more than parent_indent may continue it."""
        self.i = start
        text = self.lines[start][col:]
        c = text[:1]
        if c in ("&", "*", "!"):
            self.err("anchors, aliases and tags are not supported")
        if c in ("|", ">"):
            return self.block_scalar(text, parent_indent)
        if c in ("'", '"'):
            return self.quoted(text)
        if c in ("[", "{"):
            return self.flow(text)
        if c in ("@", "`", "%"):
            self.err("a plain value cannot start with %r" % c)
        first = _strip_comment(text)
        parts = [first.strip()]
        commented = first != text.rstrip()
        self.i += 1
        while self.i < len(self.lines):
            ln = self.lines[self.i]
            if ln.strip() and (_indent(ln) <= parent_indent or ln.lstrip().startswith("#")
                               or _is_marker(ln)):
                break
            if ln.strip() and commented:
                self.err("a value cannot continue after a comment")
            part = _strip_comment(ln.strip())
            if _find_colon(part) >= 0:
                self.err("unexpected indentation")
            commented = part != ln.strip()
            parts.append(part)
            self.i += 1
        while len(parts) > 1 and parts[-1] == "":
            parts.pop()
        value = _fold(parts)
        return None if value in ("", "~", "null", "Null", "NULL") else value

    def quoted(self, text):
        start = self.i
        while _quote_end(text, 0) < 0:
            self.i += 1
            if self.i >= len(self.lines):
                self.err("unterminated quoted string", start)
            text += "\n" + self.lines[self.i]
        end = _quote_end(text, 0)
        if _strip_comment(text[end + 1:].strip()) != "":
            self.err("unexpected text after quoted string")
        self.i += 1
        return _unquote(text[:end + 1], start + 1)

    def block_scalar(self, header, parent_indent):
        start = self.i
        m = re.match(r"^([|>])([+-]?)\s*(#.*)?$", header)
        if not m:
            self.err("block scalar header %r is not supported" % header.strip())
        style, chomp = m.group(1), m.group(2)
        self.i += 1
        lines = []
        while self.i < len(self.lines):
            ln = self.lines[self.i]
            if ln.strip() and _indent(ln) <= parent_indent:
                break
            lines.append(ln)
            self.i += 1
        trailing = 0
        while lines and not lines[-1].strip():
            lines.pop()
            trailing += 1
        if not lines:
            return "\n" * trailing if chomp == "+" else ""
        ind = _indent(next(ln for ln in lines if ln.strip()))
        for n, ln in enumerate(lines):
            if ln.strip() and _indent(ln) < ind:
                self.err("block scalar line is less indented than the first", start + 1 + n)
        body = [ln[ind:] for ln in lines]
        if style == "|":
            text = "\n".join(body)
        else:
            # Folded: lines join with a space; blank and more-indented lines
            # keep their line breaks.
            text = body[0]
            for prev, ln in zip(body, body[1:]):
                normal = prev != "" and not prev.startswith(" ")
                if normal and ln != "" and not ln.startswith(" "):
                    text += " " + ln
                elif normal and ln == "":
                    text += ln
                else:
                    text += "\n" + ln
        if chomp == "-":
            return text
        if chomp == "+":
            return text + "\n" * (1 + trailing)
        return text + "\n"

    def flow(self, text):
        start = self.i
        while True:
            try:
                value, end = _Flow(text, start + 1).parse()
                break
            except _Incomplete:
                self.i += 1
                if self.i >= len(self.lines):
                    self.err("unterminated flow collection", start)
                text += "\n" + self.lines[self.i]
        if _strip_comment(text[end:].strip()) != "":
            self.err("unexpected text after flow collection")
        self.i += 1
        return value


class _Incomplete(Exception):
    pass


class _Flow(object):
    """Parser for flow collections: [a, b] and {a: b}."""

    def __init__(self, text, lineno):
        self.s = text
        self.k = 0
        self.lineno = lineno

    def ws(self):
        while self.k < len(self.s):
            if self.s[self.k] in " \t\n":
                self.k += 1
            elif self.s[self.k] == "#" and (self.k == 0 or self.s[self.k - 1] in " \t\n"):
                nl = self.s.find("\n", self.k)
                if nl < 0:
                    raise _Incomplete()
                self.k = nl
            else:
                return
        raise _Incomplete()

    def parse(self):
        v = self.node()
        return v, self.k

    def node(self):
        self.ws()
        c = self.s[self.k]
        if c == "[":
            self.k += 1
            items = []
            while True:
                self.ws()
                if self.s[self.k] == "]":
                    self.k += 1
                    return items
                items.append(self.node())
                self.ws()
                if self.s[self.k] == ",":
                    self.k += 1
                elif self.s[self.k] != "]":
                    raise YamlError(self.lineno, "expected ',' or ']'")
        if c == "{":
            self.k += 1
            result = {}
            while True:
                self.ws()
                if self.s[self.k] == "}":
                    self.k += 1
                    return result
                key = self.node()
                self.ws()
                if self.s[self.k] != ":":
                    raise YamlError(self.lineno, "expected ':' in flow mapping")
                self.k += 1
                self.ws()
                val = None if self.s[self.k] in ",}" else self.node()
                if not isinstance(key, str) or key in result:
                    raise YamlError(self.lineno, "bad or duplicate key in flow mapping")
                result[key] = val
                self.ws()
                if self.s[self.k] == ",":
                    self.k += 1
                elif self.s[self.k] != "}":
                    raise YamlError(self.lineno, "expected ',' or '}'")
        if c in "\"'":
            end = _quote_end(self.s, self.k)
            if end < 0:
                raise _Incomplete()
            raw = self.s[self.k:end + 1]
            self.k = end + 1
            return _unquote(raw, self.lineno)
        if c in "&*!?":
            raise YamlError(self.lineno, "anchors, aliases, tags and complex keys are not supported")
        m = re.compile(r"(?:[^,\[\]{}:\n#]|:(?![ ,\]}\n])|(?<! )#)+").match(self.s, self.k)
        if not m:
            raise YamlError(self.lineno, "unexpected %r in flow collection" % c)
        self.k = m.end()
        v = m.group(0).strip()
        return None if v in ("", "~", "null") else v
