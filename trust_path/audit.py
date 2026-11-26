"""--audit-json: one audit result object (format audit-result/1) for a trust-path run.

Each finding keeps the --json record unchanged under "record" and adds a rule id and a
severity fixed by the kind of sink, one sentence that says what the path is, and its evidence.
"""

import os

from . import __version__

FORMAT = "audit-result/1"

# (rule, severity) by kind of sink; see docs/commands.md. Fixed: never from what the step does.
RULES = {
    "secret": "high", "secrets-inherit": "high", "write-permission": "high",
    "oidc-token": "high", "agent": "high", "environment": "medium",
    "default-permissions": "medium",
}


def classify(sink):
    """Return (rule name, words for a sentence) for a sink field."""
    if sink == "secrets:inherit":
        return "secrets-inherit", "every secret of the caller (secrets: inherit)"
    if sink.startswith("secrets."):
        return "secret", "the secret " + sink[len("secrets."):]
    if sink == "permissions.id-token:write":
        return "oidc-token", "an OIDC token (id-token: write)"
    if sink.startswith("permissions.") and sink.endswith(":write"):
        return "write-permission", "write permission on " + sink[len("permissions."):-6]
    if sink == "permissions:default":
        return "default-permissions", "the GITHUB_TOKEN with the repository's default permissions"
    if sink.startswith("environment:"):
        return "environment", "the environment " + sink[len("environment:"):]
    if sink.startswith("agent:"):
        return "agent", "the AI agent action " + sink[len("agent:"):]
    return "sink", sink


def message(row):
    """Return one sentence that says what the record means."""
    run, _, entry = row["source"].rpartition(":")
    _, reaches = classify(row["sink"])
    # A chain "pull_request@ci.yml>workflow_run" reads "pull_request in ci.yml, then workflow_run".
    runs = ", then ".join(" in ".join(part.split("@", 1)) for part in run.split(">"))
    text = "Untrusted input from %s, entering as %s, reaches %s in %s, job %s, step %s" % (
        runs or row["source"], entry, reaches, row["workflow"], row["job"], row["step"])
    if row["detail"] != "-":
        text += " (%s)" % row["detail"]
    return text


def finding(row, ref, commit):
    """Return the audit finding for one --json record."""
    rule, _ = classify(row["sink"])
    evidence = {"path": row["workflow"]}
    if ref is not None:
        evidence["ref"] = ref
    if commit is not None:
        evidence["commit"] = commit
    return {
        "rule": "trust-path." + rule,
        "severity": RULES.get(rule, "high"),
        "message": message(row),
        "evidence": evidence,
        "record": row,
    }


def result(directory, ref, findings, errors):
    """Return the audit result object.

    Args:
        directory: DIR as given, or "." without one.
        ref: REF as given, or None.
        findings: Audit findings, in the order of the records.
        errors: (message, path or None) pairs, in the order written to stderr.
    """
    name = os.path.basename(os.path.normpath(os.path.abspath(directory))) or directory
    target = {"kind": "repository", "name": name}
    if ref is not None:
        target["ref"] = ref
    code = 2 if errors else (1 if findings else 0)
    out = []
    for text, path in errors:
        out.append({"message": text, "path": path} if path else {"message": text})
    return {
        "format": FORMAT,
        "tool": {"name": "trust-path", "version": __version__},
        "target": target,
        "exit": code,
        "findings": findings,
        "errors": out,
    }
