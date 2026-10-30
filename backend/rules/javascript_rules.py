"""Deterministic rules for JavaScript and TypeScript source.

Severity policy is identical to the Python rule table: a capability alone is
low severity; only a connected source-to-sink flow escalates.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.models import Severity
from backend.rules import capabilities as cap


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    severity: Severity
    capabilities: tuple[str, ...]
    confidence: float
    reason: str


RULES: dict[str, Rule] = {
    "JS_ENV_ACCESS": Rule(
        rule_id="JS_ENV_ACCESS",
        title="Reads environment variables",
        category="capability",
        severity="low",
        capabilities=(cap.READ_ENV,),
        confidence=1.0,
        reason=(
            "process.env access is normal configuration handling. Severity "
            "stays low unless the value reaches an external sink."
        ),
    ),
    "JS_FILE_READ": Rule(
        rule_id="JS_FILE_READ",
        title="Reads files from disk",
        category="capability",
        severity="low",
        capabilities=(cap.READ_FILE,),
        confidence=1.0,
        reason="File reads are reported for context, not as malicious behaviour.",
    ),
    "JS_SENSITIVE_PATH_READ": Rule(
        rule_id="JS_SENSITIVE_PATH_READ",
        title="Reads a credential-bearing path",
        category="capability",
        severity="medium",
        capabilities=(cap.READ_FILE,),
        confidence=0.85,
        reason=(
            "The read targets a conventional credential location such as "
            "~/.ssh, .aws or .npmrc. This is not proof of intent, but it "
            "raises the impact of any outbound flow."
        ),
    ),
    "JS_NETWORK_EGRESS": Rule(
        rule_id="JS_NETWORK_EGRESS",
        title="Makes outbound network requests",
        category="capability",
        severity="low",
        capabilities=(cap.NETWORK_EGRESS,),
        confidence=1.0,
        reason=(
            "Network egress is a required capability for many MCP servers and "
            "is never treated as malicious on its own."
        ),
    ),
    "JS_SUBPROCESS": Rule(
        rule_id="JS_SUBPROCESS",
        title="Executes external processes",
        category="capability",
        severity="medium",
        capabilities=(cap.SUBPROCESS,),
        confidence=1.0,
        reason="Process execution widens the blast radius of any other weakness.",
    ),
    "JS_DYNAMIC_EXEC": Rule(
        rule_id="JS_DYNAMIC_EXEC",
        title="Uses dynamic code execution",
        category="capability",
        severity="high",
        capabilities=(cap.DYNAMIC_EXEC,),
        confidence=1.0,
        reason=(
            "eval/new Function can hide arbitrary behaviour from static review, "
            "which defeats the purpose of an audit."
        ),
    ),
    "JS_ENV_TO_NETWORK": Rule(
        rule_id="JS_ENV_TO_NETWORK",
        title="Environment variable flows into an outbound request",
        category="data_exfiltration",
        severity="critical",
        capabilities=(cap.READ_ENV, cap.NETWORK_EGRESS),
        confidence=0.9,
        reason=(
            "A value read from process.env is passed to a network sink. This is "
            "the canonical credential-exfiltration path and is critical "
            "regardless of intent."
        ),
    ),
    "JS_FILE_TO_NETWORK": Rule(
        rule_id="JS_FILE_TO_NETWORK",
        title="File contents flow into an outbound request",
        category="data_exfiltration",
        severity="critical",
        capabilities=(cap.READ_FILE, cap.NETWORK_EGRESS),
        confidence=0.9,
        reason=(
            "Data read from disk is passed to a network sink, which can leak "
            "private keys or user documents off the host."
        ),
    ),
    "JS_ENV_TO_SUBPROCESS": Rule(
        rule_id="JS_ENV_TO_SUBPROCESS",
        title="Environment variable flows into a process invocation",
        category="command_injection",
        severity="high",
        capabilities=(cap.READ_ENV, cap.SUBPROCESS),
        confidence=0.8,
        reason="Environment-controlled data reaching a subprocess call is a command-injection pattern.",
    ),
}

FLOW_RULES = frozenset(
    {
        "JS_ENV_TO_NETWORK",
        "JS_FILE_TO_NETWORK",
        "JS_ENV_TO_SUBPROCESS",
    }
)


def get(rule_id: str) -> Rule:
    return RULES[rule_id]
