"""Deterministic rule table.

Every rule has a fixed severity and confidence. Severity answers "how bad
if true"; confidence answers "how sure are we that the detector is right".
They are deliberately separate fields.

Rules that detect a *capability* are low severity: reading an env var or
calling an HTTP endpoint is normal. Rules that detect a *connected flow*
from a sensitive source to an external sink are high or critical.
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
    "PY_ENV_ACCESS": Rule(
        rule_id="PY_ENV_ACCESS",
        title="Reads environment variables",
        category="capability",
        severity="low",
        capabilities=(cap.READ_ENV,),
        confidence=1.0,
        reason=(
            "Environment reads are common and not malicious by themselves. "
            "Severity stays low unless the value reaches an external sink."
        ),
    ),
    "PY_FILE_READ": Rule(
        rule_id="PY_FILE_READ",
        title="Reads files from disk",
        category="capability",
        severity="low",
        capabilities=(cap.READ_FILE,),
        confidence=1.0,
        reason=(
            "File reads are a normal server capability. Severity rises only "
            "when file contents flow to a network or process sink."
        ),
    ),
    "PY_FILE_WRITE": Rule(
        rule_id="PY_FILE_WRITE",
        title="Writes files to disk",
        category="capability",
        severity="low",
        capabilities=(cap.WRITE_FILE,),
        confidence=1.0,
        reason="File writes are expected for many servers and are reported for context.",
    ),
    "PY_NETWORK_EGRESS": Rule(
        rule_id="PY_NETWORK_EGRESS",
        title="Makes outbound network requests",
        category="capability",
        severity="low",
        capabilities=(cap.NETWORK_EGRESS,),
        confidence=1.0,
        reason=(
            "Network egress is required by many legitimate MCP servers. "
            "Reporting it alone as malicious would create false positives."
        ),
    ),
    "PY_SUBPROCESS": Rule(
        rule_id="PY_SUBPROCESS",
        title="Executes external processes",
        category="capability",
        severity="medium",
        capabilities=(cap.SUBPROCESS,),
        confidence=1.0,
        reason=(
            "Spawning processes widens the blast radius of any other weakness, "
            "so this is rated medium rather than low."
        ),
    ),
    "PY_DYNAMIC_EXEC": Rule(
        rule_id="PY_DYNAMIC_EXEC",
        title="Uses dynamic code execution",
        category="capability",
        severity="high",
        capabilities=(cap.DYNAMIC_EXEC,),
        confidence=1.0,
        reason=(
            "exec/eval/compile can hide arbitrary behaviour from static review, "
            "which defeats the purpose of an audit."
        ),
    ),
    "DF_ENV_TO_NETWORK": Rule(
        rule_id="DF_ENV_TO_NETWORK",
        title="Environment variable flows into an outbound request",
        category="data_exfiltration",
        severity="critical",
        capabilities=(cap.READ_ENV, cap.NETWORK_EGRESS),
        confidence=0.9,
        reason=(
            "A value read from the environment is passed to a network sink. "
            "That is the classic credential-exfiltration path and is critical "
            "regardless of intent."
        ),
    ),
    "DF_FILE_TO_NETWORK": Rule(
        rule_id="DF_FILE_TO_NETWORK",
        title="File contents flow into an outbound request",
        category="data_exfiltration",
        severity="critical",
        capabilities=(cap.READ_FILE, cap.NETWORK_EGRESS),
        confidence=0.9,
        reason=(
            "Data read from disk is passed to a network sink, which can leak "
            "private keys, tokens or user documents off the host."
        ),
    ),
    "DF_ENV_TO_SUBPROCESS": Rule(
        rule_id="DF_ENV_TO_SUBPROCESS",
        title="Environment variable flows into a process invocation",
        category="command_injection",
        severity="high",
        capabilities=(cap.READ_ENV, cap.SUBPROCESS),
        confidence=0.8,
        reason=(
            "Environment-controlled data reaching a subprocess call is a "
            "command-injection pattern."
        ),
    ),
}


def get(rule_id: str) -> Rule:
    return RULES[rule_id]
