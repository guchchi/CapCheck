"""Evidence correlation and deterministic risk assessment.

Rules enforced here:
  * No finding exists without at least one evidence id.
  * Severity comes from the rule table, never from a model.
  * The risk score is a capped, auditable sum. Every point is traceable
    to a named finding.
"""

from __future__ import annotations

from backend.models import (
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
    Finding,
    RiskAssessment,
    RiskItem,
)
from backend.rules import python_rules


def _band(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "moderate"
    return "low"


def _capability_findings(raw: list[dict]) -> list[Finding]:
    """Group capability observations by (rule, file) to keep signal readable."""
    grouped: dict[tuple[str, str], list[dict]] = {}
    for item in raw:
        grouped.setdefault((item["rule_id"], item["path"]), []).append(item)

    findings: list[Finding] = []
    for index, ((rule_id, path), items) in enumerate(sorted(grouped.items()), start=1):
        rule = python_rules.get(rule_id)
        evidence_ids = sorted({entry["evidence_id"] for entry in items})
        lines = sorted({entry["line"] for entry in items})
        findings.append(
            Finding(
                id=f"f_cap_{index:03d}",
                rule_id=rule_id,
                category=rule.category,
                severity=rule.severity,
                title=f"{rule.title} — {path}",
                summary=(
                    f"{rule.title} at line(s) {', '.join(str(line) for line in lines)} "
                    f"in {path}."
                ),
                capabilities=list(rule.capabilities),
                evidence_ids=evidence_ids,
                ai_claim_ids=[],
                corroboration="deterministic",
                confidence=rule.confidence,
                reason=rule.reason,
            )
        )
    return findings


def _flow_findings(raw: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for index, item in enumerate(raw, start=1):
        rule = python_rules.get(item["rule_id"])
        findings.append(
            Finding(
                id=f"f_flow_{index:03d}",
                rule_id=item["rule_id"],
                category=rule.category,
                severity=rule.severity,
                title=f"{rule.title} — {item['path']}",
                summary=item["detail"],
                capabilities=list(rule.capabilities),
                evidence_ids=item["evidence_ids"],
                ai_claim_ids=[],
                corroboration="deterministic",
                confidence=rule.confidence,
                reason=rule.reason,
            )
        )
    return findings


def correlate(capability_raw: list[dict], flow_raw: list[dict]) -> list[Finding]:
    findings = _capability_findings(capability_raw) + _flow_findings(flow_raw)
    findings.sort(
        key=lambda finding: (-SEVERITY_ORDER[finding.severity], finding.rule_id, finding.title)
    )

    # Invariant: a finding without evidence is a bug, not a low-severity item.
    for finding in findings:
        if not finding.evidence_ids:
            raise ValueError(f"finding {finding.id} has no evidence")
    return findings


def assess_risk(findings: list[Finding]) -> RiskAssessment:
    breakdown: list[RiskItem] = []
    total = 0.0
    for finding in findings:
        weight = SEVERITY_WEIGHT[finding.severity]
        points = round(weight * finding.confidence, 2)
        total += points
        breakdown.append(
            RiskItem(
                finding_id=finding.id,
                severity=finding.severity,
                confidence=finding.confidence,
                weight=weight,
                points=points,
            )
        )
    score = int(min(100, round(total)))
    return RiskAssessment(
        score=score,
        band=_band(score),  # type: ignore[arg-type]
        method=(
            "score = min(100, sum(severity_weight * confidence)); "
            "weights: critical=55, high=25, medium=10, low=3"
        ),
        breakdown=breakdown,
    )
