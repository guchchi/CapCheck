"""Evidence correlation and deterministic risk assessment.

Rules enforced here:
  * No finding exists without at least one evidence id.
  * Severity comes from the rule table, never from a model.
  * The risk score is a capped, auditable sum. Every point is traceable
    to a named finding.
"""

from __future__ import annotations

import re

from backend.models import (
    SEVERITY_BASE,
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
    Evidence,
    Finding,
    RiskAssessment,
    RiskItem,
)
from backend.rules import javascript_rules, python_rules

_RULE_TABLES = (python_rules.RULES, javascript_rules.RULES)


def _rule(rule_id: str):
    """Look a rule up across language tables.

    The catalogues are separate so each language owns its own severity
    decisions, but correlation stays language-agnostic.
    """
    for table in _RULE_TABLES:
        rule = table.get(rule_id)
        if rule is not None:
            return rule
    raise KeyError(f"unknown rule id: {rule_id}")


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
        rule = _rule(rule_id)
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
        rule = _rule(item["rule_id"])
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


def _evidence_map(evidence: list[Evidence] | dict[str, Evidence] | None) -> dict[str, Evidence]:
    if evidence is None:
        return {}
    if isinstance(evidence, dict):
        return evidence
    return {e.id: e for e in evidence}


def _flow_locations_and_ids(
    flow_findings: list[Finding],
    evidence_map: dict[str, Evidence],
) -> tuple[set[str], set[tuple[str, int]]]:
    ev_ids: set[str] = set()
    locations: set[tuple[str, int]] = set()

    for flow in flow_findings:
        ev_ids.update(flow.evidence_ids)

        has_ev_locs = False
        for ev_id in flow.evidence_ids:
            ev = evidence_map.get(ev_id)
            if ev and ev.path and ev.line_start is not None:
                locations.add((ev.path, ev.line_start))
                has_ev_locs = True

        if not has_ev_locs:
            path = ""
            if " — " in flow.title:
                path = flow.title.split(" — ", 1)[1].strip()
            for m in re.finditer(r"\bline\s+(\d+)\b", flow.summary):
                if path:
                    locations.add((path, int(m.group(1))))

    return ev_ids, locations


def _capability_locations_and_ids(
    cap: Finding,
    evidence_map: dict[str, Evidence],
) -> tuple[set[str], set[tuple[str, int]]]:
    ev_ids = set(cap.evidence_ids)
    locations: set[tuple[str, int]] = set()

    for ev_id in cap.evidence_ids:
        ev = evidence_map.get(ev_id)
        if ev and ev.path and ev.line_start is not None:
            locations.add((ev.path, ev.line_start))

    if not locations:
        path = ""
        if " — " in cap.title:
            path = cap.title.split(" — ", 1)[1].strip()
        m = re.search(r"line\(s\)\s+([0-9, ]+)\s+in\s+([^\s]+)", cap.summary)
        if m:
            summary_path = m.group(2).rstrip(".")
            for part in m.group(1).split(","):
                part = part.strip()
                if part.isdigit():
                    locations.add((summary_path, int(part)))
        elif path:
            for m in re.finditer(r"\bline(?:s)?\s+(\d+)\b", cap.summary):
                locations.add((path, int(m.group(1))))

    return ev_ids, locations


def assess_risk(
    findings: list[Finding],
    evidence: list[Evidence] | dict[str, Evidence] | None = None,
) -> RiskAssessment:
    """Assess overall scan risk based on flow findings and capability findings.

    A. Flow findings:
       - Base values: Critical=80, High=50, Medium=20, Low=5, Info=0.
       - Base * confidence; if confidence >= 0.70, minimum contribution equals severity base.
       - Sorted descending; diminishing returns: 1st 100%, 2nd 50%, 3rd+ 25%.

    B. Capability findings:
       - Aggregate capability contribution capped at 15 points.
       - Capabilities subsumed by confirmed flows contribute 0 points.
       - Visible in the report even when risk contribution is zero.

    C. Final score:
       - Clamped to 0-100.
    """
    ev_map = _evidence_map(evidence)

    flow_findings = [f for f in findings if f.category != "capability"]
    cap_findings = [f for f in findings if f.category == "capability"]

    flow_ev_ids, flow_locations = _flow_locations_and_ids(flow_findings, ev_map)

    # 1. Flow findings scoring
    flow_contributions: list[tuple[Finding, float]] = []
    for flow in flow_findings:
        base = float(SEVERITY_BASE.get(flow.severity, 0))
        raw = base * flow.confidence
        contrib = max(base, raw) if flow.confidence >= 0.70 else raw
        flow_contributions.append((flow, contrib))

    flow_contributions.sort(key=lambda item: item[1], reverse=True)

    flow_items: list[tuple[Finding, float, float]] = []
    diminishing_multipliers = [1.0, 0.5]
    for idx, (flow, contrib) in enumerate(flow_contributions):
        mult = diminishing_multipliers[idx] if idx < len(diminishing_multipliers) else 0.25
        effective = round(contrib * mult, 2)
        base = float(SEVERITY_BASE.get(flow.severity, 0))
        flow_items.append((flow, base, effective))

    flow_total = sum(item[2] for item in flow_items)

    # 2. Capability findings scoring (subsumption & 15-pt cap)
    cap_items: list[tuple[Finding, float, float]] = []
    for cap in cap_findings:
        base = float(SEVERITY_BASE.get(cap.severity, 0))
        cap_ev_set, cap_locs = _capability_locations_and_ids(cap, ev_map)

        has_ev_overlap = bool(cap_ev_set & flow_ev_ids)
        has_loc_overlap = bool(cap_locs & flow_locations) if cap_locs and flow_locations else False

        if has_ev_overlap or has_loc_overlap:
            if cap_locs and flow_locations:
                unsubsumed = [loc for loc in cap_locs if loc not in flow_locations]
                if not unsubsumed:
                    cap_items.append((cap, base, 0.0))
                    continue
                ratio = len(unsubsumed) / len(cap_locs)
                raw_cap = round(base * cap.confidence * ratio, 2)
                cap_items.append((cap, base, raw_cap))
            elif cap_ev_set and flow_ev_ids:
                unsubsumed_ev = [e for e in cap_ev_set if e not in flow_ev_ids]
                if not unsubsumed_ev:
                    cap_items.append((cap, base, 0.0))
                    continue
                ratio = len(unsubsumed_ev) / len(cap_ev_set)
                raw_cap = round(base * cap.confidence * ratio, 2)
                cap_items.append((cap, base, raw_cap))
            else:
                cap_items.append((cap, base, 0.0))
        else:
            raw_cap = round(base * cap.confidence, 2)
            cap_items.append((cap, base, raw_cap))

    raw_cap_total = sum(item[2] for item in cap_items)
    effective_cap_items: list[tuple[Finding, float, float]] = []
    if raw_cap_total > 15.0:
        scale = 15.0 / raw_cap_total
        running_sum = 0.0
        for cap, base, raw_pts in cap_items:
            if raw_pts == 0.0:
                effective_cap_items.append((cap, base, 0.0))
            else:
                scaled = round(raw_pts * scale, 2)
                effective_cap_items.append((cap, base, scaled))
                running_sum += scaled
        cap_total = min(15.0, round(running_sum, 2))
    else:
        effective_cap_items = cap_items
        cap_total = round(raw_cap_total, 2)

    # 3. Final score
    combined = flow_total + cap_total
    score = int(min(100, max(0, round(combined))))

    # 4. Breakdown
    breakdown: list[RiskItem] = []
    for flow, base, eff in flow_items:
        breakdown.append(
            RiskItem(
                finding_id=flow.id,
                severity=flow.severity,
                confidence=flow.confidence,
                weight=int(base),
                points=eff,
            )
        )
    for cap, base, eff in effective_cap_items:
        breakdown.append(
            RiskItem(
                finding_id=cap.id,
                severity=cap.severity,
                confidence=cap.confidence,
                weight=int(base),
                points=eff,
            )
        )

    method = (
        "score = clamp(0, 100, diminishing_flows + capped_capabilities); "
        "flow severity_weight: critical=80, high=50, medium=20, low=5; "
        "diminishing returns: 100%, 50%, 25%; capabilities capped at 15"
    )
    return RiskAssessment(
        score=score,
        band=_band(score),  # type: ignore[arg-type]
        method=method,
        breakdown=breakdown,
    )
