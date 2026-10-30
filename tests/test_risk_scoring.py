"""Regression and contract tests for M2.2 Risk Scoring Correction."""

from __future__ import annotations

import pytest

from backend.core.correlate import assess_risk
from backend.models import Evidence, Finding, RiskAssessment
from tests.conftest import run_scan


def _make_finding(
    id: str,
    rule_id: str,
    category: str,
    severity: str,
    confidence: float,
    *,
    path: str = "server.py",
    summary: str = "",
    evidence_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        id=id,
        rule_id=rule_id,
        category=category,
        severity=severity,  # type: ignore[arg-type]
        title=f"{rule_id} — {path}",
        summary=summary or f"{rule_id} finding in {path}.",
        capabilities=[],
        evidence_ids=evidence_ids or [f"ev_{id}"],
        ai_claim_ids=[],
        corroboration="deterministic",
        confidence=confidence,
        reason="Test finding",
    )


def test_1_benign_calculator_score_zero(client):
    # Direct unit test
    empty_risk = assess_risk([])
    assert empty_risk.score == 0
    assert empty_risk.band == "low"
    assert empty_risk.breakdown == []

    # Full pipeline scan test
    scan_id = run_scan(client, "benign_calculator")
    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["finding_count"] == 0
    assert body["risk"]["score"] == 0
    assert body["risk"]["band"] == "low"


def test_2_fifty_capabilities_across_twenty_five_files_capped_at_fifteen():
    caps: list[Finding] = []
    for i in range(50):
        file_idx = i % 25
        path = f"service_{file_idx}.py"
        caps.append(
            _make_finding(
                id=f"f_cap_{i:03d}",
                rule_id="PY_ENV_ACCESS",
                category="capability",
                severity="low",
                confidence=1.0,
                path=path,
                summary=f"Reads environment variables at line(s) {i + 1} in {path}.",
                evidence_ids=[f"ev_{i}"],
            )
        )

    risk = assess_risk(caps)
    # Capabilities must be capped at 15 points and never exceed low risk band
    assert risk.score <= 15
    assert risk.band == "low"
    total_breakdown = sum(item.points for item in risk.breakdown)
    assert total_breakdown <= 15.01


def test_3_one_critical_flow_produces_critical_band_and_score_ge_80(client):
    # Unit level
    f_crit = _make_finding(
        id="f_flow_001",
        rule_id="DF_ENV_TO_NETWORK",
        category="data_exfiltration",
        severity="critical",
        confidence=0.9,
        path="server.py",
        summary="Environment variable read at line 10 reaches the network sink at line 20.",
        evidence_ids=["ev_sink", "ev_src"],
    )
    risk = assess_risk([f_crit])
    assert risk.score >= 80
    assert risk.band == "critical"
    assert risk.breakdown[0].points == 80.0

    # Pipeline fixture level
    scan_id = run_scan(client, "exfil_server")
    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["risk"]["score"] == 80
    assert body["risk"]["band"] == "critical"


def test_4_two_independent_critical_flows_diminishing_returns():
    f_crit1 = _make_finding(
        id="f_flow_001",
        rule_id="DF_ENV_TO_NETWORK",
        category="data_exfiltration",
        severity="critical",
        confidence=0.9,
        path="server.py",
        summary="Environment variable read at line 10 reaches the network sink at line 20.",
        evidence_ids=["ev_sink1", "ev_src1"],
    )
    f_crit2 = _make_finding(
        id="f_flow_002",
        rule_id="DF_FILE_TO_NETWORK",
        category="data_exfiltration",
        severity="critical",
        confidence=0.9,
        path="storage.py",
        summary="File contents read at line 5 reaches the network sink at line 15.",
        evidence_ids=["ev_sink2", "ev_src2"],
    )

    risk = assess_risk([f_crit1, f_crit2])
    # 80 (100%) + 40 (50%) = 120 -> clamped to 100
    assert risk.score == 100
    assert risk.band == "critical"
    assert risk.breakdown[0].points == 80.0
    assert risk.breakdown[1].points == 40.0

    # 3 independent flows
    f_crit3 = _make_finding(
        id="f_flow_003",
        rule_id="DF_FILE_TO_NETWORK",
        category="data_exfiltration",
        severity="critical",
        confidence=0.9,
        path="backup.py",
        summary="File contents read at line 2 reaches the network sink at line 8.",
        evidence_ids=["ev_sink3", "ev_src3"],
    )
    risk3 = assess_risk([f_crit1, f_crit2, f_crit3])
    # 80 (100%) + 40 (50%) + 20 (25%) = 140 -> clamped to 100
    assert risk3.score == 100
    assert risk3.breakdown[2].points == 20.0


def test_5_flow_plus_overlapping_capabilities_same_score_as_flow_alone():
    flow = _make_finding(
        id="f_flow_001",
        rule_id="DF_ENV_TO_NETWORK",
        category="data_exfiltration",
        severity="critical",
        confidence=0.9,
        path="server.py",
        summary="Environment variable read at line 38 reaches the network sink at line 40.",
        evidence_ids=["ev_sink", "ev_src"],
    )
    cap_env = _make_finding(
        id="f_cap_001",
        rule_id="PY_ENV_ACCESS",
        category="capability",
        severity="low",
        confidence=1.0,
        path="server.py",
        summary="Reads environment variables at line(s) 38 in server.py.",
        evidence_ids=["ev_cap_env"],
    )
    cap_net = _make_finding(
        id="f_cap_002",
        rule_id="PY_NETWORK_EGRESS",
        category="capability",
        severity="low",
        confidence=1.0,
        path="server.py",
        summary="Makes outbound network requests at line(s) 40 in server.py.",
        evidence_ids=["ev_cap_net"],
    )

    risk_flow_alone = assess_risk([flow])
    risk_with_caps = assess_risk([flow, cap_env, cap_net])

    assert risk_with_caps.score == risk_flow_alone.score == 80
    assert risk_with_caps.band == risk_flow_alone.band == "critical"
    # Subsumed capabilities must be present in breakdown with 0.0 points
    points_by_id = {item.finding_id: item.points for item in risk_with_caps.breakdown}
    assert points_by_id["f_flow_001"] == 80.0
    assert points_by_id["f_cap_001"] == 0.0
    assert points_by_id["f_cap_002"] == 0.0


def test_6_low_confidence_critical_flow_receives_no_floor():
    f_low = _make_finding(
        id="f_flow_001",
        rule_id="DF_ENV_TO_NETWORK",
        category="data_exfiltration",
        severity="critical",
        confidence=0.4,
        path="server.py",
        summary="Environment variable read at line 10 reaches the network sink at line 20.",
        evidence_ids=["ev_sink", "ev_src"],
    )
    risk = assess_risk([f_low])
    # 80 * 0.4 = 32.0 (no 80 floor)
    assert risk.score == 32
    assert risk.band == "moderate"
    assert risk.breakdown[0].points == 32.0


def test_7_multiple_low_confidence_findings_cannot_artificially_reach_critical():
    flows = [
        _make_finding(
            id=f"f_flow_{i:03d}",
            rule_id="DF_ENV_TO_NETWORK",
            category="data_exfiltration",
            severity="critical",
            confidence=0.3,
            path=f"module_{i}.py",
            summary=f"Environment variable read at line {i} reaches network sink at line {i + 10}.",
            evidence_ids=[f"ev_{i}_sink", f"ev_{i}_src"],
        )
        for i in range(5)
    ]
    risk = assess_risk(flows)
    # 24.0 (100%) + 12.0 (50%) + 6.0 (25%) + 6.0 (25%) + 6.0 (25%) = 54.0
    assert risk.score < 80
    assert risk.band != "critical"
    assert risk.score == 54


def test_8_high_and_medium_flow_scoring():
    # High flow (base 50)
    f_high = _make_finding(
        id="f_flow_001",
        rule_id="DF_ENV_TO_SUBPROCESS",
        category="command_injection",
        severity="high",
        confidence=0.8,
        path="cmd.py",
        summary="Environment variable read at line 5 reaches subprocess at line 12.",
        evidence_ids=["ev_1", "ev_2"],
    )
    risk_high = assess_risk([f_high])
    assert risk_high.score == 50
    assert risk_high.band == "high"

    # Medium flow (base 20)
    f_med = _make_finding(
        id="f_flow_002",
        rule_id="DF_UNKNOWN",
        category="flow",
        severity="medium",
        confidence=0.8,
        path="worker.py",
        summary="Flow at line 8 reaches sink at line 18.",
        evidence_ids=["ev_3", "ev_4"],
    )
    risk_med = assess_risk([f_med])
    assert risk_med.score == 20
    assert risk_med.band == "moderate"

    # Combined high + medium: 50 * 1.0 + 20 * 0.5 = 60
    risk_combined = assess_risk([f_high, f_med])
    assert risk_combined.score == 60
    assert risk_combined.band == "high"
    assert risk_combined.breakdown[0].points == 50.0
    assert risk_combined.breakdown[1].points == 10.0


def test_9_api_response_schema_compatibility(client):
    scan_id = run_scan(client, "exfil_server")
    res = client.get(f"/api/scans/{scan_id}")
    assert res.status_code == 200
    data = res.json()

    assert "risk" in data
    risk = data["risk"]
    assert isinstance(risk["score"], int)
    assert risk["band"] in {"low", "moderate", "high", "critical"}
    assert isinstance(risk["method"], str)
    assert isinstance(risk["breakdown"], list)

    for item in risk["breakdown"]:
        assert "finding_id" in item
        assert "severity" in item
        assert "confidence" in item
        assert "weight" in item
        assert "points" in item
        assert isinstance(item["points"], (int, float))


def test_10_evidence_object_matching_overlap():
    # Verify exact Evidence object matching
    evidence_list = [
        Evidence(
            id="ev_sink_1",
            kind="flow_path",
            path="app/server.py",
            line_start=50,
            line_end=50,
            snippet="requests.post(...)",
            extractor="test",
            file_sha256="abc",
        ),
        Evidence(
            id="ev_src_1",
            kind="flow_path",
            path="app/server.py",
            line_start=25,
            line_end=25,
            snippet="os.environ.get(...)",
            extractor="test",
            file_sha256="abc",
        ),
        Evidence(
            id="ev_cap_env_1",
            kind="ast_node",
            path="app/server.py",
            line_start=25,
            line_end=25,
            snippet="os.environ.get(...)",
            extractor="test",
            file_sha256="abc",
        ),
    ]

    flow = _make_finding(
        id="f_flow_001",
        rule_id="DF_ENV_TO_NETWORK",
        category="data_exfiltration",
        severity="critical",
        confidence=0.9,
        path="app/server.py",
        summary="Flow detail.",
        evidence_ids=["ev_sink_1", "ev_src_1"],
    )
    cap = _make_finding(
        id="f_cap_001",
        rule_id="PY_ENV_ACCESS",
        category="capability",
        severity="low",
        confidence=1.0,
        path="app/server.py",
        summary="Capability detail.",
        evidence_ids=["ev_cap_env_1"],
    )

    risk = assess_risk([flow, cap], evidence=evidence_list)
    assert risk.score == 80
    assert risk.breakdown[0].points == 80.0
    assert risk.breakdown[1].points == 0.0


def test_11_partial_capability_subsumption():
    flow = _make_finding(
        id="f_flow_001",
        rule_id="DF_ENV_TO_NETWORK",
        category="data_exfiltration",
        severity="critical",
        confidence=0.9,
        path="server.py",
        summary="Environment variable read at line 10 reaches the network sink at line 20.",
        evidence_ids=["ev_sink", "ev_src"],
    )
    # Capability finding with 2 lines: line 10 (subsumed by flow) and line 15 (unsubsumed)
    cap = _make_finding(
        id="f_cap_001",
        rule_id="PY_ENV_ACCESS",
        category="capability",
        severity="low",
        confidence=1.0,
        path="server.py",
        summary="Reads environment variables at line(s) 10, 15 in server.py.",
        evidence_ids=["ev_cap_10", "ev_cap_15"],
    )

    risk = assess_risk([flow, cap])
    # Flow = 80.0, Cap = 5.0 * 1.0 * (1 / 2) = 2.5
    # Total = 82.5 -> rounds to 82, band = critical
    assert risk.score == 82
    assert risk.band == "critical"
    points_by_id = {item.finding_id: item.points for item in risk.breakdown}
    assert points_by_id["f_flow_001"] == 80.0
    assert points_by_id["f_cap_001"] == 2.5


def test_12_six_independent_critical_flows_confidence_zero_point_four_reach_critical():
    flows = [
        _make_finding(
            id=f"f_flow_{i:03d}",
            rule_id="DF_ENV_TO_NETWORK",
            category="data_exfiltration",
            severity="critical",
            confidence=0.4,
            path=f"service_{i}.py",
            summary=f"Flow at line {i} reaches network sink at line {i + 10}.",
            evidence_ids=[f"ev_sink_{i}", f"ev_src_{i}"],
        )
        for i in range(1, 7)
    ]

    risk = assess_risk(flows)
    # Flow 1: 32.0, Flow 2: 16.0, Flows 3-6: 8.0 each -> sum = 80.0
    assert risk.score == 80
    assert risk.band == "critical"
    expected_points = [32.0, 16.0, 8.0, 8.0, 8.0, 8.0]
    actual_points = [item.points for item in risk.breakdown]
    assert actual_points == expected_points

