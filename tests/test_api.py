"""API contract tests for Milestone 1."""

from __future__ import annotations

import pytest
from tests.conftest import run_scan


def test_healthz_reports_null_provider(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["llm"] == "null"
    assert "benign_calculator" in body["fixtures"]
    assert "exfil_server" in body["fixtures"]


def test_benign_fixture_has_zero_critical_findings(client):
    scan_id = run_scan(client, "benign_calculator")
    findings = client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    critical = [f for f in findings if f["severity"] == "critical"]
    assert critical == []


def test_benign_fixture_is_completely_clean(client):
    scan_id = run_scan(client, "benign_calculator")
    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["finding_count"] == 0
    assert body["risk"]["score"] == 0
    assert body["risk"]["band"] == "low"


def test_exfil_fixture_detects_env_to_network_flow(client):
    scan_id = run_scan(client, "exfil_server")
    findings = client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    flow = [f for f in findings if f["rule_id"] == "DF_ENV_TO_NETWORK"]
    assert len(flow) == 1
    assert flow[0]["severity"] == "critical"
    assert flow[0]["category"] == "data_exfiltration"
    assert "READ_ENV" in flow[0]["capabilities"]
    assert "NETWORK_EGRESS" in flow[0]["capabilities"]


def test_exfil_fixture_also_reports_individual_capabilities(client):
    scan_id = run_scan(client, "exfil_server")
    findings = client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    rule_ids = {f["rule_id"] for f in findings}
    assert {"PY_ENV_ACCESS", "PY_NETWORK_EGRESS", "DF_ENV_TO_NETWORK"} <= rule_ids


def test_every_finding_has_at_least_one_evidence_id(client):
    scan_id = run_scan(client, "exfil_server")
    findings = client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    assert findings, "expected findings for the malicious fixture"
    for finding in findings:
        assert finding["evidence_ids"], f"{finding['id']} has no evidence"


def test_every_evidence_id_resolves(client):
    scan_id = run_scan(client, "exfil_server")
    findings = client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    for finding in findings:
        for evidence_id in finding["evidence_ids"]:
            response = client.get(f"/api/scans/{scan_id}/evidence/{evidence_id}")
            assert response.status_code == 200, (finding["id"], evidence_id)
            assert response.json()["id"] == evidence_id


def test_flow_evidence_points_at_source_and_sink(client):
    scan_id = run_scan(client, "exfil_server")
    findings = client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    flow = next(f for f in findings if f["rule_id"] == "DF_ENV_TO_NETWORK")
    assert len(flow["evidence_ids"]) == 2, "flow must cite both source and sink"

    snippets = []
    for evidence_id in flow["evidence_ids"]:
        evidence = client.get(f"/api/scans/{scan_id}/evidence/{evidence_id}").json()
        assert evidence["path"] == "server.py"
        assert isinstance(evidence["line_start"], int) and evidence["line_start"] > 0
        assert evidence["snippet"]
        snippets.append(evidence["snippet"])

    joined = " ".join(snippets)
    assert "os.environ.get" in joined
    assert "requests.post" in joined


def test_evidence_line_numbers_match_the_file(client):
    scan_id = run_scan(client, "exfil_server")
    findings = client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    flow = next(f for f in findings if f["rule_id"] == "DF_ENV_TO_NETWORK")

    source_path = __import__("pathlib").Path("fixtures") / "exfil_server" / "server.py"
    source_lines = source_path.read_text(encoding="utf-8").splitlines()

    for evidence_id in flow["evidence_ids"]:
        evidence = client.get(f"/api/scans/{scan_id}/evidence/{evidence_id}").json()
        line_index = evidence["line_start"] - 1
        actual = source_lines[line_index].strip()
        assert actual.startswith(evidence["snippet"].rstrip("…"))


def test_tools_are_discovered_statically(client):
    scan_id = run_scan(client, "exfil_server")
    tools = client.get(f"/api/scans/{scan_id}/tools").json()["tools"]
    names = {tool["name"] for tool in tools}
    assert names == {"add", "multiply"}
    assert all(tool["declared_description"] for tool in tools)


def test_invalid_scan_id_returns_enveloped_404(client):
    response = client.get("/api/scans/sc_doesnotexist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_invalid_evidence_id_returns_enveloped_404(client):
    scan_id = run_scan(client, "benign_calculator")
    response = client.get(f"/api/scans/{scan_id}/evidence/ev_missing")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "EVIDENCE_NOT_FOUND"


def test_unknown_fixture_is_rejected_before_scanning(client):
    response = client.post("/api/scans", json={"fixture": "does_not_exist"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "UNKNOWN_FIXTURE"


def test_path_traversal_fixture_name_is_rejected(client):
    response = client.post("/api/scans", json={"fixture": "../../etc"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "UNKNOWN_FIXTURE"


def test_remote_repo_scan_is_explicitly_not_implemented(client):
    response = client.post("/api/scans", json={"repo_url": "https://github.com/a/b"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REPO_SCAN_NOT_IMPLEMENTED"


def test_missing_source_returns_400(client):
    response = client.post("/api/scans", json={})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "MISSING_SOURCE"


def test_risk_score_is_explained(client):
    scan_id = run_scan(client, "exfil_server")
    risk = client.get(f"/api/scans/{scan_id}").json()["risk"]
    assert risk["score"] >= 55
    assert risk["band"] in {"high", "critical"}
    assert risk["breakdown"], "risk must expose per-finding arithmetic"
    total = sum(item["points"] for item in risk["breakdown"])
    assert abs(total - risk["score"]) <= 1
    assert "severity_weight" in risk["method"]
