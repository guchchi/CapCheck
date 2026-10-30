"""Tests for Milestone 3: Gemma 4 semantic analysis.

All tests run offline using mock HTTP responses and fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from backend.config import settings
from backend.core import pipeline
from backend.llm.gemma import GemmaProvider, sanitize_code_context
from backend.llm.null import NullProvider
from backend.models import ToolDef
from tests.conftest import run_scan


def _sample_tool() -> ToolDef:
    return ToolDef(
        name="add",
        declared_description="Add two numbers together.",
        params=["a", "b"],
        source_file="server.py",
        line=23,
        evidence_id="ev_tool_1",
        language="python",
        input_schema=json.dumps({"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}),
        handler_line=23,
        handler_end_line=26,
        observed_capabilities=["READ_ENV", "NETWORK_EGRESS"],
    )


# --------------------------------------------------------------------------
# 1. Secret sanitization and bounded input context
# --------------------------------------------------------------------------


def test_sanitize_code_context_redacts_credentials():
    raw_code = (
        'def send_data():\n'
        '    api_key = "sk_live_1234567890abcdef"\n'
        '    token = "ghp_123456789012345678901234567890123456"\n'
        '    secret = "my_super_secret_value_xyz"\n'
        '    auth = "Bearer secret_bearer_token_here"\n'
        '    return api_key\n'
    )
    sanitized = sanitize_code_context(raw_code)

    assert "sk_live_1234567890abcdef" not in sanitized
    assert "ghp_123456789012345678901234567890123456" not in sanitized
    assert "my_super_secret_value_xyz" not in sanitized
    assert "secret_bearer_token_here" not in sanitized
    assert "[REDACTED]" in sanitized or "[REDACTED_SECRET]" in sanitized


def test_sanitize_code_context_bounds_lines_and_length():
    many_lines = "\n".join([f"line_{i} = {i}" for i in range(100)])
    sanitized = sanitize_code_context(many_lines, max_lines=20, max_chars=300)

    assert len(sanitized.splitlines()) <= 22  # 20 lines + truncation marker
    assert "[TRUNCATED FOR BOUNDED CONTEXT]" in sanitized


# --------------------------------------------------------------------------
# 2. GemmaProvider offline unit tests (mock HTTP)
# --------------------------------------------------------------------------


def test_gemma_provider_absent_api_key_returns_empty():
    provider = GemmaProvider(api_key="")
    claims = provider.analyze_tool(_sample_tool(), ["NETWORK_EGRESS"])
    assert claims == []


def test_gemma_provider_successful_mismatch_claim():
    mock_response_json = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps(
                                {
                                    "claims": [
                                        {
                                            "claimed_behavior": "Add two numbers together.",
                                            "observed_behavior": "Reads GITHUB_TOKEN and sends outbound telemetry to remote server.",
                                            "potential_mismatch": True,
                                            "confidence": 0.95,
                                            "supporting_code_references": ["server.py:25"],
                                            "reasoning": "Declared as an arithmetic utility, but silently exfiltrates telemetry.",
                                        }
                                    ]
                                }
                            )
                        }
                    ]
                }
            }
        ]
    }

    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_response_json
    mock_client.post.return_value = mock_resp

    provider = GemmaProvider(
        api_key="fake-test-key",
        model="gemma-4-31b-it",
        client=mock_client,
    )

    claims = provider.analyze_tool(
        _sample_tool(),
        ["READ_ENV", "NETWORK_EGRESS"],
        code_context="def add(a, b):\n    requests.post(...)",
    )

    assert len(claims) == 1
    claim = claims[0]
    assert claim["tool_name"] == "add"
    assert claim["claimed_behavior"] == "Add two numbers together."
    assert "telemetry" in claim["observed_behavior"]
    assert claim["potential_mismatch"] is True
    assert claim["confidence"] == 0.95
    assert claim["supporting_code_references"] == ["server.py:25"]
    assert claim["cited_evidence_ids"] == ["ev_tool_1"]
    assert claim["model"] == "gemma-4-31b-it"


def test_gemma_provider_handles_markdown_code_fences():
    inner_json = json.dumps(
        {
            "claims": [
                {
                    "claimed_behavior": "Add numbers",
                    "observed_behavior": "Calculates sum",
                    "potential_mismatch": False,
                    "confidence": 0.9,
                    "supporting_code_references": ["server.py:24"],
                    "reasoning": "No mismatch.",
                }
            ]
        }
    )
    fenced_text = f"```json\n{inner_json}\n```"

    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": fenced_text}]}}]
    }
    mock_client.post.return_value = mock_resp

    provider = GemmaProvider(api_key="fake-key", client=mock_client)
    claims = provider.analyze_tool(_sample_tool(), [])

    assert len(claims) == 1
    assert claims[0]["potential_mismatch"] is False


def test_gemma_provider_quota_exhausted_fail_safe():
    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 429  # Quota exceeded
    mock_client.post.return_value = mock_resp

    provider = GemmaProvider(api_key="fake-key", client=mock_client)
    claims = provider.analyze_tool(_sample_tool(), ["READ_ENV"])

    assert claims == []
    # Must not retry on 429
    assert mock_client.post.call_count == 1


def test_gemma_provider_auth_failure_fail_safe():
    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 401  # Invalid key
    mock_client.post.return_value = mock_resp

    provider = GemmaProvider(api_key="invalid-key", client=mock_client)
    claims = provider.analyze_tool(_sample_tool(), [])

    assert claims == []
    # Must not retry on 401
    assert mock_client.post.call_count == 1


def test_gemma_provider_timeout_and_retries_fail_safe():
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.side_effect = httpx.TimeoutException("Read timed out")

    provider = GemmaProvider(
        api_key="fake-key", max_retries=2, client=mock_client
    )
    claims = provider.analyze_tool(_sample_tool(), [])

    assert claims == []
    # Initial attempt + 2 retries = 3 calls
    assert mock_client.post.call_count == 3


def test_gemma_provider_malformed_json_fail_safe():
    mock_client = MagicMock(spec=httpx.Client)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": "Not valid JSON at all"}]}}]
    }
    mock_client.post.return_value = mock_resp

    provider = GemmaProvider(api_key="fake-key", client=mock_client)
    claims = provider.analyze_tool(_sample_tool(), [])

    assert claims == []


# --------------------------------------------------------------------------
# 3. Pipeline integration & safety invariants
# --------------------------------------------------------------------------


def test_pipeline_fallback_to_null_when_api_key_missing(monkeypatch):
    test_settings = settings.__class__(
        dev_mode=True,
        data_dir=settings.data_dir,
        llm_provider="gemma",
        github_api_base="https://api.github.com",
        gemini_api_key=None,
    )
    monkeypatch.setattr(pipeline, "settings", test_settings)

    provider = pipeline._provider()
    assert isinstance(provider, NullProvider)


def test_ai_claims_never_create_findings_or_affect_risk_score(client, monkeypatch):
    """Core security invariant:
    AI claims are recorded in suppressed_claims as unverified observations.
    They NEVER create findings and NEVER alter risk scores.
    """
    # Create a mock provider that generates an alarming mismatch claim
    mock_claim = {
        "id": "claim_add_01",
        "tool_name": "add",
        "claimed_behavior": "Add numbers",
        "observed_behavior": "CRITICAL AI MISMATCH SUSPICION",
        "potential_mismatch": True,
        "confidence": 1.0,
        "supporting_code_references": ["server.py:25"],
        "cited_evidence_ids": [],
        "model": "gemma-4-31b-it",
        "reasoning": "Suspected backdoor",
    }

    class MockAlarmingGemmaProvider:
        name = "gemma"

        def analyze_tool(self, tool, capabilities, code_context=None):
            return [mock_claim]

    # Run scan with NullProvider first
    scan_id_baseline = run_scan(client, "benign_calculator")
    baseline = client.get(f"/api/scans/{scan_id_baseline}").json()
    findings_baseline = client.get(f"/api/scans/{scan_id_baseline}/findings").json()["findings"]

    # Run scan with Alarming Gemma Provider
    monkeypatch.setattr(pipeline, "_provider", lambda: MockAlarmingGemmaProvider())

    scan_id_gemma = run_scan(client, "benign_calculator")
    gemma_scan = client.get(f"/api/scans/{scan_id_gemma}").json()
    findings_gemma = client.get(f"/api/scans/{scan_id_gemma}/findings").json()["findings"]

    # Invariants:
    # 1. Findings count and content are identical: AI claim did NOT become a finding!
    assert len(findings_gemma) == len(findings_baseline) == 0
    # 2. Risk score is completely identical: AI claim did NOT change the risk score!
    assert gemma_scan["risk"]["score"] == baseline["risk"]["score"] == 0
    assert gemma_scan["risk"]["band"] == baseline["risk"]["band"] == "low"
    # 3. Claims are stored under suppressed_claims
    claims_resp = client.get(f"/api/scans/{scan_id_gemma}/claims").json()
    assert claims_resp["count"] > 0
    assert claims_resp["claims"][0]["provider"] == "gemma"
    assert claims_resp["claims"][0]["potential_mismatch"] is True
    assert claims_resp["claims"][0]["observed_behavior"] == "CRITICAL AI MISMATCH SUSPICION"


def test_api_claims_endpoint(client):
    scan_id = run_scan(client, "benign_calculator")
    res = client.get(f"/api/scans/{scan_id}/claims")
    assert res.status_code == 200
    data = res.json()
    assert "scan_id" in data
    assert "count" in data
    assert "claims" in data
    assert isinstance(data["claims"], list)


def test_scan_with_zero_claims_contract(client):
    """Verifies that a scan with zero claims produces an empty claims list and does not interfere with findings."""
    scan_id = run_scan(client, "benign_calculator")
    res = client.get(f"/api/scans/{scan_id}/claims")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 0
    assert data["claims"] == []

    findings = client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    assert len(findings) == 0


def test_scan_with_semantic_claims_and_verified_findings(client, monkeypatch):
    """Verifies a scan with semantic claims has complete claim fields while preserving findings and evidence."""
    mock_claim = {
        "id": "claim_exfil_01",
        "tool_name": "exfiltrate",
        "claimed_behavior": "Exfiltrate data to remote endpoint",
        "observed_behavior": "Reads system environment and performs HTTP POST",
        "potential_mismatch": False,
        "confidence": 0.88,
        "supporting_code_references": ["server.py:12"],
        "cited_evidence_ids": [],
        "model": "gemma-4-31b-it",
        "reasoning": "Observed behavior aligns with declared description.",
    }

    class MockProvider:
        name = "gemma"

        def analyze_tool(self, tool, capabilities, code_context=None):
            return [mock_claim]

    monkeypatch.setattr(pipeline, "_provider", lambda: MockProvider())

    scan_id = run_scan(client, "exfil_server")

    # 1. Check claims endpoint contract
    claims_resp = client.get(f"/api/scans/{scan_id}/claims")
    assert claims_resp.status_code == 200
    claims_data = claims_resp.json()
    assert claims_data["count"] > 0
    claim = claims_data["claims"][0]
    assert claim["tool_name"] == "exfiltrate"
    assert claim["claimed_behavior"] == "Exfiltrate data to remote endpoint"
    assert claim["observed_behavior"] == "Reads system environment and performs HTTP POST"
    assert claim["potential_mismatch"] is False
    assert claim["confidence"] == 0.88
    assert claim["supporting_code_references"] == ["server.py:12"]
    assert claim["model"] == "gemma-4-31b-it"

    # 2. Check findings and evidence still work normally
    findings_resp = client.get(f"/api/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()["findings"]
    flow_findings = [f for f in findings if f["rule_id"] == "DF_ENV_TO_NETWORK"]
    assert len(flow_findings) == 1
    flow = flow_findings[0]
    assert flow["severity"] == "critical"

    # Evidence resolves
    for ev_id in flow["evidence_ids"]:
        ev_resp = client.get(f"/api/scans/{scan_id}/evidence/{ev_id}")
        assert ev_resp.status_code == 200
        assert ev_resp.json()["id"] == ev_id


def test_claims_api_nonexistent_scan_returns_404(client):
    """Verifies that requesting claims for an invalid scan id returns 404."""
    res = client.get("/api/scans/invalid_scan_id_99999/claims")
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "SCAN_NOT_FOUND"
