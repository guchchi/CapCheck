"""Test bootstrap.

The data directory is redirected to a temp folder *before* backend.config is
imported, so tests never touch the developer's real scan artifacts.
"""

from __future__ import annotations

import os
import tempfile

_TEMP_DATA = tempfile.mkdtemp(prefix="capcheck-tests-")
os.environ["CAPCHECK_DATA_DIR"] = _TEMP_DATA
os.environ["CAPCHECK_DEV_MODE"] = "1"
os.environ["CAPCHECK_LLM_PROVIDER"] = "null"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.main import app  # noqa: E402


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


def run_scan(client: TestClient, fixture: str) -> str:
    response = client.post("/api/scans", json={"fixture": fixture})
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]

    for _ in range(20):
        status = client.get(f"/api/scans/{scan_id}").json()
        if status["status"] in {"complete", "failed"}:
            break
        # No sleep: the TestClient runs background tasks inline.
    assert status["status"] == "complete", status
    return scan_id
