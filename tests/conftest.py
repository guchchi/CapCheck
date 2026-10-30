"""Test bootstrap.

The data directory is redirected to a temp folder *before* backend.config is
imported, so tests never touch the developer's real scan artifacts.

GitHub is never contacted: every repository test installs an in-memory
``FakeFetcher`` that builds a ZIP archive locally.
"""

from __future__ import annotations

import io
import os
import tempfile
import zipfile
from pathlib import Path

_TEMP_DATA = tempfile.mkdtemp(prefix="capcheck-tests-")
os.environ["CAPCHECK_DATA_DIR"] = _TEMP_DATA
os.environ["CAPCHECK_DEV_MODE"] = "1"
os.environ["CAPCHECK_LLM_PROVIDER"] = "null"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.core import github  # noqa: E402
from backend.main import app  # noqa: E402


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


class FakeFetcher:
    """Offline stand-in for :class:`backend.core.github.HttpxFetcher`."""

    def __init__(
        self,
        files: dict[str, bytes | str],
        *,
        commit_sha: str = "0123456789abcdef0123456789abcdef01234567",
        default_branch: str = "main",
    ) -> None:
        self.files = {
            name: value.encode("utf-8") if isinstance(value, str) else value
            for name, value in files.items()
        }
        self.commit_sha = commit_sha
        self.default_branch = default_branch

    def resolve(self, ref: github.RepoRef, settings) -> github.ResolvedRepo:
        return github.ResolvedRepo(
            ref=ref, commit_sha=self.commit_sha, default_branch=self.default_branch
        )

    def download(self, resolved: github.ResolvedRepo, destination: Path, settings) -> int:
        buffer = io.BytesIO()
        prefix = f"{resolved.ref.repo}-{resolved.commit_sha[:7]}"
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name, data in self.files.items():
                bundle.writestr(f"{prefix}/{name}", data)
        destination.write_bytes(buffer.getvalue())
        return len(buffer.getvalue())


def files_from_directory(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@pytest.fixture()
def install_fetcher(monkeypatch):
    """Install an offline GitHub fetcher for one test."""

    def install(files: dict[str, bytes | str], **kwargs) -> FakeFetcher:
        fetcher = FakeFetcher(files, **kwargs)
        monkeypatch.setattr(github, "get_fetcher", lambda: fetcher)
        return fetcher

    return install


def _wait(client: TestClient, scan_id: str) -> dict:
    status: dict = {}
    for _ in range(50):
        status = client.get(f"/api/scans/{scan_id}").json()
        if status.get("status") in {"complete", "failed"}:
            break
    return status


def run_scan(client: TestClient, fixture: str) -> str:
    response = client.post("/api/scans", json={"fixture": fixture})
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]

    status = _wait(client, scan_id)
    assert status["status"] == "complete", status
    return scan_id


def run_repo_scan(client: TestClient, repo_url: str) -> tuple[str, dict]:
    response = client.post("/api/scans", json={"repo_url": repo_url})
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]

    status = _wait(client, scan_id)
    return scan_id, status
