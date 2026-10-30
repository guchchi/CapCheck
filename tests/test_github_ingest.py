"""Remote GitHub ingestion tests.

Every test that reaches the pipeline installs an in-memory fetcher via the
``install_fetcher`` fixture. No test contacts github.com.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

import pytest

from backend.core import github
from backend.core.errors import IngestError
from backend.core.github import InvalidRepoURL, parse_repo_url
from tests.conftest import files_from_directory, run_repo_scan

FIXTURES = Path("fixtures")


# --------------------------------------------------------------------------
# URL validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url, owner, repo",
    [
        ("https://github.com/guchchi/CapCheck", "guchchi", "CapCheck"),
        ("https://github.com/guchchi/CapCheck/", "guchchi", "CapCheck"),
        ("https://github.com/guchchi/CapCheck.git", "guchchi", "CapCheck"),
        ("https://www.github.com/guchchi/CapCheck", "guchchi", "CapCheck"),
        ("https://GitHub.com/Owner/Repo.Name", "Owner", "Repo.Name"),
    ],
)
def test_valid_repository_urls(url, owner, repo):
    ref = parse_repo_url(url)
    assert ref.owner == owner
    assert ref.repo == repo
    assert ref.canonical_url == f"https://github.com/{owner}/{repo}"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "github.com/owner/repo",
        "http://github.com/owner/repo",
        "git://github.com/owner/repo",
        "ssh://git@github.com/owner/repo",
        "git@github.com:owner/repo.git",
        "https://user:pass@github.com/owner/repo",
        "https://github.com:443/owner/repo",
        "https://gitlab.com/owner/repo",
        "https://github.com.evil.example/owner/repo",
        "https://140.82.112.3/owner/repo",
        "https://github.com/owner/repo?tab=readme",
        "https://github.com/owner/repo#readme",
        "https://github.com/owner",
        "https://github.com/owner/repo/extra",
        "https://github.com/-bad/repo",
        "https://github.com/owner/..",
        "https://github.com/owner/",
        "https://github.com/",
        "https://github.com/owner/repo name",
    ],
)
def test_invalid_repository_urls_are_rejected(url):
    with pytest.raises(InvalidRepoURL):
        parse_repo_url(url)


# --------------------------------------------------------------------------
# End-to-end remote scans, offline
# --------------------------------------------------------------------------


def test_remote_javascript_repository_is_scanned(client, install_fetcher):
    install_fetcher(files_from_directory(FIXTURES / "malicious_js_exfil_server"))

    scan_id, status = run_repo_scan(client, "https://github.com/example/js-utils")

    assert status["status"] == "complete", status
    assert status["source_kind"] == "github"
    assert status["source"] == "https://github.com/example/js-utils"
    assert status["commit_sha"] == "0123456789abcdef0123456789abcdef01234567"
    assert status["languages"] == ["javascript"]
    assert status["metadata"]["default_branch"] == "main"
    assert status["metadata"]["repo_url"] == "https://github.com/example/js-utils"
    assert status["tool_count"] == 2

    findings = client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    assert any(finding["rule_id"] == "JS_ENV_TO_NETWORK" for finding in findings)

    # Evidence paths are relative to the extracted root, never absolute.
    for finding in findings:
        for evidence_id in finding["evidence_ids"]:
            evidence = client.get(f"/api/scans/{scan_id}/evidence/{evidence_id}").json()
            assert evidence["path"] == "server.js"
            assert not PurePosixPath(evidence["path"]).is_absolute()

    serialized = json.dumps(status)
    assert "capcheck-scan-" not in serialized
    assert "C:\\" not in serialized


def test_remote_typescript_repository_is_scanned(client, install_fetcher):
    install_fetcher(files_from_directory(FIXTURES / "malicious_ts_exfil_server"))
    scan_id, status = run_repo_scan(client, "https://github.com/example/ts-report")
    assert status["status"] == "complete", status
    assert status["languages"] == ["typescript"]
    rule_ids = {
        finding["rule_id"]
        for finding in client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    }
    assert {"JS_ENV_TO_NETWORK", "JS_FILE_TO_NETWORK"} <= rule_ids


def test_remote_python_repository_still_works(client, install_fetcher):
    install_fetcher(files_from_directory(FIXTURES / "exfil_server"))
    scan_id, status = run_repo_scan(client, "https://github.com/example/py-exfil")
    assert status["status"] == "complete", status
    assert status["languages"] == ["python"]
    rule_ids = {
        finding["rule_id"]
        for finding in client.get(f"/api/scans/{scan_id}/findings").json()["findings"]
    }
    assert "DF_ENV_TO_NETWORK" in rule_ids


def test_repository_url_is_normalised_in_the_scan_record(client, install_fetcher):
    install_fetcher(files_from_directory(FIXTURES / "benign_js_calculator"))
    _, status = run_repo_scan(client, "https://github.com/example/js-calc.git")
    assert status["source"] == "https://github.com/example/js-calc"


def test_temporary_scan_directory_is_removed(client, install_fetcher, monkeypatch):
    created: dict[str, str] = {}
    real_mkdtemp = __import__("tempfile").mkdtemp

    def record(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created["path"] = path
        return path

    monkeypatch.setattr("backend.core.ingest.tempfile.mkdtemp", record)
    install_fetcher(files_from_directory(FIXTURES / "benign_js_calculator"))

    _, status = run_repo_scan(client, "https://github.com/example/js-calc")
    assert status["status"] == "complete"
    assert "path" in created
    assert not Path(created["path"]).exists()


def test_download_failure_cleans_up_and_records_error_code(client, monkeypatch):
    created: dict[str, str] = {}
    real_mkdtemp = __import__("tempfile").mkdtemp

    def record(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created["path"] = path
        return path

    class FailingFetcher:
        def resolve(self, ref, settings):
            return github.ResolvedRepo(ref=ref, commit_sha="a" * 40, default_branch="main")

        def download(self, resolved, destination, settings):
            raise IngestError("ARCHIVE_DOWNLOAD_FAILED", "boom")

    monkeypatch.setattr("backend.core.ingest.tempfile.mkdtemp", record)
    monkeypatch.setattr(github, "get_fetcher", lambda: FailingFetcher())

    _, status = run_repo_scan(client, "https://github.com/example/broken")
    assert status["status"] == "failed"
    assert status["error_code"] == "ARCHIVE_DOWNLOAD_FAILED"
    assert "path" in created and not Path(created["path"]).exists()


def test_resolution_failure_records_repository_not_found(client, monkeypatch):
    class MissingFetcher:
        def resolve(self, ref, settings):
            raise IngestError("REPO_NOT_FOUND", "Repository was not found or is not public.")

        def download(self, resolved, destination, settings):  # pragma: no cover
            raise AssertionError("download must not be reached")

    monkeypatch.setattr(github, "get_fetcher", lambda: MissingFetcher())
    _, status = run_repo_scan(client, "https://github.com/example/missing")
    assert status["status"] == "failed"
    assert status["error_code"] == "REPO_NOT_FOUND"


def test_repository_with_no_supported_sources_fails_cleanly(client, install_fetcher):
    install_fetcher({"README.md": "# nothing to analyse\n", "data.json": "{}"})
    _, status = run_repo_scan(client, "https://github.com/example/docs-only")
    assert status["status"] == "failed"
    assert status["error_code"] == "EMPTY_SOURCE"


def test_malformed_repo_url_is_rejected_before_a_scan_is_created(client):
    response = client.post("/api/scans", json={"repo_url": "https://gitlab.com/a/b"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REPO_URL"


def test_fixture_and_repo_url_together_are_ambiguous(client):
    response = client.post(
        "/api/scans",
        json={"fixture": "benign_calculator", "repo_url": "https://github.com/a/b"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "AMBIGUOUS_SOURCE"


def test_both_source_kinds_are_advertised(client):
    body = client.get("/healthz").json()
    assert {"benign_js_calculator", "malicious_ts_exfil_server"} <= set(body["fixtures"])
