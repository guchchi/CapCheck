"""Scan lifecycle endpoints."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, Field

from backend import storage
from backend.api.errors import ApiError
from backend.config import settings
from backend.core import github, ingest, pipeline
from backend.core.github import InvalidRepoURL
from backend.core.ingest import IngestError
from backend.models import Scan

router = APIRouter(prefix="/api", tags=["scans"])


class ScanRequest(BaseModel):
    fixture: str | None = Field(
        default=None,
        description="Name of a local fixture under fixtures/ (development source).",
    )
    repo_url: str | None = Field(
        default=None,
        description="Public GitHub repository URL, e.g. https://github.com/owner/repo.",
    )


@router.post("/scans", status_code=202)
def create_scan(payload: ScanRequest, background: BackgroundTasks) -> dict:
    if payload.fixture and payload.repo_url:
        raise ApiError(
            "AMBIGUOUS_SOURCE",
            "Provide either 'fixture' or 'repo_url', not both.",
            status_code=400,
        )

    if payload.repo_url:
        # URL shape is validated synchronously so malformed input is a 400,
        # not a failed scan. Network resolution happens in the pipeline.
        try:
            ref = github.parse_repo_url(payload.repo_url)
        except InvalidRepoURL as error:
            raise ApiError("INVALID_REPO_URL", str(error), status_code=400) from error

        scan = Scan(
            id=storage.new_scan_id(),
            source=ref.canonical_url,
            source_kind="github",
            status="queued",
            stage="queued",
            created_at=storage.utc_now(),
        )
        storage.save(scan)
        background.add_task(pipeline.execute, scan.id)
        return {"scan_id": scan.id, "status": scan.status, "source": scan.source}

    if not payload.fixture:
        raise ApiError(
            "MISSING_SOURCE",
            "Provide 'repo_url' (public GitHub URL) or 'fixture' (local fixture name).",
            status_code=400,
        )

    try:
        ingest.open_fixture(payload.fixture, settings)
    except IngestError as error:
        raise ApiError(error.code, error.message, status_code=400) from error

    scan = Scan(
        id=storage.new_scan_id(),
        source=payload.fixture,
        source_kind="fixture",
        status="queued",
        stage="queued",
        created_at=storage.utc_now(),
    )
    storage.save(scan)
    background.add_task(pipeline.execute, scan.id)

    return {"scan_id": scan.id, "status": scan.status, "source": scan.source}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    scan = storage.load(scan_id)
    if scan is None:
        raise ApiError("SCAN_NOT_FOUND", f"No scan with id '{scan_id}'.", status_code=404)

    return {
        "scan_id": scan.id,
        "source": scan.source,
        "source_kind": scan.source_kind,
        "status": scan.status,
        "stage": scan.stage,
        "created_at": scan.created_at,
        "finished_at": scan.finished_at,
        "files_scanned": scan.files_scanned,
        "commit_sha": scan.commit_sha,
        "languages": scan.languages,
        "metadata": scan.metadata,
        "tool_count": len(scan.tools),
        "finding_count": len(scan.findings),
        "critical_count": sum(1 for f in scan.findings if f.severity == "critical"),
        "risk": scan.risk.to_dict() if scan.risk else None,
        "error": scan.error,
        "error_code": scan.error_code,
    }
