"""Scan lifecycle endpoints."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, Field

from backend import storage
from backend.api.errors import ApiError
from backend.config import settings
from backend.core import ingest, pipeline
from backend.core.ingest import IngestError
from backend.models import Scan

router = APIRouter(prefix="/api", tags=["scans"])


class ScanRequest(BaseModel):
    fixture: str | None = Field(
        default=None,
        description="Name of a local fixture under fixtures/ (Milestone 1 source).",
    )
    repo_url: str | None = Field(
        default=None,
        description="Remote repository URL. Not implemented in Milestone 1.",
    )


@router.post("/scans", status_code=202)
def create_scan(payload: ScanRequest, background: BackgroundTasks) -> dict:
    if payload.repo_url:
        raise ApiError(
            "REPO_SCAN_NOT_IMPLEMENTED",
            "Remote repository scanning is not part of Milestone 1. "
            "Use the 'fixture' field with a local fixture name.",
            status_code=400,
        )
    if not payload.fixture:
        raise ApiError(
            "MISSING_SOURCE",
            "Provide 'fixture' (local fixture name).",
            status_code=400,
        )

    # Validate synchronously so bad input fails with 4xx, not a failed scan.
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

    return {"scan_id": scan.id, "status": scan.status}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    scan = storage.load(scan_id)
    if scan is None:
        raise ApiError("SCAN_NOT_FOUND", f"No scan with id '{scan_id}'.", status_code=404)

    return {
        "scan_id": scan.id,
        "source": scan.source,
        "status": scan.status,
        "stage": scan.stage,
        "created_at": scan.created_at,
        "finished_at": scan.finished_at,
        "files_scanned": scan.files_scanned,
        "tool_count": len(scan.tools),
        "finding_count": len(scan.findings),
        "critical_count": sum(1 for f in scan.findings if f.severity == "critical"),
        "risk": scan.risk.to_dict() if scan.risk else None,
        "error": scan.error,
    }
