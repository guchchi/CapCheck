"""Read endpoints for findings, evidence and discovered tools."""

from __future__ import annotations

from fastapi import APIRouter

from backend import storage
from backend.api.errors import ApiError
from backend.models import Scan

router = APIRouter(prefix="/api", tags=["report"])


def _require_scan(scan_id: str) -> Scan:
    scan = storage.load(scan_id)
    if scan is None:
        raise ApiError("SCAN_NOT_FOUND", f"No scan with id '{scan_id}'.", status_code=404)
    return scan


@router.get("/scans/{scan_id}/findings")
def get_findings(scan_id: str) -> dict:
    scan = _require_scan(scan_id)
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "count": len(scan.findings),
        "findings": [finding.to_dict() for finding in scan.findings],
    }


@router.get("/scans/{scan_id}/tools")
def get_tools(scan_id: str) -> dict:
    scan = _require_scan(scan_id)
    return {
        "scan_id": scan.id,
        "count": len(scan.tools),
        "tools": [tool.to_dict() for tool in scan.tools],
    }


@router.get("/scans/{scan_id}/evidence/{evidence_id}")
def get_evidence(scan_id: str, evidence_id: str) -> dict:
    scan = _require_scan(scan_id)
    evidence = scan.evidence_by_id(evidence_id)
    if evidence is None:
        raise ApiError(
            "EVIDENCE_NOT_FOUND",
            f"No evidence '{evidence_id}' in scan '{scan_id}'.",
            status_code=404,
        )
    return evidence.to_dict()


@router.get("/scans/{scan_id}/claims")
def get_claims(scan_id: str) -> dict:
    scan = _require_scan(scan_id)
    return {
        "scan_id": scan.id,
        "count": len(scan.suppressed_claims),
        "claims": scan.suppressed_claims,
    }
