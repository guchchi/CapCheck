"""Typed data models shared across the CapCheck pipeline.

Design rule for this module: a Finding may never exist without at least one
Evidence reference. That invariant is validated in ``Scan.to_dict`` and is
enforced by the correlation stage.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
ScanStatus = Literal["queued", "running", "complete", "failed"]
Corroboration = Literal["deterministic", "ai+static"]

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Deterministic weights. Documented in docs/PLAN.md; never model-derived.
SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 55,
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 0,
}


@dataclass
class Evidence:
    """A single traceable artefact behind a finding."""

    id: str
    kind: Literal["file_snippet", "ast_node", "manifest", "tool_def", "flow_path"]
    path: str
    line_start: int | None
    line_end: int | None
    snippet: str
    extractor: str
    file_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolDef:
    """A tool declared by an MCP server, discovered statically."""

    name: str
    declared_description: str
    params: list[str]
    source_file: str
    line: int
    evidence_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StaticFinding:
    """Raw output of a deterministic analyser, before correlation."""

    id: str
    rule_id: str
    category: str
    severity: Severity
    title: str
    description: str
    capabilities: list[str]
    evidence_ids: list[str]
    confidence: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A correlated, evidence-backed finding shown to the user."""

    id: str
    rule_id: str
    category: str
    severity: Severity
    title: str
    summary: str
    capabilities: list[str]
    evidence_ids: list[str]
    ai_claim_ids: list[str]
    corroboration: Corroboration
    confidence: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskItem:
    finding_id: str
    severity: str
    confidence: float
    weight: int
    points: int


@dataclass
class RiskAssessment:
    score: int
    band: Literal["low", "moderate", "high", "critical"]
    method: str
    breakdown: list[RiskItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "method": self.method,
            "breakdown": [asdict(item) for item in self.breakdown],
        }


@dataclass
class Scan:
    id: str
    source: str
    source_kind: Literal["fixture"]
    status: ScanStatus
    stage: str
    created_at: str
    finished_at: str | None = None
    files_scanned: int = 0
    tools: list[ToolDef] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    suppressed_claims: list[dict[str, Any]] = field(default_factory=list)
    risk: RiskAssessment | None = None
    error: str | None = None

    def evidence_by_id(self, evidence_id: str) -> Evidence | None:
        for item in self.evidence:
            if item.id == evidence_id:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "source_kind": self.source_kind,
            "status": self.status,
            "stage": self.stage,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "files_scanned": self.files_scanned,
            "tools": [tool.to_dict() for tool in self.tools],
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "suppressed_claims": self.suppressed_claims,
            "risk": self.risk.to_dict() if self.risk else None,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Scan":
        """Rebuild a Scan from stored JSON."""
        risk_payload = payload.get("risk")
        risk = None
        if risk_payload:
            risk = RiskAssessment(
                score=risk_payload["score"],
                band=risk_payload["band"],
                method=risk_payload["method"],
                breakdown=[RiskItem(**item) for item in risk_payload.get("breakdown", [])],
            )
        return cls(
            id=payload["id"],
            source=payload["source"],
            source_kind=payload["source_kind"],
            status=payload["status"],
            stage=payload["stage"],
            created_at=payload["created_at"],
            finished_at=payload.get("finished_at"),
            files_scanned=payload.get("files_scanned", 0),
            tools=[ToolDef(**item) for item in payload.get("tools", [])],
            findings=[Finding(**item) for item in payload.get("findings", [])],
            evidence=[Evidence(**item) for item in payload.get("evidence", [])],
            suppressed_claims=payload.get("suppressed_claims", []),
            risk=risk,
            error=payload.get("error"),
        )
