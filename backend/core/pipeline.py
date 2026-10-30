"""Scan orchestration.

Stage order matches docs/PLAN.md. Every stage persists the scan so the API
can report progress, and a failure in one file degrades the report instead
of crashing the scan.
"""

from __future__ import annotations

from backend.config import settings
from backend.core import correlate, discover, ingest, static_analysis
from backend.core.dataflow import scan_flows
from backend.core.ingest import IngestError
from backend.llm.null import NullProvider
from backend.models import Scan
from backend import storage

_PROVIDERS = {"null": NullProvider()}


def _provider():
    return _PROVIDERS.get(settings.llm_provider, NullProvider())


def execute(scan_id: str) -> None:
    """Run a scan end to end. Never raises: failures are recorded on the scan."""
    scan = storage.load(scan_id)
    if scan is None:
        return

    try:
        _run(scan)
        scan.status = "complete"
        scan.stage = "complete"
    except IngestError as error:
        scan.status = "failed"
        scan.stage = "ingest"
        scan.error = f"{error.code}: {error.message}"
    except Exception as error:  # pragma: no cover - defensive
        scan.status = "failed"
        scan.error = f"INTERNAL: {error}"
    finally:
        scan.finished_at = storage.utc_now()
        storage.save(scan)


def _run(scan: Scan) -> None:
    scan.status = "running"

    scan.stage = "ingest"
    storage.save(scan)
    source = ingest.open_fixture(scan.source, settings)
    scan.files_scanned = len(source.files)

    scan.stage = "discover"
    storage.save(scan)

    tools = []
    capability_raw: list[dict] = []
    flow_raw: list[dict] = []

    for path in source.files:
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = static_analysis.relative_path(path, source.root)
        tree, lines = static_analysis.parse_source(relative, text)
        if tree is None:
            continue

        context = static_analysis.AnalysisContext(path=relative, source=text, lines=lines)
        tools.extend(discover.discover_tools(context, tree))

        scan.stage = "analyze"
        capability_raw.extend(static_analysis.scan_capabilities(context, tree))
        flow_raw.extend(scan_flows(context, tree))
        scan.evidence.extend(context.evidence)

    scan.tools = tools

    scan.stage = "correlate"
    storage.save(scan)

    findings = correlate.correlate(capability_raw, flow_raw)
    scan.findings = findings
    scan.risk = correlate.assess_risk(findings)

    # Claims from the LLM layer are recorded but can never become findings.
    provider = _provider()
    for tool in scan.tools:
        capabilities = sorted(
            {cap for finding in findings for cap in finding.capabilities}
        )
        for claim in provider.analyze_tool(tool, capabilities):
            scan.suppressed_claims.append({"provider": provider.name, **claim})
