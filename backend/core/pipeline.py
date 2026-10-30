"""Scan orchestration.

Stage order matches docs/PLAN.md. Every stage persists the scan so the API can
report real progress, and a failure in one file degrades the report instead of
crashing the scan.
"""

from __future__ import annotations

import time

from backend import storage
from backend.config import settings
from backend.core import (
    correlate,
    discover,
    fileset,
    ingest,
    js_analysis,
    js_discover,
    js_parser,
    static_analysis,
)
from backend.core.dataflow import scan_flows
from backend.core.ingest import IngestError
from backend.llm.null import NullProvider
from backend.models import Scan

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
        scan.error = None
        scan.error_code = None
    except IngestError as error:
        scan.status = "failed"
        scan.error = f"{error.code}: {error.message}"
        scan.error_code = error.code
    except Exception as error:  # pragma: no cover - defensive
        scan.status = "failed"
        scan.error_code = "INTERNAL"
        # Never surface exception text: it can contain absolute temp paths.
        scan.error = f"Internal analysis error ({type(error).__name__})."
    finally:
        scan.finished_at = storage.utc_now()
        storage.save(scan)


def _run(scan: Scan) -> None:
    scan.status = "running"

    scan.stage = "ingest"
    storage.save(scan)

    if scan.source_kind == "fixture":
        source = ingest.open_fixture(scan.source, settings)
    else:
        source = ingest.open_repository(scan.source, settings)

    try:
        scan.commit_sha = source.commit_sha
        scan.metadata = dict(source.metadata)
        scan.metadata["files_discovered"] = len(source.files)
        scan.metadata["source_bytes"] = source.total_bytes
        scan.metadata["skipped_oversized"] = source.skipped_oversized
        scan.files_scanned = len(source.files)

        scan.stage = "discover"
        storage.save(scan)

        _analyze(scan, source)
    finally:
        # Remote sources live in a temp directory; it never outlives the scan
        # and its absolute path is never written to the scan artifact.
        source.cleanup()


def _analyze(scan: Scan, source: ingest.Source) -> None:
    tools = []
    capability_raw: list[dict] = []
    flow_raw: list[dict] = []
    languages: set[str] = set()
    parse_errors = 0
    analyzed = 0
    timed_out = False
    deadline = time.monotonic() + settings.scan_timeout_seconds

    scan.stage = "analyze"
    storage.save(scan)

    for path in source.files:
        if time.monotonic() > deadline:
            timed_out = True
            break

        language = fileset.language_for(path)
        if language is None:
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            parse_errors += 1
            continue

        relative = fileset.relative_path(path, source.root)
        context = static_analysis.AnalysisContext(
            path=relative, source=text, lines=text.splitlines()
        )
        analyzed += 1

        if language == "python":
            tree, _ = static_analysis.parse_source(relative, text)
            if tree is None:
                parse_errors += 1
                continue
            languages.add("python")
            tools.extend(discover.discover_tools(context, tree))
            capability_raw.extend(static_analysis.scan_capabilities(context, tree))
            flow_raw.extend(scan_flows(context, tree))
        else:
            grammar = fileset.grammar_for(path) or "javascript"
            parsed = js_parser.parse(text, grammar)
            if parsed.has_error:
                parse_errors += 1
            languages.add(language)
            resolver = js_analysis.ModuleResolver(parsed)
            capabilities, _ = js_analysis.scan_capabilities(context, parsed, resolver)
            tools.extend(js_discover.discover_tools(context, parsed, language))
            flow_raw.extend(js_analysis.scan_flows(context, parsed, resolver))
            capability_raw.extend(capabilities)

        scan.evidence.extend(context.evidence)

    scan.files_scanned = analyzed
    scan.languages = sorted(languages)
    scan.metadata["languages"] = sorted(languages)
    scan.metadata["parse_errors"] = parse_errors
    scan.metadata["files_analyzed"] = analyzed
    scan.metadata["timed_out"] = timed_out
    scan.metadata["scan_timeout_seconds"] = settings.scan_timeout_seconds

    scan.stage = "correlate"
    storage.save(scan)

    # Capabilities are attributed to a tool only when they occur inside that
    # tool's own handler span. Nothing is inferred from proximity.
    js_analysis.annotate_tool_capabilities(tools, capability_raw)
    scan.tools = tools

    findings = correlate.correlate(capability_raw, flow_raw)
    scan.findings = findings
    scan.risk = correlate.assess_risk(findings)

    # Claims from the LLM layer are recorded but can never become findings.
    provider = _provider()
    for tool in scan.tools:
        capabilities = sorted({cap for finding in findings for cap in finding.capabilities})
        for claim in provider.analyze_tool(tool, capabilities):
            scan.suppressed_claims.append({"provider": provider.name, **claim})
