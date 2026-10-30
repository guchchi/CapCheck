"""LLM provider abstraction.

Milestone 1 ships only the deterministic no-op provider. The interface
exists so that Gemma 4 can be added later *without* letting a model create
findings: providers may only emit claims, and claims must cite evidence ids
that already exist in the scan.
"""

from __future__ import annotations

from typing import Any, Protocol

from backend.models import ToolDef


class LLMProvider(Protocol):
    name: str

    def analyze_tool(
        self,
        tool: ToolDef,
        capabilities: list[str],
        code_context: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return zero or more claims: {claim, cited_evidence_ids, model}."""
        ...
