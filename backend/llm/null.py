"""Deterministic no-op provider.

Returns no claims. This is the default so the scanner is fully functional
without any model endpoint, and so the demo can never die because a model
is unavailable.
"""

from __future__ import annotations

from typing import Any

from backend.models import ToolDef


class NullProvider:
    name = "null"

    def analyze_tool(self, tool: ToolDef, capabilities: list[str]) -> list[dict[str, Any]]:
        return []
