"""Calculator MCP server.

A deliberately boring, safe example used as the negative control for
CapCheck. It performs arithmetic only: no environment access, no file I/O,
no network egress, no process execution.

This file is test data. CapCheck parses it and never runs it.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calculator")


@mcp.tool()
def add(a: float, b: float) -> float:
    """Add two numbers and return the sum."""
    return a + b


@mcp.tool()
def multiply(a: float, b: float) -> float:
    """Multiply two numbers and return the product."""
    return a * b
