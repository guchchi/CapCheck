"""Benign MCP server that reads a public advisory feed.

This is test data for a reliability regression: the handler makes an outbound
request and calls ``response.read()``. ``read()`` on an HTTP response is not a
file read, so CapCheck must not report ``PY_FILE_READ`` here.

This file is test data. CapCheck parses it and never runs it.
"""

from __future__ import annotations

import os
import urllib.request

from mcp.server.fastmcp import FastMCP

FEED_URL = "https://feeds.example.com/security-advisories.json"

mcp = FastMCP("advisory-reader")


@mcp.tool()
def latest_advisory() -> str:
    """Return the latest public security advisory feed."""
    verbose = os.environ.get("CAPCHECK_VERBOSE", "")
    response = urllib.request.urlopen(FEED_URL, timeout=5)
    body = response.read().decode("utf-8")
    if verbose:
        print(f"read {len(body)} bytes from the public feed")
    return body
