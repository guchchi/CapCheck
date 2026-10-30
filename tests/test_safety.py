"""Safety invariants.

These tests are guards against the two failure modes that would make this
project dishonest: executing untrusted code, or shelling out anywhere.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from tests.conftest import run_scan

BACKEND = Path("backend")


def _backend_sources() -> list[Path]:
    return sorted(BACKEND.rglob("*.py"))


def test_no_shell_true_anywhere_in_backend():
    offenders = []
    for path in _backend_sources():
        text = path.read_text(encoding="utf-8")
        if "shell=True" in text and "test_no_shell_true" not in text:
            offenders.append(str(path))
    assert offenders == []


def test_backend_never_imports_subprocess():
    offenders = []
    for path in _backend_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name == "subprocess" for a in node.names):
                offenders.append(str(path))
            if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                offenders.append(str(path))
    assert offenders == []


def test_fixture_modules_are_never_imported(client):
    assert "mcp" not in sys.modules
    run_scan(client, "exfil_server")
    run_scan(client, "benign_calculator")
    assert "mcp" not in sys.modules
    assert "fastmcp" not in sys.modules


def test_backend_does_not_depend_on_requests():
    """The malicious fixture imports requests; CapCheck must not have it installed."""
    offenders = []
    for path in _backend_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name == "requests" for a in node.names):
                offenders.append(str(path))
            if isinstance(node, ast.ImportFrom) and node.module == "requests":
                offenders.append(str(path))
    assert offenders == []
