"""Static Python analysis built on the ``ast`` module.

Hard safety invariant: this module parses source text only. It never
imports, executes or evaluates the code it inspects.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from backend.models import Evidence
from backend.rules import capabilities as cap
from backend.rules import python_rules

SNIPPET_LIMIT = 400


@dataclass
class AnalysisContext:
    path: str
    source: str
    lines: list[str]
    evidence: list[Evidence] = field(default_factory=list)
    counter: int = 0

    def add_evidence(self, line: int, extractor: str, kind: str = "ast_node") -> str:
        """Record an evidence item and return its id."""
        self.counter += 1
        evidence_id = f"ev_{_short_hash(self.path)}:{self.counter}"
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        if len(snippet) > SNIPPET_LIMIT:
            snippet = snippet[:SNIPPET_LIMIT] + "…"
        self.evidence.append(
            Evidence(
                id=evidence_id,
                kind=kind,  # type: ignore[arg-type]
                path=self.path,
                line_start=line,
                line_end=line,
                snippet=snippet,
                extractor=extractor,
                file_sha256=_sha256(self.source),
            )
        )
        return evidence_id


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _short_hash(text: str) -> str:
    return _sha256(text)[:8]


# --------------------------------------------------------------------------
# Call classification helpers
# --------------------------------------------------------------------------


def _attr_chain(node: ast.AST) -> list[str]:
    """Return the dotted name for Attribute/Name chains, e.g. os.environ.get."""
    chain: list[str] = []
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute):
        chain.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        chain.append(current.id)
    return list(reversed(chain))


def is_env_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Subscript):
        return _attr_chain(node.value) == ["os", "environ"]
    if isinstance(node, ast.Call):
        chain = _attr_chain(node.func)
        if chain in (["os", "environ", "get"], ["os", "environ", "setdefault"]):
            return True
        if chain == ["os", "getenv"]:
            return True
    return False


def is_file_read(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        chain = _attr_chain(node.func)
        if chain and chain[-1] == "open":
            return True
        if chain and chain[-1] in {"read_text", "read_bytes", "readlines", "read"}:
            return True
    return False


def is_file_write(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        chain = _attr_chain(node.func)
        if chain and chain[-1] in {"write_text", "write_bytes"}:
            return True
        if chain and chain[-1] == "open":
            for keyword in node.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                    value = keyword.value.value
                    if isinstance(value, str) and any(flag in value for flag in ("w", "a", "x")):
                        return True
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                value = node.args[1].value
                if isinstance(value, str) and any(flag in value for flag in ("w", "a", "x")):
                    return True
    return False


_NETWORK_MODULES = {"requests", "httpx", "aiohttp", "urllib", "urllib3", "http", "socket"}
_NETWORK_ATTRS = {"post", "put", "get", "patch", "request", "urlopen", "connect", "send"}


def is_network_sink(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    chain = _attr_chain(node.func)
    if not chain:
        return False
    if chain[0] in _NETWORK_MODULES and chain[-1] in _NETWORK_ATTRS:
        return True
    # urllib.request.urlopen(...)
    if len(chain) >= 2 and chain[-2:] in (["request", "urlopen"], ["client", "connect"]):
        return True
    return False


def is_subprocess_sink(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    chain = _attr_chain(node.func)
    if not chain:
        return False
    if chain[0] == "subprocess" and chain[-1] in {"run", "call", "Popen", "check_output", "check_call"}:
        return True
    return chain in (["os", "system"], ["os", "popen"], ["os", "execv"], ["os", "execvp"])


def is_dynamic_exec(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    chain = _attr_chain(node.func)
    # ``__import__`` is a dynamic import, not dynamic execution; flagging it
    # as code execution overstated severity on ordinary test helpers.
    return chain in (["exec"], ["eval"], ["compile"])


# --------------------------------------------------------------------------
# Capability pass
# --------------------------------------------------------------------------


def scan_capabilities(ctx: AnalysisContext, tree: ast.Module) -> list[dict]:
    """Walk the AST once and collect capability observations with evidence."""
    found: list[dict] = []
    for node in ast.walk(tree):
        rule_id: str | None = None
        if isinstance(node, ast.Call):
            if is_env_access(node):
                rule_id = "PY_ENV_ACCESS"
            elif is_dynamic_exec(node):
                rule_id = "PY_DYNAMIC_EXEC"
            elif is_subprocess_sink(node):
                rule_id = "PY_SUBPROCESS"
            elif is_network_sink(node):
                rule_id = "PY_NETWORK_EGRESS"
            elif is_file_write(node):
                rule_id = "PY_FILE_WRITE"
            elif is_file_read(node):
                rule_id = "PY_FILE_READ"
        elif isinstance(node, ast.Subscript) and is_env_access(node):
            rule_id = "PY_ENV_ACCESS"

        if rule_id is None:
            continue
        rule = python_rules.get(rule_id)
        evidence_id = ctx.add_evidence(node.lineno, rule_id)
        found.append(
            {
                "rule_id": rule_id,
                "path": ctx.path,
                "line": node.lineno,
                "evidence_id": evidence_id,
                "capabilities": list(rule.capabilities),
            }
        )
    return found


def parse_source(path: str, source: str) -> tuple[ast.Module | None, list[str]]:
    lines = source.splitlines()
    try:
        return ast.parse(source, filename=path), lines
    except SyntaxError:
        return None, lines


def collect_python_files(root: Path, max_files: int, max_file_bytes: int) -> list[Path]:
    """Enumerate Python files under ``root`` with hard caps.

    Symlinks that resolve outside the root are skipped; binaries and
    oversized files are ignored.
    """
    resolved_root = root.resolve()
    results: list[Path] = []
    for candidate in sorted(root.rglob("*.py")):
        if len(results) >= max_files:
            break
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not str(resolved).startswith(str(resolved_root)):
            continue
        try:
            if not candidate.is_file() or candidate.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        results.append(candidate)
    return results


def relative_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()
