"""Lightweight intra-procedural data-flow analysis.

Scope and honesty: this tracks taint from a *sensitive source* (environment
variable, file contents) into a *sink* (network call, subprocess call) inside
one function or module body. It does not follow interprocedural flows, class
attributes, or dynamic dispatch. That limitation is documented rather than
hidden.

Parsing only. Nothing here executes repository code.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from backend.core.static_analysis import (
    AnalysisContext,
    is_env_access,
    is_file_read,
    is_network_sink,
    is_subprocess_sink,
)

SOURCE_ENV = "ENV"
SOURCE_FILE = "FILE"

_SOURCE_LABEL = {
    SOURCE_ENV: "environment variable",
    SOURCE_FILE: "file contents",
}


@dataclass
class Taint:
    sources: set[str] = field(default_factory=set)
    line: int | None = None

    def merged_with(self, other: "Taint") -> "Taint":
        return Taint(self.sources | other.sources, self.line or other.line)


def expression_taint(node: ast.AST, env: dict[str, Taint]) -> Taint:
    """Return the taint carried by an expression under the current env."""
    if isinstance(node, ast.Name):
        known = env.get(node.id)
        return Taint(set(known.sources), known.line) if known else Taint()
    if isinstance(node, ast.Attribute):
        return expression_taint(node.value, env)
    if isinstance(node, ast.Subscript):
        if is_env_access(node):
            return Taint({SOURCE_ENV}, node.lineno)
        combined = expression_taint(node.value, env).merged_with(expression_taint(node.slice, env))
        return combined
    if isinstance(node, ast.Call):
        result = Taint()
        for child in list(node.args) + [kw.value for kw in node.keywords]:
            result = result.merged_with(expression_taint(child, env))
        if is_env_access(node):
            result.sources.add(SOURCE_ENV)
            result.line = result.line or node.lineno
        elif is_file_read(node):
            result.sources.add(SOURCE_FILE)
            result.line = result.line or node.lineno
        return result
    if isinstance(node, ast.Dict):
        result = Taint()
        for key, value in zip(node.keys, node.values):
            if key is not None:
                result = result.merged_with(expression_taint(key, env))
            result = result.merged_with(expression_taint(value, env))
        return result
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        result = Taint()
        for element in node.elts:
            result = result.merged_with(expression_taint(element, env))
        return result
    if isinstance(node, ast.JoinedStr):
        result = Taint()
        for value in node.values:
            result = result.merged_with(expression_taint(value, env))
        return result
    if isinstance(node, ast.FormattedValue):
        return expression_taint(node.value, env)
    if isinstance(node, ast.BinOp):
        return expression_taint(node.left, env).merged_with(expression_taint(node.right, env))
    if isinstance(node, ast.Compare):
        result = expression_taint(node.left, env)
        for comparator in node.comparators:
            result = result.merged_with(expression_taint(comparator, env))
        return result
    if isinstance(node, ast.IfExp):
        return (
            expression_taint(node.body, env)
            .merged_with(expression_taint(node.orelse, env))
            .merged_with(expression_taint(node.test, env))
        )
    if isinstance(node, ast.Await):
        return expression_taint(node.value, env)
    if isinstance(node, ast.Starred):
        return expression_taint(node.value, env)
    if isinstance(node, ast.BoolOp):
        result = Taint()
        for value in node.values:
            result = result.merged_with(expression_taint(value, env))
        return result
    return Taint()


def _assigned_names(target: ast.AST) -> list[str]:
    names: list[str] = []
    for node in ast.walk(target):
        if isinstance(node, ast.Name):
            names.append(node.id)
    return names


def _rule_for_flow(sources: set[str], sink_kind: str) -> str | None:
    if sink_kind == "network":
        if SOURCE_ENV in sources:
            return "DF_ENV_TO_NETWORK"
        if SOURCE_FILE in sources:
            return "DF_FILE_TO_NETWORK"
    if sink_kind == "subprocess" and SOURCE_ENV in sources:
        return "DF_ENV_TO_SUBPROCESS"
    return None


def _check_sinks(
    statement: ast.stmt,
    env: dict[str, Taint],
    ctx: AnalysisContext,
    results: list[dict],
    seen: set[int],
) -> None:
    for node in ast.walk(statement):
        if id(node) in seen:
            continue
        sink_kind: str | None = None
        if is_network_sink(node):
            sink_kind = "network"
        elif is_subprocess_sink(node):
            sink_kind = "subprocess"
        if sink_kind is None:
            continue
        seen.add(id(node))

        taint = expression_taint(node, env)
        rule_id = _rule_for_flow(taint.sources, sink_kind)
        if rule_id is None:
            continue

        sink_evidence = ctx.add_evidence(node.lineno, rule_id, kind="flow_path")
        evidence_ids = [sink_evidence]
        detail = (
            f"Line {node.lineno}: {ctx.lines[node.lineno - 1].strip()[:160]}"
            if 0 < node.lineno <= len(ctx.lines)
            else f"Line {node.lineno}"
        )
        if taint.line:
            source_evidence = ctx.add_evidence(taint.line, rule_id, kind="flow_path")
            evidence_ids.append(source_evidence)
            detail = (
                f"{_SOURCE_LABEL.get(sorted(taint.sources)[0], 'sensitive data')} "
                f"read at line {taint.line} reaches the sink at line {node.lineno}."
            )
        results.append(
            {
                "rule_id": rule_id,
                "path": ctx.path,
                "line": node.lineno,
                "source_line": taint.line,
                "sources": sorted(taint.sources),
                "evidence_ids": evidence_ids,
                "detail": detail,
            }
        )


def _statement_lists(statement: ast.stmt) -> list[list[ast.stmt]]:
    lists: list[list[ast.stmt]] = []
    for attr in ("body", "orelse", "finalbody"):
        value = getattr(statement, attr, None)
        if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
            lists.append(value)
    for handler in getattr(statement, "handlers", []) or []:
        if isinstance(handler, ast.ExceptHandler):
            lists.append(handler.body)
    return lists


def _visit_statements(
    statements: list[ast.stmt],
    env: dict[str, Taint],
    ctx: AnalysisContext,
    results: list[dict],
    seen: set[int],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Nested scopes get their own env; do not leak locals upward.
            continue

        if isinstance(statement, ast.Assign):
            taint = expression_taint(statement.value, env)
            for target in statement.targets:
                for name in _assigned_names(target):
                    if taint.sources:
                        env[name] = Taint(set(taint.sources), taint.line)
                    else:
                        env.pop(name, None)
        elif isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                taint = expression_taint(statement.value, env)
                for name in _assigned_names(statement.target):
                    if taint.sources:
                        env[name] = Taint(set(taint.sources), taint.line)
                    else:
                        env.pop(name, None)
        elif isinstance(statement, ast.AugAssign):
            taint = expression_taint(statement.value, env)
            for name in _assigned_names(statement.target):
                existing = env.get(name, Taint())
                merged = existing.merged_with(taint)
                if merged.sources:
                    env[name] = merged

        _check_sinks(statement, env, ctx, results, seen)

        for block in _statement_lists(statement):
            branch_env = dict(env)
            _visit_statements(block, branch_env, ctx, results, seen)
            for name, taint in branch_env.items():
                existing = env.get(name)
                env[name] = taint if existing is None else existing.merged_with(taint)


def scan_flows(ctx: AnalysisContext, tree: ast.Module) -> list[dict]:
    """Detect sensitive-source-to-sink flows in a parsed module."""
    results: list[dict] = []
    seen: set[int] = set()

    module_env: dict[str, Taint] = {}
    _visit_statements(tree.body, module_env, ctx, results, seen)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local_env = dict(module_env)
            _visit_statements(node.body, local_env, ctx, results, seen)

    return results
