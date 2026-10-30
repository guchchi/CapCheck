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
    # source kind -> first line where that kind of sensitive data was read.
    # Tracking one line per source keeps two sources at one sink honest: each
    # finding cites the line it actually came from.
    lines: dict[str, int] = field(default_factory=dict)

    @property
    def sources(self) -> set[str]:
        return set(self.lines)

    def merged_with(self, other: "Taint") -> "Taint":
        lines = dict(self.lines)
        for kind, line in other.lines.items():
            lines.setdefault(kind, line)
        return Taint(lines)


def expression_taint(node: ast.AST, env: dict[str, Taint]) -> Taint:
    """Return the taint carried by an expression under the current env."""
    if isinstance(node, ast.Name):
        known = env.get(node.id)
        return Taint(dict(known.lines)) if known else Taint()
    if isinstance(node, ast.Attribute):
        return expression_taint(node.value, env)
    if isinstance(node, ast.Subscript):
        if is_env_access(node):
            return Taint({SOURCE_ENV: node.lineno})
        combined = expression_taint(node.value, env).merged_with(expression_taint(node.slice, env))
        return combined
    if isinstance(node, ast.Call):
        result = Taint()
        # The callee matters: ``open(path).read()`` carries file taint through
        # the receiver, even though ``read`` itself is no longer a file
        # signal. Method calls on a tainted receiver stay tainted.
        result = result.merged_with(expression_taint(node.func, env))
        for child in list(node.args) + [kw.value for kw in node.keywords]:
            result = result.merged_with(expression_taint(child, env))
        if is_env_access(node):
            result.lines.setdefault(SOURCE_ENV, node.lineno)
        elif is_file_read(node):
            result.lines.setdefault(SOURCE_FILE, node.lineno)
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


def _rules_for_flow(sources: set[str], sink_kind: str) -> list[tuple[str, str]]:
    """Return (rule_id, source_kind) for every provable flow at one sink.

    Two sources reaching the same sink produce two findings, each citing its
    own source line. This mirrors the JavaScript analyser so the two languages
    report the same evidence shape.
    """
    rules: list[tuple[str, str]] = []
    if sink_kind == "network":
        if SOURCE_ENV in sources:
            rules.append(("DF_ENV_TO_NETWORK", SOURCE_ENV))
        if SOURCE_FILE in sources:
            rules.append(("DF_FILE_TO_NETWORK", SOURCE_FILE))
    if sink_kind == "subprocess" and SOURCE_ENV in sources:
        rules.append(("DF_ENV_TO_SUBPROCESS", SOURCE_ENV))
    return rules


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
        rules = _rules_for_flow(taint.sources, sink_kind)
        if not rules:
            continue

        for rule_id, source_kind in rules:
            sink_evidence = ctx.add_evidence(node.lineno, rule_id, kind="flow_path")
            evidence_ids = [sink_evidence]
            detail = (
                f"Line {node.lineno}: {ctx.lines[node.lineno - 1].strip()[:160]}"
                if 0 < node.lineno <= len(ctx.lines)
                else f"Line {node.lineno}"
            )
            source_line = taint.lines.get(source_kind)
            if source_line:
                source_evidence = ctx.add_evidence(source_line, rule_id, kind="flow_path")
                evidence_ids.append(source_evidence)
                detail = (
                    f"{_SOURCE_LABEL.get(source_kind, 'sensitive data').capitalize()} "
                    f"read at line {source_line} reaches the sink at line {node.lineno}."
                )
            results.append(
                {
                    "rule_id": rule_id,
                    "path": ctx.path,
                    "line": node.lineno,
                    "source_line": source_line,
                    "sources": [source_kind],
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
                    if taint.lines:
                        env[name] = Taint(dict(taint.lines))
                    else:
                        env.pop(name, None)
        elif isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                taint = expression_taint(statement.value, env)
                for name in _assigned_names(statement.target):
                    if taint.lines:
                        env[name] = Taint(dict(taint.lines))
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
