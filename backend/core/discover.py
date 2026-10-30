"""Static discovery of MCP tool declarations.

We intentionally do NOT use the official MCP client to enumerate tools:
connecting to a server means running it. Everything here is source parsing.
"""

from __future__ import annotations

import ast

from backend.core.static_analysis import AnalysisContext
from backend.models import ToolDef


def _decorator_name(decorator: ast.AST) -> str | None:
    if isinstance(decorator, ast.Call):
        decorator = decorator.func
    if isinstance(decorator, ast.Attribute):
        return decorator.attr
    if isinstance(decorator, ast.Name):
        return decorator.id
    return None


def _docstring_summary(node: ast.AST) -> str:
    doc = ast.get_docstring(node) or ""
    first_paragraph = doc.strip().split("\n\n")[0].strip()
    return " ".join(first_paragraph.split())[:500]


def _param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = node.args
    names = [arg.arg for arg in args.posonlyargs + args.args]
    if args.vararg:
        names.append("*" + args.vararg.arg)
    names.extend(arg.arg for arg in args.kwonlyargs)
    if args.kwarg:
        names.append("**" + args.kwarg.arg)
    return [name for name in names if name not in {"self", "cls"}]


def discover_tools(ctx: AnalysisContext, tree: ast.Module) -> list[ToolDef]:
    """Find tools declared via decorators or explicit Tool(...) constructors."""
    tools: list[ToolDef] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(_decorator_name(dec) == "tool" for dec in node.decorator_list):
                evidence_id = ctx.add_evidence(node.lineno, "TOOL_DEF", kind="tool_def")
                tools.append(
                    ToolDef(
                        name=node.name,
                        declared_description=_docstring_summary(node),
                        params=_param_names(node),
                        source_file=ctx.path,
                        line=node.lineno,
                        evidence_id=evidence_id,
                        language="python",
                        handler_line=node.lineno,
                        handler_end_line=node.end_lineno,
                    )
                )
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name not in {"Tool", "add_tool"}:
                continue
            tool_name = ""
            description = ""
            for keyword in node.keywords:
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    tool_name = str(keyword.value.value)
                if keyword.arg == "description" and isinstance(keyword.value, ast.Constant):
                    description = str(keyword.value.value)
            if not tool_name:
                continue
            evidence_id = ctx.add_evidence(node.lineno, "TOOL_DEF", kind="tool_def")
            tools.append(
                ToolDef(
                    name=tool_name,
                    declared_description=description,
                    params=[],
                    source_file=ctx.path,
                    line=node.lineno,
                    evidence_id=evidence_id,
                    language="python",
                )
            )

    return tools
