"""Static JavaScript/TypeScript analysis: capabilities and taint flows.

Parsing only. Nothing in this module imports, evaluates or executes repository
code; ``eval`` and ``Function`` appear here exclusively as *node names we look
for*, never as calls we make.

Scope honesty: the flow analysis is intra-procedural. It tracks taint through
local assignments, object/array literals, template strings and call arguments
inside one function body. It does not follow values across function calls,
class fields, module re-exports or dynamic property access. When it cannot
prove a path, it produces no finding rather than a guessed one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from tree_sitter import Node

from backend.core.js_parser import ParsedSource
from backend.core.static_analysis import AnalysisContext
from backend.rules import capabilities as cap
from backend.rules import javascript_rules

FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "generator_function",
        "generator_function_declaration",
    }
)

FS_MODULES = frozenset({"fs", "node:fs", "fs/promises", "node:fs/promises"})
CP_MODULES = frozenset({"child_process", "node:child_process"})
HTTP_MODULES = frozenset({"http", "node:http", "https", "node:https"})

FS_READ_FUNCS = frozenset(
    {"readFileSync", "readFile", "createReadStream", "openSync", "open", "readSync"}
)
CP_FUNCS = frozenset(
    {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
)
HTTP_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request"}
)

# Credential-shaped paths. Matching these is a capability signal, never a
# verdict on its own.
SENSITIVE_PATH_RE = re.compile(
    r"(\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]|\.npmrc|\.netrc|\.pypirc|"
    r"\.git-credentials|\.docker[/\\]config|kube[/\\]config|\.gnupg|"
    r"(^|[/\\])\.env(\.|$))",
    re.IGNORECASE,
)

SOURCE_ENV = "ENV"
SOURCE_FILE = "FILE"

_SOURCE_LABEL = {
    SOURCE_ENV: "environment variable",
    SOURCE_FILE: "file contents",
}


# --------------------------------------------------------------------------
# Module / import resolution
# --------------------------------------------------------------------------


def _normalise_module(name: str) -> str:
    name = name.removeprefix("node:")
    if name.startswith("fs/"):
        return "fs"
    return name


def _string_value(parsed: ParsedSource, node: Node | None) -> str | None:
    if node is None or node.type != "string":
        return None
    raw = parsed.text(node)
    if len(raw) < 2:
        return None
    quote = raw[0]
    if quote not in {'"', "'"} or raw[-1] != quote:
        return None
    return raw[1:-1]


class ModuleResolver:
    """Maps local identifiers to the module members they were imported from.

    Without this, ``readFileSync(...)`` after ``import { readFileSync } from
    "fs"`` would be invisible, and aliasing would defeat every detector.
    """

    def __init__(self, parsed: ParsedSource) -> None:
        self.parsed = parsed
        self.namespaces: dict[str, str] = {}
        self.members: dict[str, str] = {}
        self._build()

    def text(self, node: Node | None) -> str:
        return self.parsed.text(node)

    def _require_module(self, node: Node | None) -> str | None:
        if node is None or node.type != "call_expression":
            return None
        callee = node.child_by_field_name("function")
        if self.text(callee) != "require":
            return None
        args = node.child_by_field_name("arguments")
        if args is None:
            return None
        for child in args.named_children:
            value = _string_value(self.parsed, child)
            if value is not None:
                return _normalise_module(value)
        return None

    def _build(self) -> None:
        for node in _walk_all(self.parsed.tree.root_node):
            if node.type == "import_statement":
                self._read_import(node)
            elif node.type == "variable_declarator":
                self._read_require_binding(node)

    def _read_import(self, node: Node) -> None:
        module_node = node.child_by_field_name("source")
        module = _string_value(self.parsed, module_node)
        if module is None:
            return
        module = _normalise_module(module)
        # ``import_clause`` is the child's node type; the grammar does not
        # expose it as a named field.
        clause = next(
            (child for child in node.named_children if child.type == "import_clause"),
            None,
        )
        if clause is None:
            return

        for child in clause.named_children:
            if child.type == "namespace_import":
                for ident in child.named_children:
                    if ident.type == "identifier":
                        self.namespaces[self.text(ident)] = module
            elif child.type == "identifier":
                # default import: import axios from "axios"
                self.namespaces[self.text(child)] = module
            elif child.type == "named_imports":
                for spec in child.named_children:
                    if spec.type != "import_specifier":
                        continue
                    idents = [c for c in spec.named_children if c.type == "identifier"]
                    if not idents:
                        continue
                    original = self.text(idents[0])
                    local = self.text(idents[-1])
                    self.members[local] = f"{module}.{original}"

    def _read_require_binding(self, node: Node) -> None:
        value = node.child_by_field_name("value")
        module = self._require_module(value)
        if module is None:
            return
        name = node.child_by_field_name("name")
        if name is None:
            return
        if name.type == "identifier":
            self.namespaces[self.text(name)] = module
        elif name.type == "object_pattern":
            for local, original in _pattern_pairs(self.parsed, name):
                self.members[local] = f"{module}.{original}"

    def module_of(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type == "identifier":
            return self.namespaces.get(self.text(node))
        if node.type == "member_expression":
            base = self.module_of(node.child_by_field_name("object"))
            prop = self.text(node.child_by_field_name("property"))
            if base == "fs" and prop == "promises":
                return "fs"
            return None
        if node.type == "call_expression":
            return self._require_module(node)
        return None

    def canonical(self, node: Node | None) -> str | None:
        """Return ``module.member`` for a callee, resolving aliases."""
        if node is None:
            return None
        if node.type == "identifier":
            name = self.text(node)
            return self.members.get(name, name)
        if node.type == "member_expression":
            base = self.module_of(node.child_by_field_name("object"))
            prop = self.text(node.child_by_field_name("property"))
            if base:
                return f"{base}.{prop}"
            return None
        if node.type == "call_expression":
            return self._require_module(node)
        return None


def _walk_all(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _walk_no_functions(node: Node) -> Iterator[Node]:
    """Walk descendants without entering nested function bodies."""
    stack = list(reversed(node.named_children))
    while stack:
        current = stack.pop()
        yield current
        if current.type in FUNCTION_TYPES:
            continue
        stack.extend(reversed(current.named_children))


def _pattern_pairs(parsed: ParsedSource, pattern: Node) -> Iterator[tuple[str, str]]:
    """Yield (local_name, property_name) pairs from a destructuring pattern."""
    for child in pattern.named_children:
        if child.type == "shorthand_property_identifier_pattern":
            name = parsed.text(child)
            yield name, name
        elif child.type == "pair_pattern":
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            if key is not None and value is not None and value.type == "identifier":
                yield parsed.text(value), parsed.text(key)
        elif child.type == "object_assignment_pattern":
            left = child.child_by_field_name("left")
            if left is not None and left.type in {
                "identifier",
                "shorthand_property_identifier_pattern",
            }:
                name = parsed.text(left)
                yield name, name


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def is_env_access(parsed: ParsedSource, node: Node) -> bool:
    text = parsed.text

    if node.type == "member_expression":
        if text(node) == "process.env":
            parent = node.parent
            if (
                parent is not None
                and parent.type in {"member_expression", "subscript_expression"}
                and parent.child_by_field_name("object") is not None
                and parent.child_by_field_name("object").id == node.id
            ):
                # The outer expression (`process.env.KEY`) is the read anchor.
                return False
            return True
        obj = node.child_by_field_name("object")
        return obj is not None and text(obj) == "process.env"

    if node.type == "subscript_expression":
        obj = node.child_by_field_name("object")
        return obj is not None and text(obj) == "process.env"

    return False


def is_file_read(resolver: ModuleResolver, node: Node) -> bool:
    if node.type != "call_expression":
        return False
    canonical = resolver.canonical(node.child_by_field_name("function"))
    return canonical in {f"fs.{name}" for name in FS_READ_FUNCS}


def is_network_sink(resolver: ModuleResolver, node: Node) -> bool:
    if node.type != "call_expression":
        return False
    canonical = resolver.canonical(node.child_by_field_name("function"))
    if canonical is None:
        return False
    if canonical == "fetch":
        return True
    if canonical == "axios":
        return True
    if canonical.startswith("axios.") and canonical.split(".", 1)[1] in HTTP_METHODS:
        return True
    if canonical in {"http.request", "http.get", "https.request", "https.get"}:
        return True
    return False


def is_subprocess_sink(resolver: ModuleResolver, node: Node) -> bool:
    if node.type != "call_expression":
        return False
    canonical = resolver.canonical(node.child_by_field_name("function"))
    if canonical is None:
        return False
    return any(canonical == f"child_process.{name}" for name in CP_FUNCS)


def is_dynamic_exec(resolver: ModuleResolver, node: Node) -> bool:
    if node.type == "call_expression":
        return resolver.canonical(node.child_by_field_name("function")) == "eval"
    if node.type == "new_expression":
        constructor = node.child_by_field_name("constructor")
        if constructor is None and node.named_children:
            constructor = node.named_children[0]
        return resolver.parsed.text(constructor) in {"Function", "AsyncFunction"}
    return False


def _sensitive_path(parsed: ParsedSource, call: Node) -> tuple[str, Node] | None:
    """Return the first credential-shaped path literal in a call's args.

    Both plain strings and template literals are inspected; ``readFileSync(
    `${process.env.HOME}/.aws/credentials`)`` is a real credential read.
    """
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    for node in _walk_no_functions(args):
        if node.type not in {"string", "template_string"}:
            continue
        raw = parsed.text(node)
        if SENSITIVE_PATH_RE.search(raw):
            return raw, node
    return None


# --------------------------------------------------------------------------
# Capability pass
# --------------------------------------------------------------------------


def scan_capabilities(
    ctx: AnalysisContext, parsed: ParsedSource, resolver: ModuleResolver
) -> tuple[list[dict], list[dict]]:
    """Return (capability observations, attribution observations).

    Both lists share the same shape as the Python analyser so ``correlate()``
    needs no language-specific branch. The second list is identical but is
    kept separate to make per-tool attribution explicit.
    """
    found: list[dict] = []

    for node in _walk_all(parsed.tree.root_node):
        rule_id: str | None = None

        if is_env_access(parsed, node):
            rule_id = "JS_ENV_ACCESS"
        elif is_dynamic_exec(resolver, node):
            rule_id = "JS_DYNAMIC_EXEC"
        elif is_subprocess_sink(resolver, node):
            rule_id = "JS_SUBPROCESS"
        elif is_network_sink(resolver, node):
            rule_id = "JS_NETWORK_EGRESS"
        elif is_file_read(resolver, node):
            rule_id = "JS_FILE_READ"

        if rule_id is None:
            continue

        rule = javascript_rules.get(rule_id)
        evidence_id = ctx.add_evidence(parsed.line(node), rule_id)
        found.append(
            {
                "rule_id": rule_id,
                "path": ctx.path,
                "line": parsed.line(node),
                "evidence_id": evidence_id,
                "capabilities": list(rule.capabilities),
            }
        )

    # Sensitive credential paths get their own medium-severity observation.
    for node in _walk_all(parsed.tree.root_node):
        if not is_file_read(resolver, node):
            continue
        match = _sensitive_path(parsed, node)
        if match is None:
            continue
        _, string_node = match
        rule = javascript_rules.get("JS_SENSITIVE_PATH_READ")
        evidence_id = ctx.add_evidence(parsed.line(string_node), "JS_SENSITIVE_PATH_READ")
        found.append(
            {
                "rule_id": "JS_SENSITIVE_PATH_READ",
                "path": ctx.path,
                "line": parsed.line(string_node),
                "evidence_id": evidence_id,
                "capabilities": list(rule.capabilities),
            }
        )

    return found, [dict(item) for item in found]


# --------------------------------------------------------------------------
# Intra-procedural taint
# --------------------------------------------------------------------------


@dataclass
class Taint:
    # source kind -> first line where that kind of sensitive data was read
    lines: dict[str, int] = field(default_factory=dict)

    @property
    def sources(self) -> set[str]:
        return set(self.lines)

    def merged_with(self, other: "Taint") -> "Taint":
        lines = dict(self.lines)
        for kind, line in other.lines.items():
            lines.setdefault(kind, line)
        return Taint(lines)


def expression_taint(
    parsed: ParsedSource, resolver: ModuleResolver, node: Node | None, env: dict[str, Taint]
) -> Taint:
    if node is None:
        return Taint()

    if node.type in {
        "identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
    }:
        known = env.get(parsed.text(node))
        return Taint(dict(known.lines)) if known else Taint()

    result = Taint()
    if is_env_access(parsed, node):
        result.lines.setdefault(SOURCE_ENV, parsed.line(node))
    elif is_file_read(resolver, node):
        result.lines.setdefault(SOURCE_FILE, parsed.line(node))

    for child in node.named_children:
        if child.type in FUNCTION_TYPES:
            continue
        result = result.merged_with(expression_taint(parsed, resolver, child, env))
    return result


def _assigned_names(parsed: ParsedSource, pattern: Node | None) -> list[str]:
    if pattern is None:
        return []
    if pattern.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return [parsed.text(pattern)]
    if pattern.type == "object_pattern":
        names: list[str] = []
        for child in pattern.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                names.append(parsed.text(child))
            elif child.type == "pair_pattern":
                names.extend(_assigned_names(parsed, child.child_by_field_name("value")))
            elif child.type == "object_assignment_pattern":
                names.extend(_assigned_names(parsed, child.child_by_field_name("left")))
            elif child.type == "rest_pattern":
                names.extend(_assigned_names(parsed, child.named_children[-1] if child.named_children else None))
        return names
    if pattern.type == "array_pattern":
        names = []
        for child in pattern.named_children:
            if child.type == "assignment_pattern":
                names.extend(_assigned_names(parsed, child.child_by_field_name("left")))
            else:
                names.extend(_assigned_names(parsed, child))
        return names
    if pattern.type == "assignment_pattern":
        return _assigned_names(parsed, pattern.child_by_field_name("left"))
    return []


def _bindings(parsed: ParsedSource, statement: Node) -> Iterator[tuple[Node | None, Node | None]]:
    if statement.type in {"lexical_declaration", "variable_declaration"}:
        for child in statement.named_children:
            if child.type == "variable_declarator":
                yield child.child_by_field_name("name"), child.child_by_field_name("value")
        return
    if statement.type == "expression_statement" and statement.named_children:
        expr = statement.named_children[0]
        if expr.type == "assignment_expression":
            yield expr.child_by_field_name("left"), expr.child_by_field_name("right")


def _rules_for_flow(sources: set[str], sink_kind: str) -> list[tuple[str, str]]:
    """Return (rule_id, source_kind) for every provable flow at one sink.

    Two sources reaching one sink produce two findings: each cites its own
    source line, so neither finding can point at the wrong line.
    """
    rules: list[tuple[str, str]] = []
    if sink_kind == "network":
        if SOURCE_ENV in sources:
            rules.append(("JS_ENV_TO_NETWORK", SOURCE_ENV))
        if SOURCE_FILE in sources:
            rules.append(("JS_FILE_TO_NETWORK", SOURCE_FILE))
    if sink_kind == "subprocess" and SOURCE_ENV in sources:
        rules.append(("JS_ENV_TO_SUBPROCESS", SOURCE_ENV))
    return rules


def _sink_kind(resolver: ModuleResolver, node: Node) -> str | None:
    if is_network_sink(resolver, node):
        return "network"
    if is_subprocess_sink(resolver, node):
        return "subprocess"
    return None


def _check_sinks(
    parsed: ParsedSource,
    resolver: ModuleResolver,
    statement: Node,
    env: dict[str, Taint],
    ctx: AnalysisContext,
    results: list[dict],
    seen: set[int],
) -> None:
    for node in _walk_no_functions(statement):
        kind = _sink_kind(resolver, node)
        if kind is None or node.id in seen:
            continue
        seen.add(node.id)

        taint = expression_taint(parsed, resolver, node, env)
        rules = _rules_for_flow(taint.sources, kind)
        if not rules:
            continue

        sink_line = parsed.line(node)
        for rule_id, source_kind in rules:
            sink_evidence = ctx.add_evidence(sink_line, rule_id, kind="flow_path")
            evidence_ids = [sink_evidence]
            source_label = _SOURCE_LABEL.get(source_kind, "sensitive data")
            source_line = taint.lines.get(source_kind)
            detail = f"Sink at line {sink_line}: {parsed.lines[sink_line - 1].strip()[:160]}"

            if source_line:
                source_evidence = ctx.add_evidence(source_line, rule_id, kind="flow_path")
                evidence_ids.append(source_evidence)
                detail = (
                    f"{source_label.capitalize()} read at line {source_line} reaches the "
                    f"{kind} sink at line {sink_line}."
                )

            results.append(
                {
                    "rule_id": rule_id,
                    "path": ctx.path,
                    "line": sink_line,
                    "source_line": source_line,
                    "sources": [source_kind],
                    "evidence_ids": evidence_ids,
                    "detail": detail,
                }
            )


def _statement_blocks(statement: Node) -> list[list[Node]]:
    blocks: list[list[Node]] = []

    def add(node: Node | None) -> None:
        if node is None:
            return
        if node.type == "statement_block":
            blocks.append(list(node.named_children))
        else:
            blocks.append([node])

    if statement.type == "if_statement":
        add(statement.child_by_field_name("consequence"))
        add(statement.child_by_field_name("alternative"))
    elif statement.type in {
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "labeled_statement",
    }:
        add(statement.child_by_field_name("body"))
    elif statement.type == "try_statement":
        add(statement.child_by_field_name("body"))
        add(statement.child_by_field_name("finalizer"))
        for child in statement.named_children:
            if child.type == "catch_clause":
                add(child.child_by_field_name("body"))
    elif statement.type == "switch_statement":
        body = statement.child_by_field_name("body")
        if body is not None:
            for case in body.named_children:
                if case.type in {"switch_case", "switch_default"}:
                    blocks.append(list(case.named_children))
    elif statement.type == "statement_block":
        blocks.append(list(statement.named_children))
    return blocks


def _visit_statements(
    parsed: ParsedSource,
    resolver: ModuleResolver,
    statements: Iterable[Node],
    env: dict[str, Taint],
    ctx: AnalysisContext,
    results: list[dict],
    seen: set[int],
) -> None:
    for statement in statements:
        if statement.type in FUNCTION_TYPES or statement.type in {
            "class_declaration",
            "class",
        }:
            continue

        for name_node, value_node in _bindings(parsed, statement):
            if name_node is None:
                continue
            taint = (
                expression_taint(parsed, resolver, value_node, env)
                if value_node is not None
                else Taint()
            )
            for name in _assigned_names(parsed, name_node):
                if taint.lines:
                    env[name] = Taint(dict(taint.lines))
                else:
                    env.pop(name, None)

        _check_sinks(parsed, resolver, statement, env, ctx, results, seen)

        for block in _statement_blocks(statement):
            branch_env = dict(env)
            _visit_statements(
                parsed, resolver, block, branch_env, ctx, results, seen
            )
            for name, taint in branch_env.items():
                existing = env.get(name)
                env[name] = taint if existing is None else existing.merged_with(taint)


def scan_flows(
    ctx: AnalysisContext, parsed: ParsedSource, resolver: ModuleResolver
) -> list[dict]:
    results: list[dict] = []
    seen: set[int] = set()

    module_env: dict[str, Taint] = {}
    _visit_statements(
        parsed,
        resolver,
        list(parsed.tree.root_node.named_children),
        module_env,
        ctx,
        results,
        seen,
    )

    # Every function gets its own scope, seeded with module-level bindings it
    # can lexically see. This is not inter-procedural propagation: no call
    # graph is assumed and no return value is followed.
    for node in _walk_all(parsed.tree.root_node):
        if node.type not in FUNCTION_TYPES:
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        if body.type == "statement_block":
            statements = list(body.named_children)
        else:
            statements = [body]
        _visit_statements(
            parsed, resolver, statements, dict(module_env), ctx, results, seen
        )

    return results


def annotate_tool_capabilities(tools, observations: list[dict]) -> None:
    """Attach capabilities observed inside each tool's own handler span.

    A capability outside the handler is never attributed to the tool. This is
    deliberate: guessing attribution would manufacture mismatches that the
    code does not contain.
    """
    by_file: dict[str, list[dict]] = {}
    for observation in observations:
        by_file.setdefault(observation["path"], []).append(observation)

    for tool in tools:
        if tool.handler_line is None or tool.handler_end_line is None:
            continue
        capabilities: set[str] = set()
        for observation in by_file.get(tool.source_file, []):
            if tool.handler_line <= observation["line"] <= tool.handler_end_line:
                capabilities.update(observation["capabilities"])
        tool.observed_capabilities = sorted(capabilities)
