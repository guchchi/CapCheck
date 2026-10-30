"""Static discovery of MCP tool declarations in JavaScript and TypeScript.

Only source text is inspected. CapCheck never starts the server, never speaks
MCP to it and never imports the SDK, because all three would execute untrusted
code.

Recognised shapes::

    const server = new McpServer({ name: "x" });
    server.tool("add", "Add numbers", { a: z.number() }, handler);
    server.tool("add", { description: "..." }, handler);
    server.registerTool("mul", { description: "...", inputSchema: {...} }, handler);

If a tool name is not a literal string, the declaration is skipped rather than
invented.
"""

from __future__ import annotations

from tree_sitter import Node

from backend.core.js_parser import ParsedSource
from backend.core.static_analysis import AnalysisContext
from backend.models import ToolDef

SERVER_CONSTRUCTORS = frozenset({"McpServer", "Server"})
SERVER_RECEIVER_RE = frozenset({"server", "mcp", "mcpserver", "srv", "fastmcp"})
TOOL_METHODS = frozenset({"tool", "registerTool"})
FUNCTION_ARG_TYPES = frozenset({"arrow_function", "function_expression"})
SCHEMA_TEXT_LIMIT = 500
NAME_LIMIT = 200
DESCRIPTION_LIMIT = 500
PARAM_LIMIT = 50


def _dotted(parsed: ParsedSource, node: Node | None) -> str:
    if node is None:
        return ""
    if node.type == "identifier":
        return parsed.text(node)
    if node.type == "member_expression":
        base = _dotted(parsed, node.child_by_field_name("object"))
        prop = parsed.text(node.child_by_field_name("property"))
        return f"{base}.{prop}" if base else prop
    return parsed.text(node)


def _literal_string(parsed: ParsedSource, node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type == "string":
        raw = parsed.text(node)
        if len(raw) >= 2 and raw[0] in {'"', "'"} and raw[-1] == raw[0]:
            return raw[1:-1]
        return None
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.named_children):
            return None
        raw = parsed.text(node)
        if len(raw) >= 2 and raw[0] == "`" and raw[-1] == "`":
            return raw[1:-1]
    return None


def _object_property(parsed: ParsedSource, node: Node, key: str) -> Node | None:
    if node.type != "object":
        return None
    for child in node.named_children:
        if child.type != "pair":
            continue
        key_node = child.child_by_field_name("key")
        if key_node is not None and parsed.text(key_node) == key:
            return child.child_by_field_name("value")
    return None


def _object_keys(parsed: ParsedSource, node: Node) -> list[str]:
    keys: list[str] = []
    for child in node.named_children:
        if child.type == "pair":
            key_node = child.child_by_field_name("key")
            if key_node is not None:
                keys.append(parsed.text(key_node).strip("\"'"))
        elif child.type == "shorthand_property_identifier":
            keys.append(parsed.text(child))
    return keys


def _schema_keys(parsed: ParsedSource, schema: Node | None) -> list[str]:
    if schema is None:
        return []
    if schema.type == "object":
        return _object_keys(parsed, schema)
    if schema.type == "call_expression":
        args = schema.child_by_field_name("arguments")
        if args is not None:
            for child in args.named_children:
                if child.type == "object":
                    return _object_keys(parsed, child)
    return []


def _handler_parameter_keys(parsed: ParsedSource, handler: Node | None) -> list[str]:
    if handler is None:
        return []
    params = handler.child_by_field_name("parameters")
    if params is None:
        for child in handler.named_children:
            if child.type == "formal_parameters":
                params = child
                break
    if params is None:
        return []
    for child in params.named_children:
        if child.type == "object_pattern":
            keys: list[str] = []
            for item in child.named_children:
                if item.type == "shorthand_property_identifier_pattern":
                    keys.append(parsed.text(item))
                elif item.type == "pair_pattern":
                    key_node = item.child_by_field_name("key")
                    if key_node is not None:
                        keys.append(parsed.text(key_node).strip("\"'"))
            return keys
    return []


def _last_function(arguments: list[Node]) -> Node | None:
    for node in reversed(arguments):
        if node.type in FUNCTION_ARG_TYPES:
            return node
    return None


def _arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    if args is None:
        return []
    return list(args.named_children)


def discover_servers(parsed: ParsedSource) -> list[dict]:
    """Record ``new McpServer(...)`` declarations (metadata, not findings)."""
    servers: list[dict] = []
    for node in _walk_all(parsed.tree.root_node):
        if node.type != "new_expression":
            continue
        constructor = node.child_by_field_name("constructor")
        if constructor is None and node.named_children:
            constructor = node.named_children[0]
        if parsed.text(constructor) not in SERVER_CONSTRUCTORS:
            continue
        parent = node.parent
        name = ""
        if parent is not None and parent.type == "variable_declarator":
            name_node = parent.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier":
                name = parsed.text(name_node)
        servers.append({"name": name, "line": parsed.line(node)})
    return servers


def _server_variables(parsed: ParsedSource) -> set[str]:
    variables: set[str] = set()
    for node in _walk_all(parsed.tree.root_node):
        if node.type != "variable_declarator":
            continue
        value = node.child_by_field_name("value")
        if value is None or value.type != "new_expression":
            continue
        constructor = value.child_by_field_name("constructor")
        if constructor is None and value.named_children:
            constructor = value.named_children[0]
        if parsed.text(constructor) not in SERVER_CONSTRUCTORS:
            continue
        name_node = node.child_by_field_name("name")
        if name_node is not None and name_node.type == "identifier":
            variables.add(parsed.text(name_node))
    return variables


def _walk_all(node: Node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _parse_tool_call(
    parsed: ParsedSource, call: Node, method: str
) -> tuple[str, str, Node | None, Node | None] | None:
    """Return (name, description, schema, handler) or None."""
    arguments = _arguments(call)
    if not arguments:
        return None

    handler = _last_function(arguments)

    name: str | None = None
    description = ""
    schema: Node | None = None

    first = arguments[0]
    name = _literal_string(parsed, first)

    if name is None and first.type == "object":
        name_node = _object_property(parsed, first, "name")
        name = _literal_string(parsed, name_node)

    if name is None:
        return None

    for argument in arguments[1:]:
        if argument is handler:
            continue
        if argument.type == "string":
            if not description:
                value = _literal_string(parsed, argument)
                if value is not None:
                    description = value
            continue
        if argument.type == "object":
            if method == "registerTool":
                config_description = _object_property(parsed, argument, "description")
                config_title = _object_property(parsed, argument, "title")
                if not description:
                    for candidate in (config_description, config_title):
                        value = _literal_string(parsed, candidate)
                        if value:
                            description = value
                            break
                input_schema = _object_property(parsed, argument, "inputSchema")
                if input_schema is not None:
                    schema = input_schema
            else:
                if not description:
                    value = _literal_string(
                        parsed, _object_property(parsed, argument, "description")
                    )
                    if value:
                        description = value
                if schema is None:
                    schema = argument
            continue
        if method == "tool" and schema is None and argument.type in {
            "call_expression",
            "member_expression",
            "identifier",
        }:
            schema = argument

    return name, description, schema, handler


def discover_tools(
    ctx: AnalysisContext, parsed: ParsedSource, language: str
) -> list[ToolDef]:
    server_variables = _server_variables(parsed)
    tools: list[ToolDef] = []
    seen: set[tuple[str, int]] = set()

    for node in _walk_all(parsed.tree.root_node):
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "member_expression":
            continue
        property_node = callee.child_by_field_name("property")
        method = parsed.text(property_node)
        if method not in TOOL_METHODS:
            continue

        receiver = _dotted(parsed, callee.child_by_field_name("object"))
        if receiver not in server_variables and receiver.lower() not in SERVER_RECEIVER_RE:
            continue

        parsed_call = _parse_tool_call(parsed, node, method)
        if parsed_call is None:
            continue
        name, description, schema, handler = parsed_call

        line = parsed.line(node)
        if (name, line) in seen:
            continue
        seen.add((name, line))

        params = _schema_keys(parsed, schema)
        if not params:
            params = _handler_parameter_keys(parsed, handler)

        evidence_id = ctx.add_evidence(line, "TOOL_DEF", kind="tool_def")

        tools.append(
            ToolDef(
                name=name[:NAME_LIMIT],
                declared_description=description[:DESCRIPTION_LIMIT],
                params=params[:PARAM_LIMIT],
                source_file=ctx.path,
                line=line,
                evidence_id=evidence_id,
                language=language,
                input_schema=(
                    parsed.text(schema)[:SCHEMA_TEXT_LIMIT] if schema is not None else None
                ),
                handler_line=parsed.line(handler) if handler is not None else None,
                handler_end_line=parsed.end_line(handler) if handler is not None else None,
            )
        )

    return tools
