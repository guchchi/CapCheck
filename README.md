# CapCheck

Static, evidence-driven security analysis for MCP servers.

CapCheck reads an MCP server's source, determines what its tools **claim** to
do versus what the code **can actually do**, and reports a risk score in which
every point is traceable to a real file, line and snippet.

> **Milestone 3 scope:** public GitHub ingestion, Python + JavaScript +
> TypeScript analysis, deterministic risk scoring, and Gemma 4 semantic tool
> behavior analysis with bounded, secret-sanitized context. Claims are surfaced
> as unverified observations and never independently create findings or alter risk scores.

## Why

MCP is how agents get tools. Installing an MCP server runs a stranger's code
with your permissions, and tool descriptions are injected into the model's
context as trusted text. A description can say "adds two numbers" while the
handler reads `process.env.GITHUB_TOKEN` and posts it to an attacker. You
cannot regex that, and you should not have to run it to find out.

CapCheck does not claim to stop every attack. It raises the cost of the attack
by turning "trust me" into "here is the line."

## Quick start

Requires Python 3.11+ and Node 18+.

```bash
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # macOS/Linux

# backend  -> http://127.0.0.1:8000
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173  (proxies /api to :8000)
```

For a single-process production build:

```bash
cd frontend && npm run build
cd .. && .\.venv\Scripts\python.exe -m uvicorn backend.main:app
# the built UI is served from / by the backend
```

## Try it

```bash
curl -s http://127.0.0.1:8000/healthz

# public GitHub repository
curl -s -X POST http://127.0.0.1:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"repo_url":"https://github.com/guchchi/CapCheck"}'

# local fixture (development)
curl -s -X POST http://127.0.0.1:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"fixture":"malicious_ts_exfil_server"}'

curl -s http://127.0.0.1:8000/api/scans/<scan_id>/findings
```

| Fixture | Language | Expected |
|---|---|---|
| `benign_calculator` | Python | 0 findings, risk 0 |
| `exfil_server` | Python | 3 findings, 1 **critical** `DF_ENV_TO_NETWORK`, risk 56 |
| `benign_js_calculator` | JavaScript | 0 findings, risk 0 |
| `malicious_js_exfil_server` | JavaScript | 3 findings, 1 **critical** `JS_ENV_TO_NETWORK`, risk 56 |
| `benign_ts_mcp_server` | TypeScript | 2 low capability findings, **0 critical** |
| `malicious_ts_exfil_server` | TypeScript | 6 findings, 2 **critical** (`JS_ENV_TO_NETWORK`, `JS_FILE_TO_NETWORK`), risk 100 |

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness, active LLM provider, available fixtures |
| POST | `/api/scans` | Create a scan: `{"repo_url": "..."}` or `{"fixture": "..."}` |
| GET | `/api/scans/{id}` | Status, stage, commit SHA, languages, counts, risk |
| GET | `/api/scans/{id}/findings` | Correlated findings |
| GET | `/api/scans/{id}/tools` | Discovered tool declarations + observed capabilities |
| GET | `/api/scans/{id}/claims` | Semantic AI claims and tool behavior observations |
| GET | `/api/scans/{id}/evidence/{ev_id}` | Source evidence |

Errors use a uniform envelope:

```json
{ "error": { "code": "INVALID_REPO_URL", "message": "Only github.com repositories are supported." } }
```

## How GitHub ingestion works

1. Validate the URL synchronously (`https://github.com/owner/repo` only).
   Rejected: other schemes, hosts, credentials, ports, IPs, query strings,
   fragments, extra path segments and malformed names.
2. Resolve the default branch and commit SHA through the GitHub REST API.
3. Download `codeload.github.com/{owner}/{repo}/zip/{sha}`.
4. Validate and extract manually into an isolated temp directory.
5. Analyse, then delete the temp directory in a `finally` block.

There is no `git clone`, therefore no hooks, no `.git` directory, no
submodule recursion and no git binary in the untrusted path. Nothing runs
`npm`, `pip`, package scripts or build commands.

Archive hardening: absolute paths, drive letters, backslashes, `..` segments,
encrypted entries, symlinks, entry count, per-file size, total expanded size
and compression ratio are checked. Declared sizes are not trusted: actual
bytes are counted while streaming, and every target is verified to resolve
inside the scan directory.

Limits (defaults in `backend/config.py`): 3,000 files, 1 MB per file, 25 MB
per source, 50 MB archive, 20,000 archive entries, 200:1 compression ratio,
30 s network timeout, 90 s scan budget.

Set `CAPCHECK_GITHUB_TOKEN` to raise the unauthenticated GitHub API rate limit.
The token is only sent in a request header; it is never stored in a scan.

## Analysis coverage

### JavaScript / TypeScript sources

| Source | Detected as |
|---|---|
| `process.env.KEY`, `process.env["KEY"]`, `const { KEY } = process.env` | `JS_ENV_ACCESS` (low) |
| `fs.readFileSync`, `fs.readFile`, `createReadStream`, `require("fs")`, aliased imports | `JS_FILE_READ` (low) |
| Reads of `.ssh`, `.aws`, `.npmrc`, `.netrc`, `.git-credentials`, kube config | `JS_SENSITIVE_PATH_READ` (medium) |

### JavaScript / TypeScript sinks

| Sink | Detected as |
|---|---|
| `fetch(...)` | `JS_NETWORK_EGRESS` (low) |
| `axios.post/get/...`, `http.request`, `https.request` | `JS_NETWORK_EGRESS` (low) |
| `child_process` `exec`/`spawn`/`execFile`/`fork` (named or namespace import) | `JS_SUBPROCESS` (medium) |
| `eval(...)`, `new Function(...)` | `JS_DYNAMIC_EXEC` (high) |

### Connected flows

| Flow | Rule | Severity |
|---|---|---|
| env → network | `JS_ENV_TO_NETWORK` | **critical** |
| file → network | `JS_FILE_TO_NETWORK` | **critical** |
| env → subprocess | `JS_ENV_TO_SUBPROCESS` | high |

A capability alone is never malicious. The same policy applies to the
existing Python rules (`PY_*`, `DF_*`).

### MCP discovery

* JavaScript/TypeScript: `new McpServer(...)` (also `Server`), `server.tool(...)`
  and `server.registerTool(...)`; tool name, description, input schema, handler
  span and parameters. Multiple tools per repository are supported.
* Python: unchanged from Milestone 1 (decorators and `Tool(...)`).

Tool names must be literal strings. When a name or handler cannot be resolved
statically, it is omitted rather than guessed.

## Architecture

```
backend/
  main.py            FastAPI app, static mount
  config.py          settings, caps, fixture allowlist
  models.py          Evidence / ToolDef / Finding / Scan / RiskAssessment
  storage.py         atomic JSON per scan
  api/               routes + error envelope
  core/
    errors.py        shared IngestError
    fileset.py       language-agnostic file enumeration + caps
    ingest.py        fixture and GitHub source acquisition
    github.py        URL validation, REST/codeload fetcher, safe extraction
    discover.py      Python MCP tool declarations
    static_analysis.py  Python AST capability rules
    dataflow.py      Python intra-procedural taint
    js_parser.py     tree-sitter wrapper (JS / TS / TSX)
    js_analysis.py   JS/TS capabilities + intra-procedural taint
    js_discover.py   JS/TS MCP tool declarations
    correlate.py     evidence invariant + deterministic risk score
    pipeline.py      stage orchestration, language dispatch, cleanup
  llm/               LLMProvider protocol + NullProvider
  rules/             capability taxonomy, Python + JS rule tables
fixtures/            inert test data, never executed
frontend/            React + TS + Vite
tests/               offline tests
```

Full design notes: [`docs/PLAN.md`](docs/PLAN.md).

## New dependency: tree-sitter

Milestone 2 adds exactly three packages:

| Package | Installed version | Why |
|---|---|---|
| `tree-sitter` | 0.26.0 | Incremental parser runtime with Python bindings |
| `tree-sitter-javascript` | 0.25.0 | JavaScript/JSX grammar |
| `tree-sitter-typescript` | 0.23.2 | TypeScript/TSX grammar |

A real grammar is required because JS/TS cannot be analysed safely with
regex: JSX, template literals, generics, decorators, optional chaining and
destructuring all break pattern matching, and byte-accurate spans are needed
for evidence line numbers. The packages ship wheels for Python 3.13 on
Windows; no C toolchain was needed. No other dependency was added — archive
download reuses the existing `httpx`.

## Safety guarantees

- Scanned source is parsed and **never executed**. No `exec`, `eval`,
  `import`, `runpy` or `subprocess` of repository code.
- The JavaScript analyser only *searches for* `eval` and `Function` nodes.
- `shell=True` appears nowhere in the backend (test-enforced).
- Archives are never passed to `extractall` (test-enforced).
- Evidence paths are validated on construction: relative, POSIX separators,
  no `..`, no drive letters.
- Remote sources are extracted into an isolated temp directory and deleted
  after the scan; their absolute paths are never written to scan artifacts.
- Repository text (descriptions, snippets, schemas) is truncated and treated
  as untrusted display data.
- Environment variable *values* are never read by the scanner; only the
  source expression is reported.
- `CAPCHECK_DEV_MODE=0` disables local fixture scanning.
- The server binds `127.0.0.1` in the documented commands and has no
  authentication. Do not expose it publicly as-is.

## Tests

```bash
.\.venv\Scripts\python.exe -m pytest -q
```

111 tests, fully offline. GitHub downloads are replaced by an in-memory
`FakeFetcher`, so no test contacts github.com.

## Limitations

- **Static analysis only.** No runtime detonation, no sandbox execution.
- **Intra-procedural flow.** No inter-procedural propagation, no class
  fields, no alias analysis, no re-export tracking, no dynamic
  `require(variable)` resolution.
- **Module-level bindings are visible to handlers** (JavaScript lexical
  scope). Values passed between functions are not followed.
- **Per-tool capabilities are limited to the handler span.** A dangerous
  helper called by a tool is reported as a repository finding, not attributed
  to that tool. This avoids invented mismatches.
- **Discovery patterns are finite.** Low-level `Server.setRequestHandler`
  registrations and non-literal tool names are not discovered.
- **Python remains the wider analyser.** JS/TS rule coverage matches the
  brief, not every Python rule.
- **GitHub ZIP only.** Git LFS content arrives as pointer files; submodules
  are not fetched (by design).
- **Soft scan timeout** is checked between files, not enforced per file.
- **Unauthenticated GitHub API** allows 60 requests/hour per IP; set
  `CAPCHECK_GITHUB_TOKEN` for more.
- **Known false positive:** Python `is_file_read()` matches any `.read()`
  call, so `response.read()` is labelled a file read (low severity only).
- **No authentication, no multi-user isolation, no report export.** Local
  development use only.

## License

MIT — see [LICENSE](LICENSE).
