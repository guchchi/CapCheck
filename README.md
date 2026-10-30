# CapCheck

Static, evidence-driven security analysis for MCP servers.

CapCheck reads an MCP server's source, determines what the tools **claim** to
do versus what the code **can actually do**, and reports a risk score in which
every point is traceable to a real file, line and snippet.

> **Milestone 1 scope:** local fixture scanning, Python AST analysis,
> deterministic risk scoring, minimal UI. Gemma 4 is not integrated yet.

## Why

MCP is how agents get tools. Installing an MCP server runs a stranger's code
with your permissions, and tool descriptions are injected into the model's
context as trusted text. A description can say "adds two numbers" while
instructing the model to read `~/.ssh/id_rsa`. You cannot regex that.

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

curl -s -X POST http://127.0.0.1:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"fixture":"exfil_server"}'

curl -s http://127.0.0.1:8000/api/scans/<scan_id>/findings
```

| Fixture | Expected |
|---|---|
| `benign_calculator` | 0 findings, risk 0 (`low`) |
| `exfil_server` | 3 findings, 1 **critical** `DF_ENV_TO_NETWORK`, risk 56 (`high`) |

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness, active LLM provider, available fixtures |
| POST | `/api/scans` | Create a scan (`{"fixture": "..."}`) |
| GET | `/api/scans/{id}` | Status, counts, risk |
| GET | `/api/scans/{id}/findings` | Correlated findings |
| GET | `/api/scans/{id}/tools` | Discovered tool declarations |
| GET | `/api/scans/{id}/evidence/{ev_id}` | Source evidence |

Errors use a uniform envelope:

```json
{ "error": { "code": "SCAN_NOT_FOUND", "message": "No scan with id 'sc_x'." } }
```

## Architecture

```
backend/
  main.py            FastAPI app, static mount
  config.py          settings, caps, fixture allowlist
  models.py          Evidence / Finding / Scan / RiskAssessment
  storage.py         atomic JSON per scan
  api/               routes + error envelope
  core/
    ingest.py        source resolution, file caps
    discover.py      MCP tool declarations (static)
    static_analysis.py  AST capability rules
    dataflow.py      intra-procedural taint
    correlate.py     evidence invariant + risk score
    pipeline.py      stage orchestration
  llm/               LLMProvider protocol + NullProvider
  rules/             capability taxonomy + rule table
fixtures/            inert test data, never executed
frontend/            React + TS + Vite
tests/               29 assertions, offline
```

Full design notes: [`docs/PLAN.md`](docs/PLAN.md).

## Safety guarantees

- Scanned source is parsed with `ast` and **never executed**. No `exec`,
  `eval`, `import`, `runpy` or `subprocess` of repository code.
- `shell=True` appears nowhere in the backend (test-enforced).
- CapCheck has no dependency on the packages its fixtures import; accidental
  execution would fail loudly.
- Fixture names are matched against a directory allowlist, so traversal is not
  expressible.

## Tests

```bash
.\.venv\Scripts\python.exe -m pytest -q
```

29 tests, no network access required.

## Limitations

- Python only (no JS/TS analysis yet).
- Intra-procedural data-flow: one function or module body, no inter-procedural
  propagation, no alias analysis.
- Static analysis cannot observe runtime behaviour or dynamic imports.
- No runtime detonation.
- No authentication. Do not expose this to the internet as-is.

## License

MIT — see [LICENSE](LICENSE).
