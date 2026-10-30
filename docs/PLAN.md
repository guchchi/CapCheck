# CapCheck — Approved Architecture & Roadmap

> Status: Milestone 2 implemented. Python + JavaScript + TypeScript analysis,
> public GitHub ingestion. Gemma 4 not yet integrated.
> This document is the reference for all later milestones.

## 1. Product

CapCheck answers four questions about an MCP server, in this order:

1. What does it **claim** to do? (tool names, descriptions, parameters)
2. What does its **source actually do**? (capabilities, data flows)
3. Does anything look **dangerous**? (rule matches, evidence)
4. Can **sensitive data reach an external destination**? (source → sink)

## 2. Core principle

> **Analysers produce evidence. The LLM produces claims. Only corroboration
> produces findings.**

- A `Finding` requires ≥ 1 `Evidence` record. Enforced in
  `backend/core/correlate.py::correlate`.
- An `AIClaim` must cite evidence ids that already exist in the scan.
  Invalid citations are dropped.
- A claim with no supporting static or data-flow evidence is recorded in
  `suppressed_claims` and **excluded from the findings list and the risk
  score**.
- The risk score is computed by a deterministic function. No model influences it.

## 3. Pipeline

```
source ──► ingest ──► discover ──► static (AST) ──┐
                              │                   ├──► correlate ──► report
                              └► data-flow ───────┘
                                        ▲
                                semantic (Gemma 4, M3+)
```

| Stage | Module | Responsibility |
|---|---|---|
| Ingest | `core/ingest.py`, `core/github.py` | Resolve a fixture or fetch a public GitHub archive, unpack it safely, enumerate files, apply caps. No execution. |
| Discover | `core/discover.py`, `core/js_discover.py` | Find MCP tool declarations (Python decorators/`Tool(...)`; JS/TS `new McpServer`, `.tool`, `.registerTool`). |
| Static (Python) | `core/static_analysis.py` | Python AST walk → capabilities + evidence. |
| Static (JS/TS) | `core/js_analysis.py`, `core/js_parser.py` | tree-sitter walk → capabilities + evidence. |
| Data-flow (Python) | `core/dataflow.py` | Intra-procedural taint: env/file → network/subprocess. |
| Data-flow (JS/TS) | `core/js_analysis.py` | Intra-procedural taint across local bindings, object/array literals, templates and call arguments. |
| Semantic | `core/semantic.py` *(M3)* | Gemma 4 claim generation. Never a finding. |
| Correlate | `core/correlate.py` | Enforce evidence invariant, attribute tool capabilities, score risk. |
| Report | API serialisers | Expose findings, evidence, tools, commit SHA, languages, metadata. |

Both analysers emit the same normalised dict shapes, so correlation has no
language-specific branch. The rule catalogues stay separate
(`rules/python_rules.py`, `rules/javascript_rules.py`).

**Deliberate scope limit:** tool discovery is static. We do **not** use the
official MCP client to enumerate tools, because connecting to a server means
executing it.

## 4. Data model invariants

- `Evidence` is immutable and carries `path`, `line_start`, `line_end`,
  `snippet`, `extractor`, `file_sha256`.
- `Finding.evidence_ids` is never empty.
- `severity` (rule table) and `confidence` (detector reliability) are separate
  fields and are never conflated.
- `RiskAssessment.breakdown` exposes the per-finding arithmetic.

## 5. Risk model (deterministic)

```
points = severity_weight * confidence
score  = min(100, round(sum(points)))

weights: critical 55 · high 25 · medium 10 · low 3 · info 0
bands:   0–19 low · 20–49 moderate · 50–79 high · 80–100 critical
```

Rule table lives in `backend/rules/python_rules.py` and is the single source
of truth for severity.

## 6. Rule set

| Rule | Severity | Capabilities |
|---|---|---|
| `PY_ENV_ACCESS` | low | READ_ENV |
| `PY_FILE_READ` | low | READ_FILE |
| `PY_FILE_WRITE` | low | WRITE_FILE |
| `PY_NETWORK_EGRESS` | low | NETWORK_EGRESS |
| `PY_SUBPROCESS` | medium | SUBPROCESS |
| `PY_DYNAMIC_EXEC` | high | DYNAMIC_EXEC |
| `DF_ENV_TO_NETWORK` | **critical** | READ_ENV + NETWORK_EGRESS |
| `DF_FILE_TO_NETWORK` | **critical** | READ_FILE + NETWORK_EGRESS |
| `DF_ENV_TO_SUBPROCESS` | high | READ_ENV + SUBPROCESS |

### JavaScript / TypeScript rules

| Rule | Severity | Capabilities |
|---|---|---|
| `JS_ENV_ACCESS` | low | READ_ENV |
| `JS_FILE_READ` | low | READ_FILE |
| `JS_SENSITIVE_PATH_READ` | medium | READ_FILE |
| `JS_NETWORK_EGRESS` | low | NETWORK_EGRESS |
| `JS_SUBPROCESS` | medium | SUBPROCESS |
| `JS_DYNAMIC_EXEC` | high | DYNAMIC_EXEC |
| `JS_ENV_TO_NETWORK` | **critical** | READ_ENV + NETWORK_EGRESS |
| `JS_FILE_TO_NETWORK` | **critical** | READ_FILE + NETWORK_EGRESS |
| `JS_ENV_TO_SUBPROCESS` | high | READ_ENV + SUBPROCESS |

A capability alone is never malicious. Only connected flows escalate. When two
sources reach one sink, two findings are emitted so each cites its own source
line.

## 7. Security posture

- **Never execute repository code.** Parsing only. No `exec`, `eval`,
  `import`, `runpy`, `importlib`, `subprocess`, package manager or build
  command touches scanned source. The JS analyser searches for `eval` and
  `Function` nodes; it never calls them.
- **No `shell=True` anywhere.**
- Path handling resolves against the source root and rejects escapes.
  Evidence paths are validated on construction: relative, `/` separators, no
  `..`, no drive letters.
- **Remote ingestion does not use git.** GitHub REST resolves the commit, then
  the codeload ZIP is downloaded and extracted manually. No hooks, no `.git`,
  no submodules, no git binary.
- **Archive hardening:** absolute paths, drive letters, backslashes, `..`,
  symlinks, encrypted entries, entry count, per-file size, total expanded
  size and compression ratio are checked. Declared sizes are not trusted;
  actual bytes are counted while streaming, and every target must resolve
  inside the scan directory.
- **Temp isolation:** remote sources are unpacked into an isolated temp
  directory and deleted in a `finally` block. Absolute paths never reach an
  API response or scan artifact.
- **Untrusted text is display data:** tool descriptions, schemas and snippets
  are truncated; environment variable values are never read by the scanner.
- Prompt injection is treated as a design problem, not a prompt problem: the
  model cannot create findings.
- Dev mode binds `127.0.0.1`; fixture scanning can be disabled with
  `CAPCHECK_DEV_MODE=0`. There is no authentication; do not expose publicly.

## 8. Roadmap

| Milestone | Content | State |
|---|---|---|
| **M1** | Fixture ingest, AST rules, data-flow, deterministic risk, NullProvider, minimal UI, 29 tests | ✅ done |
| **M2** | Public GitHub ingestion, archive hardening, JS/TS discovery, JS/TS source-to-sink analysis, four new fixtures, UI for repo URL + tools + stages | ✅ done |
| **M3** | Gemma 4 semantic claims with validated citations + corroboration; `suppressed_claims` surfaced in UI | next |
| **M4** | DigitalOcean deployment, report export, history | planned |
| **M5 (stretch)** | Ephemeral droplet detonation with egress logging | stretch |

### 8-hour hackathon budget (original plan)

| Time | Goal |
|---|---|
| 0:00–0:40 | Skeleton, fixtures, NullProvider |
| 0:40–2:00 | Ingest + discover |
| 2:00–3:15 | Static rules |
| 3:15–4:15 | Data-flow |
| 4:15–5:00 | Correlate + risk + report |
| 5:00–6:15 | Frontend |
| 6:15–7:00 | Gemma 4 claims |
| 7:00–7:30 | Deploy |
| 7:30–8:00 | Freeze, video, pitch |

## 9. Known limitations (state these to judges)

- Python, JavaScript and TypeScript only. JSX/TSX parse, but tool discovery is
  pattern-based.
- Intra-procedural data-flow only: one function body, no inter-procedural
  propagation, no alias analysis, no class fields or re-exports. Module-level
  bindings are visible to handlers (lexical scope), but values passed between
  functions are not followed.
- Per-tool capabilities are attributed only from the tool's own handler span.
  Helper functions are reported at repository level, never attributed to a
  tool.
- Static analysis cannot see runtime behaviour, dynamic imports or obfuscation.
- Low-level `Server.setRequestHandler` tool registrations and non-literal tool
  names are not discovered.
- GitHub ZIP archives only: LFS content appears as pointer files; submodules
  are not fetched (by design).
- The scan timeout is checked between files; a single pathological file is
  bounded by the per-file size cap, not by a hard kill.
- Unauthenticated GitHub API limits scans to 60 requests/hour per IP
  (set `CAPCHECK_GITHUB_TOKEN` for more).
- No runtime detonation, no authentication, no multi-user isolation.
