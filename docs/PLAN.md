# CapCheck — Approved Architecture & Roadmap

> Status: Milestone 1 implemented. Gemma 4 not yet integrated.
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
| Ingest | `core/ingest.py` | Resolve source, enumerate files, apply caps. No execution. |
| Discover | `core/discover.py` | Find MCP tool declarations (decorators, `Tool(...)`). |
| Static | `core/static_analysis.py` | AST walk → capabilities + evidence. |
| Data-flow | `core/dataflow.py` | Intra-procedural taint: env/file → network/subprocess. |
| Semantic | `core/semantic.py` *(M3)* | Gemma 4 claim generation. Never a finding. |
| Correlate | `core/correlate.py` | Enforce evidence invariant, score risk. |
| Report | API serialisers | Expose findings, evidence, tools. |

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

A capability alone is never malicious. Only connected flows escalate.

## 7. Security posture

- **Never execute repository code.** `ast.parse` only. No `exec`, `eval`,
  `import`, `runpy`, `importlib`, or `subprocess` of scanned code.
- **No `shell=True` anywhere.**
- Path handling resolves against the source root and rejects escapes.
- When remote cloning arrives (M2): allowlist `https://github.com/`, shallow
  clone, `--no-recurse-submodules`, hooks disabled, size/file caps, timeouts.
- Prompt injection is treated as a design problem, not a prompt problem: the
  model cannot create findings.
- Dev mode binds `127.0.0.1`; fixture scanning can be disabled with
  `CAPCHECK_DEV_MODE=0`.

## 8. Roadmap

| Milestone | Content | State |
|---|---|---|
| **M1** | Fixture ingest, AST rules, data-flow, deterministic risk, NullProvider, minimal UI, 29 tests | ✅ done |
| **M2** | Remote GitHub ingestion (allowlist, caps, timeouts), JS/TS discovery, tool-vs-behaviour mismatch | next |
| **M3** | Gemma 4 semantic claims with validated citations + corroboration; `suppressed_claims` surfaced in UI | planned |
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

- Python only; no JS/TS analysis yet.
- Intra-procedural data-flow only; no inter-procedural or alias analysis.
- Static analysis cannot see runtime behaviour, dynamic imports or obfuscation.
- No runtime detonation.
- No authentication; local/dev use only.
