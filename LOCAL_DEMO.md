# CapCheck Local Demo Guide

This document describes how to start and operate CapCheck locally on Windows using PowerShell.

---

## 1. Prerequisites

- **Python**: 3.11+
- **Node.js**: 18+ (tested with v22.14.0)
- **Virtual Environment**: `.venv` in the repository root

---

## 2. Environment Configuration

CapCheck uses `.env` in the repository root (gitignored) for local overrides:

```env
# Enable Gemma 4 semantic analysis (default is 'null')
CAPCHECK_LLM_PROVIDER=gemma

# Server-side Google API key for Gemma 4
GEMINI_API_KEY=your_gemini_api_key_here

# Gemma model identifier (default: gemma-4-26b-a4b-it)
CAPCHECK_GEMMA_MODEL=gemma-4-26b-a4b-it

# Model call timeouts (default: 30.0s)
CAPCHECK_LLM_TIMEOUT=30.0
CAPCHECK_LLM_RETRIES=1
```

*Note: In development mode, `CAPCHECK_DEV_MODE=1` enables local fixture scanning directly from the UI.*

---

## 3. Starting the Services

Open two separate Windows PowerShell windows from the project root:

### Terminal 1: Backend Service (FastAPI / Uvicorn)

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Backend URL**: `http://127.0.0.1:8000`
- **Health Check**: `http://127.0.0.1:8000/healthz`

### Terminal 2: Frontend Dev Server (Vite + React)

```powershell
cd frontend
npm run dev
```
- **Frontend URL**: `http://localhost:5173`
- The Vite dev server proxies `/api` and `/healthz` directly to `http://127.0.0.1:8000`.

---

## 4. Single-Process Production Build (Optional)

Alternatively, you can build the frontend and serve both through the single backend process:

```powershell
# Build frontend static bundle into frontend/dist
cd frontend
npm run build
cd ..

# Start backend (serves frontend/dist at root /)
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
Then navigate directly to `http://127.0.0.1:8000`.

---

## 5. Performing Scans via the UI

1. Open `http://localhost:5173` in your browser.
2. Under the **Local fixture** tab, select a test fixture:
   - **Benign Demo**: Select `benign_calculator` and click **Scan fixture**.
     - Result: 0 findings, 0 critical, Risk Score `0/100` (`low`).
   - **Malicious Demo**: Select `exfil_server` and click **Scan fixture**.
     - Result: 3 findings (`DF_ENV_TO_NETWORK`, `PY_ENV_ACCESS`, `PY_NETWORK_EGRESS`), Risk Score `80/100` (`critical`).
3. Click any finding to inspect exact source file lines and AST evidence snippets.
4. Review the **Unverified AI Observations** section for semantic model assessments.

