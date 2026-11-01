# CapCheck Cloud Deployment Guide

This guide details the complete deployment process for CapCheck using:
- **Backend**: DigitalOcean App Platform (FastAPI web service)
- **Frontend**: Vercel (React + Vite static hosting)
- **Repository**: `guchchi/CapCheck` on branch `master`

---

## 1. DigitalOcean App Platform (Backend Service)

DigitalOcean App Platform runs CapCheck as a long-running Python container service. This enables background processing via FastAPI `BackgroundTasks`, polling across requests within the active container, and outbound Google Gemma API calls.

> [!WARNING]
> **Ephemeral Filesystem Limitation**: DigitalOcean App Platform provides an **ephemeral local container filesystem**, NOT persistent disk storage.
> - Scan JSON records (`data/scans/{scan_id}.json`) are written locally and remain available as long as the container is running.
> - **Any redeployment, restart, or container replacement will wipe previously stored scan JSON records**.
> - For this hackathon demo, atomic local JSON storage is retained to avoid unnecessary complexity and paid cloud databases or object storage. Users should be aware that scan history does not persist across container restarts.

### Component Configuration Settings
- **Service Name**: `capcheck-backend`
- **Source**: GitHub repository `guchchi/CapCheck`
- **Branch**: `master`
- **Source Directory**: `/` (repository root)
- **Environment**: `Python` (Python 3.11+)
- **Instance Size**: Basic ($5.00/mo — 1 vCPU, 512 MiB RAM)
  - *Resource Constraint Note*: 512 MiB RAM is a hard fixed boundary. While baseline idle and fixture scans operate within this ceiling, actual memory usage on large external GitHub repositories has not been benchmarked under production concurrency. Monitor memory metrics in the DigitalOcean dashboard during multi-file scans.
- **HTTP Port**: `8080` (Matches Uvicorn fallback `${PORT:-8080}`)

### Exact Build & Run Commands
- **Build Command**:
  ```bash
  pip install -r requirements.txt
  ```
- **Run Command**:
  ```bash
  python -m uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8080}
  ```
  *(DigitalOcean App Platform automatically injects the `PORT` environment variable, defaulting to `8080` if unset).*

### Health Check Configuration
- **HTTP Path**: `/healthz`
- **Initial Delay**: `10` seconds
- **Period**: `15` seconds
- **Timeout**: `5` seconds
- **Success Threshold**: `1`
- **Failure Threshold**: `3`

### Required Backend Environment Variables
Configure these in the DigitalOcean App Platform component settings (marked as **Encrypted** for secrets):

| Variable | Recommended Production Value | Description |
| :--- | :--- | :--- |
| `CAPCHECK_LLM_PROVIDER` | `gemma` | Enables Gemma semantic analysis (or `null` if disabled) |
| `GEMINI_API_KEY` | *(Your secret API key)* | **[ENCRYPTED]** Server-side Google API key for Gemma 4 |
| `CAPCHECK_GEMMA_MODEL` | `gemma-4-26b-a4b-it` | Gemma model identifier |
| `CAPCHECK_LLM_TIMEOUT` | `30.0` | Timeout in seconds for model calls |
| `CAPCHECK_LLM_RETRIES` | `1` | Retry attempts on transient API failures |
| `CAPCHECK_DEV_MODE` | `0` | Disables local fixture access in production; allows GitHub scans |
| `CAPCHECK_DATA_DIR` | `data` | Storage directory for scan JSON artifacts |
| `CAPCHECK_CORS_ORIGINS` | `https://<your-vercel-app>.vercel.app` | Allowed frontend origin(s), comma-separated (or `*`) |

> **Note on Backend URL**: Once deployed, DigitalOcean will assign a public domain, e.g.:
> `https://capcheck-backend-xxxxx.ondigitalocean.app`

---

## 2. Vercel (Frontend Deployment)

Vercel hosts the React + Vite frontend as a globally distributed static application.

### Project Setup Settings
- **Framework Preset**: `Vite`
- **Root Directory**: `frontend` *(Important: set this to the `frontend` folder)*
- **Build Command**: `npm run build` (or `tsc --noEmit && vite build`)
- **Output Directory**: `dist`
- **Install Command**: `npm install`

### Required Frontend Environment Variables
Set in Vercel Project Settings -> **Environment Variables**:

| Variable | Value | Description |
| :--- | :--- | :--- |
| `VITE_API_BASE_URL` | `https://capcheck-backend-xxxxx.ondigitalocean.app` | Public URL of your DigitalOcean backend (no trailing slash) |

*All browser requests (`/api/scans`, `/healthz`, `/claims`, etc.) will be dispatched directly to your DigitalOcean backend URL with full CORS support.*

---

## 3. Deployment Steps & Connectivity Flow

```
+------------------------------------+        HTTPS REST        +-------------------------------------+
|        Vercel (Frontend)           | -----------------------> |    DigitalOcean App Platform        |
|  https://capcheck.vercel.app       |   (VITE_API_BASE_URL)    |  https://capcheck-backend-....app   |
|  - Root: frontend/                 |                          |  - FastAPI (uvicorn)                |
|  - Static React SPA                |                          |  - AST & Dataflow Pipeline          |
+------------------------------------+                          |  - Atomic JSON disk storage         |
                                                                |  - Gemma 4 Model Integration        |
                                                                +-------------------------------------+
                                                                                   |
                                                                                   | HTTPS (GEMINI_API_KEY)
                                                                                   v
                                                                +-------------------------------------+
                                                                |     Google Gemini / Gemma API       |
                                                                +-------------------------------------+
```

### Step-by-Step Procedure:

1. **Deploy Backend First**:
   - Go to [DigitalOcean App Platform](https://cloud.digitalocean.com/apps).
   - Click **Create App** -> Select **GitHub** -> Choose `guchchi/CapCheck` -> Branch `master`.
   - Set Source Directory to `/`.
   - Set Build Command to `pip install -r requirements.txt`.
   - Set Run Command to `python -m uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8080}`.
   - Choose the Basic $5/month instance.
   - Add environment variables (`GEMINI_API_KEY`, `CAPCHECK_LLM_PROVIDER=gemma`, etc.).
   - Deploy and copy the resulting `ondigitalocean.app` domain.

2. **Deploy Frontend on Vercel**:
   - Go to [Vercel Dashboard](https://vercel.com/new).
   - Import the `guchchi/CapCheck` repository.
   - In **Project Settings**, change **Root Directory** to `frontend`.
   - Add Environment Variable:
     `VITE_API_BASE_URL` = `https://<your-digitalocean-backend-domain>`
   - Click **Deploy**.

3. **Update CORS on Backend**:
   - In DigitalOcean App Platform Settings -> Components -> `capcheck-backend` -> Environment Variables:
     Set `CAPCHECK_CORS_ORIGINS` = `https://<your-vercel-domain>.vercel.app`
   - Save and apply (triggers zero-downtime rolling restart).

---

## 4. Redeployment Workflow for Future Pushes

- DigitalOcean App Platform and Vercel both monitor the `master` branch.
- Any future push to `origin/master`:
  - Automatically triggers a frontend build and deploy on Vercel.
  - Automatically triggers a backend build and container restart on DigitalOcean.
- No manual redeployment steps are needed after initial setup.

