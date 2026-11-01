"""CapCheck FastAPI application.

Run from the project root:
    uvicorn backend.main:app --reload
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api import routes_findings, routes_scan
from backend.api.errors import ApiError, api_error_handler, validation_error_handler
from backend.config import PROJECT_ROOT, settings

app = FastAPI(
    title="CapCheck",
    version="0.1.0",
    description="Evidence-driven static security analysis for MCP servers.",
)

app.add_exception_handler(ApiError, api_error_handler)
app.add_exception_handler(RequestValidationError, validation_error_handler)

# CORS middleware configuration: supports local Vite dev server (5173),
# self origin, and any production frontend origins via CAPCHECK_CORS_ORIGINS.
_default_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
_env_origins = os.environ.get("CAPCHECK_CORS_ORIGINS", "").strip()
if _env_origins:
    if _env_origins == "*":
        _allowed_origins = ["*"]
    else:
        _allowed_origins = _default_origins + [
            o.strip() for o in _env_origins.split(",") if o.strip()
        ]
else:
    # In production without specific origins set, allow all or wildcard
    _allowed_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=True if _allowed_origins != ["*"] else False,
)

app.include_router(routes_scan.router)
app.include_router(routes_findings.router)


@app.get("/healthz", tags=["system"])
def healthz() -> dict:
    return {
        "ok": True,
        "service": "capcheck",
        "llm": settings.llm_provider,
        "dev_mode": settings.dev_mode,
        "fixtures": settings.available_fixtures(),
    }


# Serve the built frontend when present. API routes are registered above, so
# they always win; this mount only catches everything else.
_dist = PROJECT_ROOT / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="ui")
