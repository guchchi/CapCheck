"""Uniform API error envelope."""

from __future__ import annotations

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class ApiError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


async def api_error_handler(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, ApiError)
    return JSONResponse(
        {"error": {"code": exc.code, "message": exc.message}},
        status_code=exc.status_code,
    )


async def validation_error_handler(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    return JSONResponse(
        {
            "error": {
                "code": "INVALID_REQUEST",
                "message": "Request body failed validation.",
                "details": exc.errors(),
            }
        },
        status_code=422,
    )
