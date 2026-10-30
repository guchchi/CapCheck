"""Shared ingestion errors.

Kept in its own module so ``ingest`` and ``github`` can both raise it without
importing each other.
"""

from __future__ import annotations


class IngestError(Exception):
    """A source could not be acquired or safely unpacked."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
