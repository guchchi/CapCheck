"""Runtime configuration for CapCheck.

Milestone 1 is deliberately small: no database, no external services.
Everything is read from environment variables with safe local defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_ROOT = PROJECT_ROOT / "fixtures"


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Immutable process settings."""

    dev_mode: bool
    data_dir: Path
    llm_provider: str
    max_files: int = 3000
    max_file_bytes: int = 1_000_000
    scan_timeout_seconds: int = 90

    @classmethod
    def load(cls) -> "Settings":
        data_dir = Path(os.environ.get("CAPCHECK_DATA_DIR", "data"))
        if not data_dir.is_absolute():
            data_dir = PROJECT_ROOT / data_dir
        return cls(
            dev_mode=_as_bool(os.environ.get("CAPCHECK_DEV_MODE"), True),
            data_dir=data_dir,
            llm_provider=os.environ.get("CAPCHECK_LLM_PROVIDER", "null"),
        )

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"

    def available_fixtures(self) -> list[str]:
        """Fixture directory names that exist on disk."""
        if not FIXTURES_ROOT.is_dir():
            return []
        return sorted(
            p.name for p in FIXTURES_ROOT.iterdir() if p.is_dir() and not p.name.startswith(".")
        )


settings = Settings.load()
