"""Runtime configuration for CapCheck."""

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
    github_api_base: str
    gemini_api_key: str | None = None
    gemma_model: str = "gemma-4-31b-it"
    llm_timeout_seconds: float = 10.0
    llm_max_retries: int = 2

    # Enumeration caps (apply to fixtures and remote repositories alike).
    max_files: int = 3000
    max_file_bytes: int = 1_000_000
    max_total_bytes: int = 25 * 1024 * 1024

    # Archive caps (remote ingestion only).
    max_archive_bytes: int = 50 * 1024 * 1024
    max_archive_entries: int = 20_000
    max_compression_ratio: int = 200

    # Network.
    fetch_timeout_seconds: int = 30
    github_api_base: str = "https://api.github.com"

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
            github_api_base=os.environ.get(
                "CAPCHECK_GITHUB_API_BASE", "https://api.github.com"
            ),
            gemini_api_key=os.environ.get("GEMINI_API_KEY"),
            gemma_model=os.environ.get("CAPCHECK_GEMMA_MODEL", "gemma-4-31b-it"),
            llm_timeout_seconds=float(os.environ.get("CAPCHECK_LLM_TIMEOUT", "10.0")),
            llm_max_retries=int(os.environ.get("CAPCHECK_LLM_RETRIES", "2")),
        )

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"

    def available_fixtures(self) -> list[str]:
        """Fixture directory names that exist on disk."""
        if not FIXTURES_ROOT.is_dir():
            return []
        return sorted(
            p.name
            for p in FIXTURES_ROOT.iterdir()
            if p.is_dir() and not p.name.startswith(".")
        )


settings = Settings.load()
