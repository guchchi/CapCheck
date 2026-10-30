"""Source acquisition.

Milestone 1 supports local fixtures only. Remote repository cloning is
deliberately not implemented; the guard here exists so that when it is
added, the allowlist and caps are already in the right place.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from backend.config import FIXTURES_ROOT, Settings
from backend.core.static_analysis import collect_python_files


class IngestError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Source:
    kind: str
    name: str
    root: Path
    files: list[Path]


def open_fixture(name: str, settings: Settings) -> Source:
    """Resolve an allowlisted local fixture directory.

    The name is matched against directories that actually exist under
    ``fixtures/``; path traversal is impossible because we never join a
    user-supplied string onto a path.
    """
    if not settings.dev_mode:
        raise IngestError(
            "FIXTURES_DISABLED",
            "Local fixture scanning is disabled (CAPCHECK_DEV_MODE=0).",
        )
    allowed = settings.available_fixtures()
    if name not in allowed:
        raise IngestError(
            "UNKNOWN_FIXTURE",
            f"Unknown fixture '{name}'. Available: {', '.join(allowed) or 'none'}.",
        )

    root = (FIXTURES_ROOT / name).resolve()
    if not str(root).startswith(str(FIXTURES_ROOT.resolve())):
        raise IngestError("INVALID_FIXTURE", "Fixture path escapes the fixtures directory.")

    files = collect_python_files(root, settings.max_files, settings.max_file_bytes)
    if not files:
        raise IngestError("EMPTY_SOURCE", f"Fixture '{name}' contains no Python files.")

    return Source(kind="fixture", name=name, root=root, files=files)
