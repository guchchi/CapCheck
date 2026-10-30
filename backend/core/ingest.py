"""Source acquisition.

Two source kinds:

* ``fixture`` — an allowlisted local directory used by tests and development.
* ``github``  — a public repository archive fetched over HTTPS, never cloned
  and never executed.

Both return the same ``Source`` shape so every downstream stage is
language- and origin-agnostic. Temporary remote sources are cleaned up by the
pipeline in a ``finally`` block.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from backend.config import FIXTURES_ROOT, Settings
from backend.core import fileset, github
from backend.core.errors import IngestError

__all__ = ["IngestError", "Source", "open_fixture", "open_repository"]


@dataclass
class Source:
    kind: str
    name: str
    root: Path
    files: list[Path]
    temporary: Path | None = None
    commit_sha: str | None = None
    metadata: dict = field(default_factory=dict)
    total_bytes: int = 0
    skipped_oversized: int = 0

    def cleanup(self) -> None:
        if self.temporary is not None:
            shutil.rmtree(self.temporary, ignore_errors=True)
            self.temporary = None


def _collect(root: Path, settings: Settings) -> fileset.FileSet:
    return fileset.collect_files(
        root,
        suffixes=fileset.SOURCE_SUFFIXES,
        max_files=settings.max_files,
        max_file_bytes=settings.max_file_bytes,
        max_total_bytes=settings.max_total_bytes,
    )


def open_fixture(name: str, settings: Settings) -> Source:
    """Resolve an allowlisted local fixture directory.

    The name is matched against directories that actually exist under
    ``fixtures/``; traversal is not expressible because the user string is
    never joined onto a path.
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
    if not root.is_relative_to(FIXTURES_ROOT.resolve()):
        raise IngestError("INVALID_FIXTURE", "Fixture path escapes the fixtures directory.")

    collected = _collect(root, settings)
    if not collected.files:
        raise IngestError("EMPTY_SOURCE", f"Fixture '{name}' contains no supported source files.")

    return Source(
        kind="fixture",
        name=name,
        root=root,
        files=collected.files,
        metadata={"fixture": name},
        total_bytes=collected.total_bytes,
        skipped_oversized=collected.skipped_oversized,
    )


def open_repository(url: str, settings: Settings) -> Source:
    """Fetch and unpack a public GitHub repository into an isolated temp dir.

    Nothing is executed: the archive is downloaded, validated and extracted as
    data. On any failure the temp directory is removed before the error
    propagates.
    """
    try:
        ref = github.parse_repo_url(url)
    except github.InvalidRepoURL as error:
        raise IngestError("INVALID_REPO_URL", str(error)) from error

    fetcher = github.get_fetcher()
    resolved = fetcher.resolve(ref, settings)

    temporary = Path(tempfile.mkdtemp(prefix="capcheck-scan-"))
    archive = temporary / "source.zip"
    extract_dir = temporary / "src"

    try:
        archive_bytes = fetcher.download(resolved, archive, settings)
        extracted = github.safe_extract(archive, extract_dir, settings)
        root = github.effective_root(extract_dir)

        collected = _collect(root, settings)
        if not collected.files:
            raise IngestError(
                "EMPTY_SOURCE",
                "Repository contains no supported Python, JavaScript or TypeScript source files.",
            )

        return Source(
            kind="github",
            name=ref.slug,
            root=root,
            files=collected.files,
            temporary=temporary,
            commit_sha=resolved.commit_sha,
            total_bytes=collected.total_bytes,
            skipped_oversized=collected.skipped_oversized,
            metadata={
                "repo_url": ref.canonical_url,
                "owner": ref.owner,
                "repo": ref.repo,
                "default_branch": resolved.default_branch,
                "commit_sha": resolved.commit_sha,
                "archive_bytes": archive_bytes,
                "archive_entries": extracted.files,
                "archive_bytes_written": extracted.bytes_written,
                "skipped_symlinks": extracted.skipped_symlinks,
                "archive_skipped_oversized": extracted.skipped_oversized,
            },
        )
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
