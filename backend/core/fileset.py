"""Language-agnostic file enumeration and classification.

Both the Python and JavaScript/TypeScript analyzers consume files discovered
here, so limits and symlink handling stay identical across languages.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PYTHON_SUFFIXES = frozenset({".py"})
JAVASCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs"})
TYPESCRIPT_SUFFIXES = frozenset({".ts", ".tsx"})
SOURCE_SUFFIXES = PYTHON_SUFFIXES | JAVASCRIPT_SUFFIXES | TYPESCRIPT_SUFFIXES

_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

_GRAMMAR_BY_SUFFIX = {
    ".ts": "typescript",
    ".tsx": "tsx",
}


@dataclass
class FileSet:
    files: list[Path]
    total_bytes: int
    skipped_oversized: int


def language_for(path: Path) -> str | None:
    return _LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def grammar_for(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return None
    return _GRAMMAR_BY_SUFFIX.get(suffix, "javascript")


def collect_files(
    root: Path,
    *,
    suffixes: frozenset[str],
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> FileSet:
    """Enumerate source files under ``root`` with hard caps.

    Symlinks resolving outside the root are skipped. Oversized individual
    files are skipped and counted, so the report can state that analysis was
    partial rather than pretending the file did not exist.
    """
    resolved_root = root.resolve()
    files: list[Path] = []
    total = 0
    skipped_oversized = 0

    for candidate in sorted(root.rglob("*")):
        if candidate.suffix.lower() not in suffixes:
            continue
        try:
            if candidate.is_symlink():
                continue
            resolved = candidate.resolve()
            if not resolved.is_relative_to(resolved_root):
                continue
            if not candidate.is_file():
                continue
            size = candidate.stat().st_size
        except OSError:
            continue

        if size > max_file_bytes:
            skipped_oversized += 1
            continue
        if len(files) >= max_files:
            break
        if total + size > max_total_bytes:
            break

        files.append(candidate)
        total += size

    return FileSet(files=files, total_bytes=total, skipped_oversized=skipped_oversized)


def relative_path(path: Path, root: Path) -> str:
    """Path relative to the source root, POSIX-style, never absolute.

    Evidence paths go through this function so the API can never leak a temp
    directory or a developer's home directory.
    """
    return path.resolve().relative_to(root.resolve()).as_posix()
