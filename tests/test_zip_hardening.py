"""Archive hardening tests.

Each test builds a hostile or oversized ZIP locally and asserts that
``safe_extract`` refuses to escape the scan directory, refuses to write
symlinks, and enforces every size limit.
"""

from __future__ import annotations

import ast
import os
import stat
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from backend.config import settings as base_settings
from backend.core import fileset, github
from backend.core.errors import IngestError


def _settings(**changes):
    return replace(base_settings, **changes)


def _zip(tmp_path: Path, entries: list[tuple[object, bytes | str]]) -> Path:
    archive = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in entries:
            bundle.writestr(name, data)
    return archive


def _symlink_entry(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return info


# --------------------------------------------------------------------------
# Path traversal and absolute paths
# --------------------------------------------------------------------------


def test_parent_directory_traversal_is_rejected(tmp_path):
    archive = _zip(tmp_path, [("pkg/../../evil.txt", "owned")])
    with pytest.raises(IngestError) as caught:
        github.safe_extract(archive, tmp_path / "dest", _settings())
    assert caught.value.code == "ARCHIVE_TRAVERSAL"
    assert not (tmp_path / "evil.txt").exists()


def test_nested_traversal_is_rejected(tmp_path):
    archive = _zip(tmp_path, [("pkg/sub/../../../evil.txt", "owned")])
    with pytest.raises(IngestError) as caught:
        github.safe_extract(archive, tmp_path / "dest", _settings())
    assert caught.value.code == "ARCHIVE_TRAVERSAL"


def test_absolute_path_is_rejected(tmp_path):
    archive = _zip(tmp_path, [("/etc/evil.txt", "owned")])
    with pytest.raises(IngestError) as caught:
        github.safe_extract(archive, tmp_path / "dest", _settings())
    assert caught.value.code == "ARCHIVE_UNSAFE_PATH"


def test_windows_drive_letter_is_rejected(tmp_path):
    archive = _zip(tmp_path, [("C:/evil.txt", "owned")])
    with pytest.raises(IngestError) as caught:
        github.safe_extract(archive, tmp_path / "dest", _settings())
    assert caught.value.code == "ARCHIVE_UNSAFE_PATH"


def test_backslash_path_is_rejected(tmp_path):
    # ``zipfile`` normalises backslashes to "/" on Windows, so the archive
    # route may surface as traversal; either way it is rejected. The validator
    # itself is tested directly below.
    archive = _zip(tmp_path, [("pkg\\..\\evil.txt", "owned")])
    with pytest.raises(IngestError) as caught:
        github.safe_extract(archive, tmp_path / "dest", _settings())
    assert caught.value.code in {"ARCHIVE_UNSAFE_PATH", "ARCHIVE_TRAVERSAL"}


def test_backslash_entry_name_is_rejected_by_the_validator():
    with pytest.raises(IngestError) as caught:
        github._entry_parts("pkg\\..\\evil.txt")
    assert caught.value.code == "ARCHIVE_UNSAFE_PATH"


def test_dotdot_entry_name_is_rejected_by_the_validator():
    with pytest.raises(IngestError) as caught:
        github._entry_parts("pkg/../../evil.txt")
    assert caught.value.code == "ARCHIVE_TRAVERSAL"


# --------------------------------------------------------------------------
# Symlinks
# --------------------------------------------------------------------------


def test_symlink_entries_are_skipped_not_written(tmp_path):
    archive = _zip(
        tmp_path,
        [
            (_symlink_entry("pkg/link-to-passwd"), "/etc/passwd"),
            ("pkg/server.js", "console.log(1);\n"),
        ],
    )
    destination = tmp_path / "dest"
    result = github.safe_extract(archive, destination, _settings())

    assert result.skipped_symlinks == 1
    assert result.files == 1
    assert (destination / "pkg" / "server.js").is_file()
    assert not (destination / "pkg" / "link-to-passwd").exists()


# --------------------------------------------------------------------------
# Size and count limits
# --------------------------------------------------------------------------


def test_entry_count_limit_is_enforced(tmp_path):
    entries = [(f"pkg/file{i}.js", "x") for i in range(5)]
    archive = _zip(tmp_path, entries)
    with pytest.raises(IngestError) as caught:
        github.safe_extract(archive, tmp_path / "dest", _settings(max_archive_entries=4))
    assert caught.value.code == "ARCHIVE_TOO_LARGE"


def test_oversized_file_is_skipped_not_extracted(tmp_path):
    archive = _zip(
        tmp_path,
        [
            ("pkg/huge.bin", b"0" * 2_000_000),
            ("pkg/server.js", "console.log(1);\n"),
        ],
    )
    destination = tmp_path / "dest"
    result = github.safe_extract(
        archive, destination, _settings(max_file_bytes=1_000_000)
    )
    assert result.skipped_oversized == 1
    assert result.files == 1
    assert not (destination / "pkg" / "huge.bin").exists()


def test_compression_bomb_is_rejected(tmp_path):
    # 1 MB of zeros compresses far beyond a 50:1 ratio.
    archive = _zip(tmp_path, [("pkg/bomb.bin", b"\x00" * 1_000_000)])
    with pytest.raises(IngestError) as caught:
        github.safe_extract(
            archive,
            tmp_path / "dest",
            _settings(
                max_file_bytes=2_000_000,
                max_total_bytes=20_000_000,
                max_compression_ratio=50,
            ),
        )
    assert caught.value.code == "ARCHIVE_BOMB"


def test_total_expanded_size_limit_is_enforced(tmp_path):
    archive = _zip(
        tmp_path,
        [
            ("pkg/a.bin", os.urandom(400_000)),
            ("pkg/b.bin", os.urandom(400_000)),
            ("pkg/c.bin", os.urandom(400_000)),
        ],
    )
    with pytest.raises(IngestError) as caught:
        github.safe_extract(
            archive,
            tmp_path / "dest",
            _settings(
                max_file_bytes=1_000_000,
                max_total_bytes=1_000_000,
                max_compression_ratio=10_000,
            ),
        )
    assert caught.value.code == "ARCHIVE_TOO_LARGE"


def test_invalid_archive_is_rejected(tmp_path):
    archive = tmp_path / "archive.zip"
    archive.write_text("this is not a zip", encoding="utf-8")
    with pytest.raises(IngestError) as caught:
        github.safe_extract(archive, tmp_path / "dest", _settings())
    assert caught.value.code == "ARCHIVE_INVALID"


# --------------------------------------------------------------------------
# Successful extraction and file enumeration
# --------------------------------------------------------------------------


def test_github_top_level_directory_is_detected(tmp_path):
    archive = _zip(tmp_path, [("repo-abc1234/server.ts", "export {};\n")])
    destination = tmp_path / "dest"
    result = github.safe_extract(archive, destination, _settings())
    assert result.files == 1
    root = github.effective_root(destination)
    assert root.name == "repo-abc1234"
    assert (root / "server.ts").is_file()


def test_collect_files_enforces_count_and_size(tmp_path):
    for index in range(5):
        (tmp_path / f"file{index}.js").write_text("console.log(1);\n", encoding="utf-8")
    (tmp_path / "big.js").write_text("x" * 2000, encoding="utf-8")

    result = fileset.collect_files(
        tmp_path,
        suffixes=fileset.SOURCE_SUFFIXES,
        max_files=3,
        max_file_bytes=1000,
        max_total_bytes=10_000,
    )
    assert len(result.files) == 3
    assert result.skipped_oversized == 1
    assert all(path.suffix == ".js" for path in result.files)


def test_backend_never_calls_zipfile_extractall():
    offenders = []
    for path in sorted(Path("backend").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"extractall", "extract"}
            ):
                offenders.append(f"{path}:{node.lineno}")
    assert offenders == []
