"""Public GitHub source acquisition without ``git`` and without execution.

Design decisions:

* **No ``git clone``.** We resolve the default branch and commit through the
  GitHub REST API, then download the source archive from codeload. There are
  no hooks to fire, no submodules to recurse into, no ``.git`` directory to
  leak, and no git binary in the untrusted path.
* **No ``extractall``.** Extraction is manual so every entry is validated
  before a byte is written: path traversal, absolute paths, drive letters,
  backslashes, symlinks, encryption, declared and actual size, entry count,
  compression ratio and destination containment.
* **No execution.** Nothing here imports repository code or runs package
  managers or build scripts.

The fetcher is behind a small protocol so tests can inject a fake and stay
fully offline.
"""

from __future__ import annotations

import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, urlsplit

import httpx

from backend.config import Settings, settings
from backend.core.errors import IngestError

OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_HOSTS = frozenset({"github.com", "www.github.com", "api.github.com", "codeload.github.com"})
ALLOWED_HOST_SUFFIXES = (".githubusercontent.com",)
CHUNK = 64 * 1024
USER_AGENT = "CapCheck/0.2 (+https://github.com/guchchi/CapCheck)"


class InvalidRepoURL(ValueError):
    """The supplied repository URL is not an acceptable public GitHub URL."""


@dataclass(frozen=True)
class RepoRef:
    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def canonical_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"


@dataclass(frozen=True)
class ResolvedRepo:
    ref: RepoRef
    commit_sha: str
    default_branch: str

    @property
    def archive_url(self) -> str:
        return (
            f"https://codeload.github.com/{self.ref.owner}/{self.ref.repo}/zip/"
            f"{self.commit_sha}"
        )


def parse_repo_url(raw: str) -> RepoRef:
    """Validate a public GitHub repository URL, strictly.

    Rejected: non-HTTPS schemes, any host other than github.com, embedded
    credentials, explicit ports, IP literals, query strings, fragments, extra
    path segments, and malformed owner/repository names.
    """
    if not isinstance(raw, str):
        raise InvalidRepoURL("Repository URL must be a string.")

    url = raw.strip()
    if not url:
        raise InvalidRepoURL("Repository URL is empty.")
    if len(url) > 200:
        raise InvalidRepoURL("Repository URL is too long.")
    if any(char.isspace() for char in url):
        raise InvalidRepoURL("Repository URL must not contain whitespace.")

    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise InvalidRepoURL("Only https:// GitHub URLs are supported.")
    if parts.username is not None or parts.password is not None:
        raise InvalidRepoURL("Repository URLs must not contain credentials.")
    if parts.port is not None:
        raise InvalidRepoURL("Repository URLs must not specify a port.")

    host = (parts.hostname or "").lower()
    if host not in {"github.com", "www.github.com"}:
        raise InvalidRepoURL("Only github.com repositories are supported.")

    if parts.query or parts.fragment:
        raise InvalidRepoURL("Repository URLs must not contain a query or fragment.")

    segments = [segment for segment in parts.path.split("/") if segment]
    if len(segments) != 2:
        raise InvalidRepoURL(
            "Expected a repository URL of the form https://github.com/owner/repository."
        )

    owner, repo = segments
    if repo.endswith(".git"):
        repo = repo[:-4]

    if not OWNER_RE.match(owner) or owner.endswith("-"):
        raise InvalidRepoURL(f"Invalid GitHub owner name: '{owner}'.")
    if not REPO_RE.match(repo) or repo in {".", ".."}:
        raise InvalidRepoURL(f"Invalid GitHub repository name: '{repo}'.")

    return RepoRef(owner=owner, repo=repo)


class ArchiveFetcher(Protocol):
    def resolve(self, ref: RepoRef, settings: Settings) -> ResolvedRepo: ...

    def download(self, resolved: ResolvedRepo, destination: Path, settings: Settings) -> int: ...


def _assert_allowed_host(url: str) -> None:
    host = (urlsplit(url).hostname or "").lower()
    if host in ALLOWED_HOSTS:
        return
    if host.endswith(ALLOWED_HOST_SUFFIXES):
        return
    raise IngestError(
        "UNSAFE_REDIRECT",
        f"Refusing to follow a redirect to unexpected host '{host}'.",
    )


class HttpxFetcher:
    """GitHub REST + codeload fetcher.

    An optional ``CAPCHECK_GITHUB_TOKEN`` raises the API rate limit. It is only
    ever sent in a request header; it is never written to scan artifacts.
    """

    def __init__(self, timeout_seconds: int = 30) -> None:
        self.timeout = httpx.Timeout(timeout_seconds)
        self._client: httpx.Client | None = None

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.environ.get("CAPCHECK_GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _client_or_create(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _get_json(self, url: str) -> dict:
        client = self._client_or_create()
        try:
            response = client.get(url, headers=self._headers(), timeout=self.timeout)
        except httpx.HTTPError as error:
            raise IngestError("GITHUB_UNREACHABLE", f"GitHub request failed: {error}") from error
        _assert_allowed_host(str(response.url))

        if response.status_code == 404:
            raise IngestError("REPO_NOT_FOUND", "Repository was not found or is not public.")
        if response.status_code in {403, 429}:
            raise IngestError(
                "GITHUB_RATE_LIMITED",
                "GitHub API rate limit reached. Try again later or set CAPCHECK_GITHUB_TOKEN.",
            )
        if response.status_code >= 400:
            raise IngestError(
                "GITHUB_API_ERROR",
                f"GitHub API returned HTTP {response.status_code}.",
            )
        try:
            payload = response.json()
        except ValueError as error:
            raise IngestError("GITHUB_API_ERROR", "GitHub returned invalid JSON.") from error
        if not isinstance(payload, dict):
            raise IngestError("GITHUB_API_ERROR", "GitHub returned an unexpected payload.")
        return payload

    def resolve(self, ref: RepoRef, settings: Settings) -> ResolvedRepo:
        api = settings.github_api_base.rstrip("/")
        metadata = self._get_json(f"{api}/repos/{ref.owner}/{ref.repo}")

        if metadata.get("private") is True:
            raise IngestError("REPO_NOT_PUBLIC", "Only public repositories can be scanned.")

        default_branch = metadata.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            raise IngestError("REPO_METADATA_INVALID", "Repository has no default branch.")

        commit = self._get_json(
            f"{api}/repos/{ref.owner}/{ref.repo}/commits/{quote(default_branch, safe='')}"
        )
        sha = commit.get("sha")
        if not isinstance(sha, str) or not SHA_RE.match(sha):
            raise IngestError("REPO_METADATA_INVALID", "Repository commit SHA was invalid.")

        return ResolvedRepo(ref=ref, commit_sha=sha, default_branch=default_branch)

    def download(self, resolved: ResolvedRepo, destination: Path, settings: Settings) -> int:
        client = self._client_or_create()
        written = 0
        try:
            with client.stream(
                "GET",
                resolved.archive_url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                follow_redirects=True,
            ) as response:
                _assert_allowed_host(str(response.url))
                if response.status_code == 404:
                    raise IngestError("ARCHIVE_NOT_FOUND", "Source archive was not available.")
                if response.status_code >= 400:
                    raise IngestError(
                        "ARCHIVE_DOWNLOAD_FAILED",
                        f"Archive download returned HTTP {response.status_code}.",
                    )
                with destination.open("wb") as handle:
                    for chunk in response.iter_bytes(CHUNK):
                        written += len(chunk)
                        if written > settings.max_archive_bytes:
                            raise IngestError(
                                "ARCHIVE_TOO_LARGE",
                                f"Archive exceeds {settings.max_archive_bytes} bytes.",
                            )
                        handle.write(chunk)
        except httpx.HTTPError as error:
            raise IngestError(
                "ARCHIVE_DOWNLOAD_FAILED", f"Archive download failed: {error}"
            ) from error

        if written == 0:
            raise IngestError("ARCHIVE_EMPTY", "Downloaded archive was empty.")
        return written


@dataclass
class ExtractResult:
    files: int
    bytes_written: int
    skipped_symlinks: int
    skipped_oversized: int


def _entry_parts(name: str) -> list[str]:
    """Validate one archive entry name and split it into safe segments."""
    if "\x00" in name:
        raise IngestError("ARCHIVE_UNSAFE_PATH", "Archive entry contains a NUL byte.")
    if "\\" in name:
        raise IngestError("ARCHIVE_UNSAFE_PATH", "Archive entry contains a backslash.")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise IngestError("ARCHIVE_UNSAFE_PATH", "Archive entry uses an absolute path.")

    parts = [part for part in name.split("/") if part not in {"", "."}]
    if any(part == ".." for part in parts):
        raise IngestError("ARCHIVE_TRAVERSAL", "Archive entry attempts path traversal.")
    return parts


def safe_extract(archive: Path, destination: Path, settings: Settings) -> ExtractResult:
    """Extract a ZIP without trusting a single byte of its metadata."""
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()

    files = 0
    total = 0
    skipped_symlinks = 0
    skipped_oversized = 0

    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            if len(infos) > settings.max_archive_entries:
                raise IngestError(
                    "ARCHIVE_TOO_LARGE",
                    f"Archive contains {len(infos)} entries, limit is "
                    f"{settings.max_archive_entries}.",
                )

            for info in infos:
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    raise IngestError("ARCHIVE_ENCRYPTED", "Encrypted archives are rejected.")

                name = info.filename
                parts = _entry_parts(name)
                if not parts:
                    continue

                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    # Symlinks can point outside the scan directory. Skip them
                    # instead of failing the whole scan; a normal GitHub source
                    # archive does not need them.
                    skipped_symlinks += 1
                    continue

                if info.file_size > settings.max_file_bytes:
                    skipped_oversized += 1
                    continue

                if info.file_size > 0:
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > settings.max_compression_ratio:
                        raise IngestError(
                            "ARCHIVE_BOMB",
                            "Archive entry has an implausible compression ratio.",
                        )

                if total + info.file_size > settings.max_total_bytes:
                    raise IngestError(
                        "ARCHIVE_TOO_LARGE",
                        f"Archive expands beyond {settings.max_total_bytes} bytes.",
                    )

                target = destination.joinpath(*parts)
                try:
                    resolved = target.resolve()
                except OSError as error:
                    raise IngestError(
                        "ARCHIVE_UNSAFE_PATH", "Archive entry path could not be resolved."
                    ) from error
                if not resolved.is_relative_to(root):
                    raise IngestError(
                        "ARCHIVE_TRAVERSAL", "Archive entry escapes the scan directory."
                    )

                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with bundle.open(info) as source, target.open("wb") as sink:
                    while True:
                        chunk = source.read(CHUNK)
                        if not chunk:
                            break
                        written += len(chunk)
                        total += len(chunk)
                        # Enforce against actual bytes: declared sizes can lie.
                        if written > settings.max_file_bytes:
                            raise IngestError(
                                "ARCHIVE_TOO_LARGE",
                                "Archive entry exceeded the per-file size limit.",
                            )
                        if total > settings.max_total_bytes:
                            raise IngestError(
                                "ARCHIVE_TOO_LARGE",
                                "Archive expanded beyond the total size limit.",
                            )
                        sink.write(chunk)

                files += 1
    except zipfile.BadZipFile as error:
        raise IngestError("ARCHIVE_INVALID", "Downloaded file is not a valid ZIP archive.") from error

    return ExtractResult(
        files=files,
        bytes_written=total,
        skipped_symlinks=skipped_symlinks,
        skipped_oversized=skipped_oversized,
    )


def effective_root(destination: Path) -> Path:
    """Return the single top-level directory GitHub wraps archives in."""
    entries = list(destination.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return destination


_FETCHER: ArchiveFetcher | None = None


def get_fetcher() -> ArchiveFetcher:
    """Return the process fetcher. Tests monkeypatch this function."""
    global _FETCHER
    if _FETCHER is None:
        _FETCHER = HttpxFetcher(timeout_seconds=settings.fetch_timeout_seconds)
    return _FETCHER


def set_fetcher(fetcher: ArchiveFetcher | None) -> None:
    """Inject a fetcher (used by tests and by the API in future)."""
    global _FETCHER
    _FETCHER = fetcher
