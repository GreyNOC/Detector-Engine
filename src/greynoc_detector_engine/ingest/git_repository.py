"""Ingest defensive content from an allowlisted git repository.

The ingestor either:
  * Uses ``fixture_path`` (a local directory) — for tests and offline dev.
  * Clones the source URL via :class:`GitCloner` — opt-in, allowlist-gated,
    HTTPS-only, shallow, sandboxed, never executed.

Walking is restricted to a content-extension allowlist (yml/yaml/yara/yar/
rules/json/md/txt by default) with per-file and total size caps. Symlinks
are skipped entirely so a hostile repo cannot escape the sandbox via a
``rules -> /etc/passwd`` symlink trick.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

from greynoc_detector_engine.ingest.base import BaseIngestor, IngestSourceUnavailable
from greynoc_detector_engine.ingest.git_clone import (
    GitCloneError,
    GitCloner,
    GitCloneRefused,
)
from greynoc_detector_engine.models.source import SourceItem
from greynoc_detector_engine.normalize.normalizer import SourceItemNormalizer
from greynoc_detector_engine.utils.text import make_excerpt

DEFAULT_CONTENT_EXTENSIONS: tuple[str, ...] = (
    ".yml",
    ".yaml",
    ".yara",
    ".yar",
    ".rules",
    ".json",
    ".md",
    ".txt",
)

SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".github",
        ".idea",
        ".vscode",
        "__pycache__",
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".env",
        "dist",
        "build",
        "target",
    }
)

FORBIDDEN_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".pyc",
        ".pyo",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".elf",
        ".o",
        ".a",
        ".lib",
        ".jar",
        ".class",
        ".vbs",
        ".js",
        ".mjs",
        ".cjs",
        ".html",
        ".htm",
        ".php",
        ".pl",
        ".rb",
        ".scpt",
        ".app",
        ".msi",
        ".apk",
        ".ipa",
    }
)


class GitRepositoryIngestor(BaseIngestor[SourceItem]):
    """Harvest text content from an allowlisted defensive-content git repo."""

    def ingest(self) -> list[SourceItem]:
        clone_path, cleanup_after = self._resolve_clone_path()
        cloner: GitCloner | None = None
        if cleanup_after:
            cloner = self._build_cloner()
        try:
            return list(self._walk(clone_path))
        finally:
            if cleanup_after and cloner is not None:
                cloner.cleanup(clone_path)

    # -- internals ------------------------------------------------------------

    def _resolve_clone_path(self) -> tuple[Path, bool]:
        if self.fixture_path is not None:
            if not self.fixture_path.is_dir():
                raise IngestSourceUnavailable(
                    f"Expected a repository directory fixture for "
                    f"{self.source_config.source_id}; got file {self.fixture_path}"
                )
            return self.fixture_path, False

        if not self.settings.fetch_live:
            raise IngestSourceUnavailable(
                f"{self.source_config.source_id} requires a fixture directory or "
                "GREYNOC_FETCH_LIVE=true"
            )
        if not self.source_config.url:
            raise IngestSourceUnavailable(f"{self.source_config.source_id} has no configured URL")

        cloner = self._build_cloner()
        try:
            target = cloner.clone(self.source_config.url)
        except GitCloneRefused as exc:
            raise IngestSourceUnavailable(f"Clone refused by policy: {exc}") from exc
        except GitCloneError as exc:
            raise IngestSourceUnavailable(str(exc)) from exc
        cleanup_after = bool(self.source_config.metadata.get("cleanup_after_ingest", True))
        return target, cleanup_after

    def _build_cloner(self) -> GitCloner:
        raw_allowlist = self.source_config.metadata.get("clone_allowlist") or []
        if not isinstance(raw_allowlist, list) or not raw_allowlist:
            raise IngestSourceUnavailable(
                f"{self.source_config.source_id} has no clone_allowlist; "
                "refusing to clone arbitrary repos."
            )
        timeout = float(self.source_config.metadata.get("clone_timeout_s", 60.0))
        return GitCloner(allowlist=raw_allowlist, timeout_seconds=timeout)

    def _walk(self, root: Path) -> Iterator[SourceItem]:
        normalizer = SourceItemNormalizer()
        configured = self.source_config.metadata.get("content_extensions")
        exts: tuple[str, ...] = (
            tuple(str(e).lower() for e in configured)
            if isinstance(configured, list) and configured
            else DEFAULT_CONTENT_EXTENSIONS
        )
        max_file_bytes = int(self.source_config.metadata.get("max_file_size_kb", 256)) * 1024
        max_total_bytes = (
            int(self.source_config.metadata.get("max_total_size_mb", 100)) * 1024 * 1024
        )
        total = 0
        try:
            root_resolved = root.resolve(strict=True)
        except OSError:
            return

        # followlinks=False keeps os.walk from descending through symlinked
        # directories; lstat below skips symlink files too.
        for dirpath, dirnames, filenames in os.walk(root_resolved, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for filename in filenames:
                lower = filename.lower()
                ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
                if ext in FORBIDDEN_EXTENSIONS:
                    continue
                if not lower.endswith(exts):
                    continue
                file_path = Path(dirpath) / filename
                try:
                    lst = file_path.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(lst.st_mode):
                    # Skip symlinks, sockets, FIFOs, block/char devices.
                    continue
                try:
                    resolved = file_path.resolve(strict=True)
                    resolved.relative_to(root_resolved)
                except (OSError, ValueError):
                    continue
                size = lst.st_size
                if size > max_file_bytes:
                    continue
                if total + size > max_total_bytes:
                    return
                total += size
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                rel = file_path.relative_to(root_resolved).as_posix()
                yield normalizer.normalize(
                    self.source_config,
                    title=f"{self.source_config.source_id}:{rel}",
                    content=make_excerpt(content, max_chars=3500),
                    url=self.source_config.url,
                    metadata={
                        "repo_path": rel,
                        "size_bytes": size,
                        "ingest_mode": "git_repository",
                    },
                )
