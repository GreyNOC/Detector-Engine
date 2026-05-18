"""Safe, sandboxed shallow-clone utility for *defensive* content repositories.

Trust boundary (do not relax without updating docs/security_review.md):
  * **HTTPS only.** No ``ssh://``, ``git://``, ``file://``, scp-style ``user@host:`` URLs.
  * **Allowlist match required.** A per-source ``clone_allowlist`` of
    ``host/path-prefix`` entries gates which repos may be cloned.
  * **No redirects.** ``http.followRedirects=false`` so a hostile server
    cannot redirect us to an unallowlisted destination.
  * **Shallow.** ``--depth=1 --single-branch --no-tags --no-recurse-submodules``.
  * **No prompts, no hooks, no helpers.** Credential prompts, hooks, and
    credential helpers are explicitly neutered.
  * **Per-clone unique sandbox.** Each clone lands in a fresh random
    subdirectory so a pre-staged symlink at a predictable path cannot
    influence behavior.
  * **Subprocess timeout.** Default 60 s, configurable per source.
  * **No execution.** Cloning fetches blobs only. Walking and reading
    happens later under a content-extension allowlist with size caps.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

# Restrictive URL shape: scheme://host[:port]/path (no userinfo, no @, no
# query, no fragment, no IDN homograph tricks via non-ASCII). The allowlist
# check below catches everything this regex can't.
_SAFE_URL_RE = re.compile(r"^https://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9._\-/]+(?:\.git)?$")


class GitCloneError(RuntimeError):
    """A clone operation failed for an operational reason (timeout, network, git)."""


class GitCloneRefused(GitCloneError):
    """A clone was refused for a policy reason (URL shape or allowlist)."""


class GitCloner:
    """Shallow-clone an allowlisted https repo into a sandboxed directory."""

    def __init__(
        self,
        *,
        allowlist: Iterable[str],
        clone_root: Path | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.allowlist: list[str] = sorted({self._normalize(a) for a in allowlist if a})
        self.clone_root: Path = clone_root or Path(tempfile.gettempdir()) / "greynoc-clones"
        self.timeout_seconds = timeout_seconds

    # -- public API -----------------------------------------------------------

    def clone(self, url: str) -> Path:
        """Shallow-clone ``url``; raise GitCloneRefused on any policy violation."""
        if "@" in url or "%40" in url.lower():
            raise GitCloneRefused(f"URL contains userinfo / @ token: {url!r}")
        if not _SAFE_URL_RE.match(url):
            raise GitCloneRefused(f"URL fails strict format check: {url!r}")
        if not self.is_allowed(url):
            raise GitCloneRefused(f"URL not on allowlist: {url!r}")

        self.clone_root.mkdir(parents=True, exist_ok=True)
        target = self._unique_target(url)

        # Per-clone scratch HOME so we never read the user's `.gitconfig`.
        scratch_home = target.parent / f".home-{secrets.token_hex(4)}"
        scratch_home.mkdir(parents=True, exist_ok=True)
        env = self._safe_env(scratch_home)

        cmd = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.version=2",
            "-c",
            "submodule.recurse=false",
            "-c",
            "credential.helper=",
            "-c",
            "http.followRedirects=false",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            "--no-recurse-submodules",
            "--filter=blob:none",
            url,
            str(target),
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                env=env,
                check=False,
            )
        except FileNotFoundError as exc:
            shutil.rmtree(scratch_home, ignore_errors=True)
            raise GitCloneError(
                "git executable not found in PATH; install git or use a fixture directory"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(target, ignore_errors=True)
            shutil.rmtree(scratch_home, ignore_errors=True)
            raise GitCloneError(f"git clone timed out for {url!r}") from exc
        finally:
            shutil.rmtree(scratch_home, ignore_errors=True)
        if result.returncode != 0:
            shutil.rmtree(target, ignore_errors=True)
            raise GitCloneError(
                f"git clone failed (exit {result.returncode}): {result.stderr.strip()}"
            )
        return target

    def is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        if "@" in parsed.netloc:
            return False
        host_and_path = self._normalize(f"{parsed.netloc}{parsed.path}")
        return any(host_and_path.startswith(prefix) for prefix in self.allowlist)

    def cleanup(self, path: Path) -> None:
        """Remove a previously-cloned directory; safe to call repeatedly.

        Defense-in-depth: ``resolve()`` follows symlinks so an attacker who
        replaced the clone target with a symlink cannot trick us into
        deleting an arbitrary path outside ``clone_root``.
        """
        if not path or not path.exists():
            return
        try:
            resolved = path.resolve()
            resolved.relative_to(self.clone_root.resolve())
        except (OSError, ValueError):
            return
        shutil.rmtree(resolved, ignore_errors=True)

    # -- helpers --------------------------------------------------------------

    def _unique_target(self, url: str) -> Path:
        slug = self._safe_dirname(url)
        unique = f"{slug}-{secrets.token_hex(8)}"
        target = self.clone_root / unique
        # Vanishingly unlikely to collide; if it does, fail closed.
        if target.exists():
            raise GitCloneError(f"clone target collision: {target}")
        return target

    @staticmethod
    def _normalize(value: str) -> str:
        text = value.strip().lower().rstrip("/")
        if text.startswith("https://"):
            text = text[len("https://") :]
        if text.endswith(".git"):
            text = text[: -len(".git")]
        return text

    @staticmethod
    def _safe_dirname(url: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", url)
        return slug[-80:]

    @staticmethod
    def _safe_env(scratch_home: Path) -> dict[str, str]:
        # Minimal environment so cloning never inherits credentials, proxies,
        # or user-side .gitconfig that we did not explicitly authorize.
        env: dict[str, str] = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "echo",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(scratch_home / ".gitconfig"),
            "HOME": str(scratch_home),
        }
        # Windows-specific essentials. We intentionally omit USERPROFILE so
        # git does not search the user's home for .gitconfig either.
        for key in ("SYSTEMROOT", "TEMP", "TMP", "LOCALAPPDATA"):
            if key in os.environ:
                env[key] = os.environ[key]
        return env
