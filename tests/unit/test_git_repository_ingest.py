from __future__ import annotations

from pathlib import Path

import pytest

from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.ingest.base import IngestSourceUnavailable
from greynoc_detector_engine.ingest.git_clone import (
    GitCloner,
    GitCloneRefused,
)
from greynoc_detector_engine.ingest.git_repository import GitRepositoryIngestor
from greynoc_detector_engine.models.source import (
    SourceCategory,
    SourceConfig,
    SourceType,
)

FIXTURE_REPO = Path("data/fixtures/sample_rules_repo")


def _source(metadata: dict[str, object] | None = None) -> SourceConfig:
    return SourceConfig(
        id="test-repo",
        name="Test repo",
        category=SourceCategory.SECURITY_RESEARCH_BLOG,
        type=SourceType.GIT_REPOSITORY,
        url="https://github.com/example/sample.git",
        metadata=metadata
        or {
            "clone_allowlist": ["github.com/example/sample"],
            "content_extensions": [".yml", ".yaml", ".yar", ".yara", ".md"],
            "max_file_size_kb": 256,
            "max_total_size_mb": 100,
        },
    )


def test_git_repository_ingestor_walks_fixture_directory(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "t.sqlite")
    items = GitRepositoryIngestor(_source(), settings, fixture_path=FIXTURE_REPO).ingest()
    titles = {item.title for item in items}
    assert any("proc_creation_win_mimikatz.yml" in t for t in titles)
    assert any("demo.yar" in t for t in titles)
    assert any("README.md" in t for t in titles)


def test_git_repository_ingestor_skips_forbidden_extensions(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "t.sqlite")
    items = GitRepositoryIngestor(_source(), settings, fixture_path=FIXTURE_REPO).ingest()
    for item in items:
        assert not item.title.endswith(".py"), "Python files must never be ingested"


def test_git_repository_ingestor_skips_dot_git_directory(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "t.sqlite")
    items = GitRepositoryIngestor(_source(), settings, fixture_path=FIXTURE_REPO).ingest()
    for item in items:
        assert "/.git/" not in item.title, ".git/ contents must never leak into ingestion"


def test_git_repository_ingestor_requires_directory(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "t.sqlite")
    # Point fixture_path at a file, not a directory
    fake_file = tmp_path / "not_a_repo.txt"
    fake_file.write_text("hi")
    with pytest.raises(IngestSourceUnavailable):
        GitRepositoryIngestor(_source(), settings, fixture_path=fake_file).ingest()


def test_git_cloner_refuses_non_https_urls() -> None:
    cloner = GitCloner(allowlist=["github.com/example/sample"])
    with pytest.raises(GitCloneRefused):
        cloner.clone("git://github.com/example/sample.git")
    with pytest.raises(GitCloneRefused):
        cloner.clone("ssh://git@github.com/example/sample.git")
    with pytest.raises(GitCloneRefused):
        cloner.clone("file:///etc/passwd")


def test_git_cloner_refuses_off_allowlist_urls() -> None:
    cloner = GitCloner(allowlist=["github.com/example/sample"])
    with pytest.raises(GitCloneRefused):
        cloner.clone("https://github.com/attacker/evil.git")


def test_git_cloner_refuses_urls_with_userinfo() -> None:
    cloner = GitCloner(allowlist=["github.com/example/sample"])
    with pytest.raises(GitCloneRefused):
        cloner.clone("https://user:token@github.com/example/sample.git")


def test_git_cloner_is_allowed_helper() -> None:
    cloner = GitCloner(allowlist=["github.com/SigmaHQ/sigma"])
    assert cloner.is_allowed("https://github.com/SigmaHQ/sigma.git")
    assert cloner.is_allowed("https://github.com/sigmahq/sigma")  # case-insensitive
    assert not cloner.is_allowed("https://github.com/sigmahq/other")
    assert not cloner.is_allowed("https://github.com/sigmahq/sigma-evil")
    assert not cloner.is_allowed("https://github.com/sigmahq/sigma/../other")
    assert not cloner.is_allowed("http://github.com/SigmaHQ/sigma.git")


def test_live_clone_without_allowlist_is_refused(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "t.sqlite", fetch_live=True)
    cfg = SourceConfig(
        id="no-allowlist",
        name="No allowlist",
        category=SourceCategory.SECURITY_RESEARCH_BLOG,
        type=SourceType.GIT_REPOSITORY,
        url="https://github.com/example/anything.git",
        metadata={},  # NO clone_allowlist
    )
    with pytest.raises(IngestSourceUnavailable, match="clone_allowlist"):
        GitRepositoryIngestor(cfg, settings).ingest()


def test_max_total_size_caps_collection(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "t.sqlite")
    capped = _source(
        {
            "clone_allowlist": ["github.com/example/sample"],
            "content_extensions": [".yml", ".yaml", ".yar", ".yara", ".md"],
            "max_file_size_kb": 256,
            "max_total_size_mb": 0,  # immediate cap
        }
    )
    items = GitRepositoryIngestor(capped, settings, fixture_path=FIXTURE_REPO).ingest()
    assert items == []
