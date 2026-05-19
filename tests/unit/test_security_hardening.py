from __future__ import annotations

from pathlib import Path

import pytest

from greynoc_detector_engine.api.safety import validate_fixture_path
from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.detection.safety import (
    sanitize_rule_term,
    sanitize_rule_terms,
)
from greynoc_detector_engine.ingest.base import BaseIngestor, IngestSourceUnavailable
from greynoc_detector_engine.ingest.git_clone import GitCloner, GitCloneRefused
from greynoc_detector_engine.models.source import SourceCategory, SourceConfig, SourceType
from greynoc_detector_engine.spacestation.honeypot import HoneypotConfig
from greynoc_detector_engine.utils.http import DefensiveHttpClient, HttpFetchError


class _DummyIngestor(BaseIngestor[object]):
    def ingest(self) -> list[object]:
        return []


def _source_config() -> SourceConfig:
    return SourceConfig(
        id="test-source",
        name="Test Source",
        category=SourceCategory.CVE,
        type=SourceType.CVE_JSON,
        url="https://good.example/feed.json",
    )


def test_sanitize_rule_term_strips_quotes_and_newlines() -> None:
    assert sanitize_rule_term('CVE-2026-12345"; DROP TABLE--') == "CVE-2026-12345 DROP TABLE--"
    # Newlines and tabs are dropped.
    assert sanitize_rule_term("foo\nbar") == "foobar"
    # Empty input is safe.
    assert sanitize_rule_term("") == ""
    # Very long input is bounded.
    assert len(sanitize_rule_term("A" * 500)) <= 96


def test_sanitize_rule_terms_dedupes_and_caps() -> None:
    out = sanitize_rule_terms(["CVE-1", "CVE-1", "CVE-2", "x" * 200], max_terms=2)
    assert out == ["CVE-1", "CVE-2"]


def test_honeypot_refuses_external_bind_without_opt_in() -> None:
    with pytest.raises(ValueError, match="not loopback"):
        from greynoc_detector_engine.spacestation.honeypot import DarknetHoneypot

        DarknetHoneypot(HoneypotConfig(bind_host="0.0.0.0", port=4242))


def test_honeypot_accepts_external_bind_with_opt_in() -> None:
    from greynoc_detector_engine.spacestation.honeypot import DarknetHoneypot

    # Construction must succeed; we don't actually start the listener.
    DarknetHoneypot(HoneypotConfig(bind_host="0.0.0.0", port=4242, allow_external_bind=True))


def test_git_cloner_refuses_userinfo_in_url() -> None:
    cloner = GitCloner(allowlist=["github.com/example/sample"])
    with pytest.raises(GitCloneRefused):
        cloner.clone("https://attacker%40github.com/example/sample.git")


def test_git_cloner_unique_target_per_call(tmp_path: Path) -> None:
    cloner = GitCloner(
        allowlist=["github.com/example/sample"],
        clone_root=tmp_path / "clones",
    )
    a = cloner._unique_target("https://github.com/example/sample.git")
    b = cloner._unique_target("https://github.com/example/sample.git")
    assert a != b


def test_validate_fixture_path_refuses_traversal(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "t.sqlite", data_dir=tmp_path / "data")
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "ok.json").write_text("{}", encoding="utf-8")

    inside = validate_fixture_path(str(settings.data_dir / "ok.json"), settings)
    assert inside is not None

    # Path outside the allowed roots → 400.
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        validate_fixture_path(str(tmp_path / "outside.json"), settings)


def test_validate_fixture_path_returns_none_when_omitted(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "t.sqlite", data_dir=tmp_path / "data")
    assert validate_fixture_path(None, settings) is None
    assert validate_fixture_path("", settings) is None


def test_http_redirects_must_stay_allowlisted() -> None:
    client = DefensiveHttpClient(
        timeout_seconds=1.0,
        user_agent="test",
        allowed_hosts=["good.example"],
    )

    assert (
        client._resolve_redirect_url(
            "https://good.example/feed",
            "/next",
            original_url="https://good.example/feed",
        )
        == "https://good.example/next"
    )

    with pytest.raises(HttpFetchError, match="allowed_fetch_hosts"):
        client._resolve_redirect_url(
            "https://good.example/feed",
            "https://evil.example/metadata",
            original_url="https://good.example/feed",
        )


def test_http_redirects_reject_cross_host_without_allowlist() -> None:
    client = DefensiveHttpClient(timeout_seconds=1.0, user_agent="test")

    with pytest.raises(HttpFetchError, match="cross-host redirect refused"):
        client._resolve_redirect_url(
            "https://good.example/feed",
            "https://evil.example/metadata",
            original_url="https://good.example/feed",
        )


def test_fixture_reads_are_size_bounded(tmp_path: Path) -> None:
    fixture = tmp_path / "too-large.json"
    fixture.write_text("x" * 1025, encoding="utf-8")
    settings = Settings(database_path=tmp_path / "t.sqlite", max_response_bytes=1024)
    ingestor = _DummyIngestor(_source_config(), settings, fixture_path=fixture)

    with pytest.raises(IngestSourceUnavailable, match="GREYNOC_MAX_RESPONSE_BYTES"):
        ingestor.load_text_payload()
