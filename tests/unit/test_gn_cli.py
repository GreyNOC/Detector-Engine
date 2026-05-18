from __future__ import annotations

from greynoc_detector_engine.cli.gn import _normalize_args


def test_gn_separator_is_removed() -> None:
    assert _normalize_args(["gn", "-", "doctor"]) == ["gn", "doctor"]


def test_gn_standard_syntax_is_unchanged() -> None:
    assert _normalize_args(["gn", "doctor"]) == ["gn", "doctor"]


def test_gn_lone_separator_is_safe() -> None:
    assert _normalize_args(["gn", "-"]) == ["gn"]
