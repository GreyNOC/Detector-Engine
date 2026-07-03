from __future__ import annotations

from greynoc_detector_engine.models.source import (
    SourceCategory,
    SourceConfig,
    SourceType,
)
from greynoc_detector_engine.normalize.adversarial import (
    deobfuscate,
    normalize_adversarial,
    scan_evasion,
)
from greynoc_detector_engine.normalize.entity_extractor import EntityExtractor
from greynoc_detector_engine.normalize.normalizer import SourceItemNormalizer, ThreatNormalizer

# Built from codepoints, never literal invisibles/confusables in source (the
# same auditability rule the module under test follows).
_ZWSP = chr(0x200B)  # zero-width space
# "Fortinet" with the Latin 'o' replaced by Cyrillic U+043E (renders identically).
_FORTINET_HOMOGLYPH = "F" + chr(0x043E) + "rtinet"
_RLO = chr(0x202E)  # right-to-left override (Trojan-Source family)


def test_scan_detects_zero_width_and_marks_evasive() -> None:
    report = scan_evasion(f"acti{_ZWSP}vely exploited")
    assert report.invisible_chars == 1
    assert report.is_evasive


def test_scan_detects_mixed_script_and_bidi() -> None:
    report = scan_evasion(f"{_FORTINET_HOMOGLYPH} advisory {_RLO}")
    assert report.mixed_script_words >= 1
    assert report.bidi_controls == 1
    assert report.is_evasive
    assert report.examples  # the offending token is captured


def test_normalize_folds_homoglyphs_and_strips_invisibles() -> None:
    cleaned = normalize_adversarial(f"F{chr(0x043E)}rtinet act{_ZWSP}ively")
    assert "Fortinet" in cleaned
    assert _ZWSP not in cleaned
    assert "actively" in cleaned


def test_clean_text_is_left_unchanged() -> None:
    text = "Fortinet FortiOS actively exploited per CISA KEV."
    cleaned, report = deobfuscate(text)
    assert cleaned == text
    assert not report.is_evasive
    assert report.total == 0


def test_normalizer_defeats_homoglyph_product_evasion() -> None:
    source = SourceConfig(
        id="test-blog",
        name="Test Blog",
        category=SourceCategory.SECURITY_RESEARCH_BLOG,
        type=SourceType.BLOG,
    )
    normalizer = SourceItemNormalizer()
    # The product name is hidden behind a Cyrillic homoglyph; a naive regex on
    # the raw text would miss it entirely.
    raw = f"{_FORTINET_HOMOGLYPH} appliance actively exploited in the wild."
    assert not EntityExtractor().extract(raw).products  # naive extraction misses it

    item = normalizer.normalize(source, title="Advisory", content=raw)
    # After de-obfuscation the product is recovered and extractable.
    assert "Fortinet" in item.raw_content
    assert "Fortinet" in EntityExtractor().extract(item.raw_content).products
    assert item.metadata["evasion"]["is_evasive"] is True


def test_threat_record_surfaces_evasion_finding() -> None:
    source = SourceConfig(
        id="test-blog",
        name="Test Blog",
        category=SourceCategory.SECURITY_RESEARCH_BLOG,
        type=SourceType.BLOG,
    )
    item = SourceItemNormalizer().normalize(
        source,
        title=f"{_RLO}Urgent",
        content=f"{_FORTINET_HOMOGLYPH} exploited",
    )
    threat = ThreatNormalizer().from_source_item(item)
    assert any("obfuscation" in opp for opp in threat.detection_opportunities)
    assert any("evasion" in entry.lower() for entry in threat.changelog)
