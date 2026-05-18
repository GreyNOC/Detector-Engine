from __future__ import annotations

from datetime import datetime

from greynoc_detection_engine.models.cve import CVERecord
from greynoc_detection_engine.models.indicator import Indicator, IndicatorType
from greynoc_detection_engine.models.kev import KEVRecord
from greynoc_detection_engine.models.source import SourceConfig, SourceItem, SourceReference
from greynoc_detection_engine.models.threat import ThreatRecord, ThreatSeverity
from greynoc_detection_engine.normalize.ai_attack_classifier import AIAttackClassifier
from greynoc_detection_engine.normalize.entity_extractor import EntityExtractor
from greynoc_detection_engine.utils.hashing import stable_hash
from greynoc_detection_engine.utils.text import make_excerpt, normalize_whitespace
from greynoc_detection_engine.utils.time import utc_now


class SourceItemNormalizer:
    def normalize(
        self,
        source: SourceConfig,
        title: str,
        content: str,
        *,
        url: str | None = None,
        author: str | None = None,
        published_at: datetime | None = None,
        metadata: dict[str, object] | None = None,
    ) -> SourceItem:
        normalized_content = normalize_whitespace(content)
        content_basis = f"{source.source_id}|{url or ''}|{title}|{normalized_content}"
        content_hash = stable_hash(content_basis, 32)
        return SourceItem(
            item_id=f"src-{stable_hash(content_hash)}",
            source_id=source.source_id,
            title=normalize_whitespace(title),
            url=url or source.url,
            author=author,
            published_at=published_at,
            fetched_at=utc_now(),
            raw_content=normalized_content,
            raw_excerpt=make_excerpt(normalized_content, max_chars=1000),
            content_hash=content_hash,
            confidence=0.8 if source.reliability in {"high", "verified"} else 0.55,
            metadata=metadata or {},
        )


class ThreatNormalizer:
    def __init__(self) -> None:
        self.extractor = EntityExtractor()
        self.ai_classifier = AIAttackClassifier()

    def from_cve(self, cve: CVERecord, kev: KEVRecord | None = None) -> ThreatRecord:
        severity = self._severity_from_cvss(cve.cvss_score)
        references = list(cve.source_references)
        related_kev_entries: list[str] = []
        if kev:
            references.extend(kev.source_references)
            related_kev_entries.append(kev.cve_id)

        return ThreatRecord(
            threat_id=f"thr-cve-{cve.cve_id.lower()}",
            title=f"{cve.cve_id}: {self._short_title(cve.description)}",
            summary=cve.description,
            category="vulnerability",
            affected_products=cve.affected_products,
            related_cves=[cve.cve_id],
            related_kev_entries=related_kev_entries,
            source_references=references,
            first_seen=cve.published_date,
            last_seen=cve.last_modified_date or cve.published_date,
            confidence=0.8 if kev else 0.65,
            severity=severity,
            recommended_soc_actions=[
                "Confirm asset exposure for affected products.",
                "Review vendor guidance and patch timelines.",
                "Hunt for exploitation indicators in available telemetry.",
            ],
            detection_opportunities=[
                "Correlate vulnerable product inventory with external exposure.",
                "Monitor endpoint and network logs for exploitation attempts.",
            ],
            changelog=["Created from normalized CVE data."],
        )

    def from_source_item(self, item: SourceItem, source_name: str | None = None) -> ThreatRecord:
        text = f"{item.title} {item.raw_content}"
        entities = self.extractor.extract(text)
        ai_classification = self.ai_classifier.classify(text)
        indicators = [
            Indicator(value=cve_id, type=IndicatorType.CVE, confidence=0.9, source=item.source_id)
            for cve_id in entities.cve_ids
        ]
        indicators.extend(
            Indicator(
                value=term,
                type=IndicatorType.AI_ATTACK_TERM,
                confidence=0.7,
                source=item.source_id,
            )
            for term in entities.ai_terms
        )
        return ThreatRecord(
            threat_id=f"thr-src-{stable_hash(item.content_hash)}",
            title=item.title,
            summary=item.raw_excerpt,
            category="ai_enabled_threat" if ai_classification.attack_type else "emerging_signal",
            ai_attack_type=ai_classification.attack_type,
            affected_products=entities.products,
            related_cves=entities.cve_ids,
            observed_indicators=indicators,
            source_references=[item.to_reference(source_name)],
            first_seen=item.published_at,
            last_seen=item.fetched_at,
            confidence=max(item.confidence, ai_classification.confidence),
            severity=ThreatSeverity.MEDIUM,
            recommended_soc_actions=[
                "Validate the signal against trusted sources before escalation.",
                "Track related CVEs, product mentions, and detection-rule references.",
            ],
            detection_opportunities=[
                "Create targeted hunt queries once concrete telemetry fields are known."
            ],
            changelog=["Created from normalized source signal."],
        )

    @staticmethod
    def _severity_from_cvss(score: float | None) -> ThreatSeverity:
        if score is None:
            return ThreatSeverity.MEDIUM
        if score >= 9:
            return ThreatSeverity.CRITICAL
        if score >= 7:
            return ThreatSeverity.HIGH
        if score >= 4:
            return ThreatSeverity.MEDIUM
        return ThreatSeverity.LOW

    @staticmethod
    def _short_title(description: str) -> str:
        words = normalize_whitespace(description).split()
        return " ".join(words[:12]) + ("..." if len(words) > 12 else "")


def source_reference_from_record(
    *,
    title: str,
    source: str,
    url: str | None,
    content: str,
    published_at: datetime | None = None,
) -> SourceReference:
    return SourceReference(
        url=url,
        title=title,
        source=source,
        published_at=published_at,
        fetched_at=utc_now(),
        content_hash=stable_hash(content, length=32),
        confidence=0.85,
        raw_excerpt=make_excerpt(content, max_chars=1000),
    )
