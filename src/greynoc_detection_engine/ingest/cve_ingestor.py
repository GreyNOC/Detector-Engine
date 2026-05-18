from __future__ import annotations

from typing import Any

from greynoc_detection_engine.ingest.base import BaseIngestor
from greynoc_detection_engine.models.cve import CVERecord
from greynoc_detection_engine.normalize.normalizer import source_reference_from_record
from greynoc_detection_engine.utils.time import parse_datetime

EXPLOIT_REFERENCE_KEYWORDS = (
    "exploit",
    "poc",
    "proof-of-concept",
    "proof of concept",
    "metasploit",
    "packetstorm",
    "exploit-db",
    "github.com",
)


class CVEIngestor(BaseIngestor[CVERecord]):
    def ingest(self) -> list[CVERecord]:
        payload = self.load_json_payload()
        return [self._normalize_record(item) for item in self._iter_records(payload)]

    def _iter_records(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("cves"), list):
            return [item for item in payload["cves"] if isinstance(item, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
            return [
                item.get("cve", item)
                for item in payload["vulnerabilities"]
                if isinstance(item, dict)
            ]
        if isinstance(payload, dict) and "id" in payload:
            return [payload]
        return []

    def _normalize_record(self, record: dict[str, Any]) -> CVERecord:
        cve_id = record.get("cve_id") or record.get("id")
        descriptions = record.get("descriptions") or []
        description = record.get("description") or self._description_from_nvd(descriptions)
        references = self._references(record)
        cvss_score, cvss_vector = self._cvss(record.get("metrics") or record)
        affected_products = record.get("affected_products") or self._affected_products(record)
        exploit_references = [
            ref
            for ref in references
            if any(keyword in ref.lower() for keyword in EXPLOIT_REFERENCE_KEYWORDS)
        ]
        tags = sorted(
            set(record.get("tags") or []) | ({"exploit-reference"} if exploit_references else set())
        )
        source_ref = source_reference_from_record(
            title=f"{cve_id} CVE record",
            source=self.source_config.name,
            url=self.source_config.url,
            content=f"{cve_id} {description} {' '.join(references)}",
            published_at=parse_datetime(record.get("published") or record.get("published_date")),
        )
        return CVERecord(
            cve_id=str(cve_id),
            description=str(description),
            published_date=parse_datetime(record.get("published") or record.get("published_date")),
            last_modified_date=parse_datetime(
                record.get("lastModified") or record.get("last_modified_date")
            ),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe=record.get("cwe") or self._cwes(record),
            affected_products=sorted({str(product) for product in affected_products if product}),
            references=references,
            exploit_references=exploit_references,
            tags=tags,
            source_references=[source_ref],
        )

    @staticmethod
    def _description_from_nvd(descriptions: list[dict[str, Any]]) -> str:
        for item in descriptions:
            if item.get("lang") == "en" and item.get("value"):
                return str(item["value"])
        return str(descriptions[0].get("value", "")) if descriptions else ""

    @staticmethod
    def _references(record: dict[str, Any]) -> list[str]:
        if isinstance(record.get("references"), list) and all(
            isinstance(item, str) for item in record["references"]
        ):
            return list(dict.fromkeys(record["references"]))
        reference_data = (record.get("references") or {}).get("referenceData", [])
        if not reference_data and isinstance(record.get("references"), list):
            reference_data = record["references"]
        refs = [
            item.get("url") for item in reference_data if isinstance(item, dict) and item.get("url")
        ]
        return list(dict.fromkeys(str(ref) for ref in refs))

    @staticmethod
    def _cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
        if "cvss_score" in metrics:
            return metrics.get("cvss_score"), metrics.get("cvss_vector")
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key)
            if isinstance(values, list) and values:
                data = values[0].get("cvssData", {})
                return data.get("baseScore"), data.get("vectorString")
        return None, None

    @staticmethod
    def _cwes(record: dict[str, Any]) -> list[str]:
        weaknesses = record.get("weaknesses") or []
        cwes: set[str] = set()
        for weakness in weaknesses:
            for description in weakness.get("description", []):
                value = description.get("value")
                if value:
                    cwes.add(str(value))
        return sorted(cwes)

    @staticmethod
    def _affected_products(record: dict[str, Any]) -> list[str]:
        products: set[str] = set()
        configurations = record.get("configurations") or []
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria") or match.get("cpe23Uri")
                    if not criteria:
                        continue
                    parts = str(criteria).split(":")
                    if len(parts) >= 6:
                        vendor, product = parts[3], parts[4]
                        if vendor != "*" and product != "*":
                            products.add(f"{vendor}:{product}")
        return sorted(products)
