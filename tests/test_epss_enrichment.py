from __future__ import annotations

import json
from pathlib import Path

from greynoc_detector_engine.config.settings import Settings
from greynoc_detector_engine.enrichment.epss import EPSSClient, enrich_cves_with_epss
from greynoc_detector_engine.models.cve import CVERecord


def test_epss_client_loads_first_api_fixture(tmp_path: Path) -> None:
    fixture = tmp_path / "epss.json"
    fixture.write_text(
        json.dumps(
            {
                "data": [
                    {"cve": "CVE-2026-12345", "epss": "0.81234", "percentile": "0.99"}
                ]
            }
        ),
        encoding="utf-8",
    )

    records = EPSSClient(Settings()).load_records(fixture_path=fixture)

    assert len(records) == 1
    assert records[0].cve_id == "CVE-2026-12345"
    assert records[0].epss_score == 0.81234
    assert records[0].percentile == 0.99


def test_enrich_cves_with_epss_updates_matching_cves() -> None:
    cve = CVERecord(cve_id="CVE-2026-12345", description="Example CVE")
    records = EPSSClient(Settings())._parse_payload(
        {"data": [{"cve": "CVE-2026-12345", "epss": "0.7"}]}
    )

    enriched = enrich_cves_with_epss([cve], records)

    assert enriched[0].epss_score == 0.7
    assert "epss-enriched" in enriched[0].tags
