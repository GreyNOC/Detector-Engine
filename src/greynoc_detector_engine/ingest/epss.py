from __future__ import annotations

from greynoc_detector_engine.enrich.epss import EPSSEnricher
from greynoc_detector_engine.ingest.base import BaseIngestor
from greynoc_detector_engine.models.prediction import EPSSScore


class EPSSIngestor(BaseIngestor[EPSSScore]):
    """Ingest FIRST.org EPSS daily scores.

    EPSS is the de-facto external prior for exploitation probability. We pull
    it and store one EPSSScore per CVE; the predictive engine later joins it
    against our internal threat records.
    """

    def ingest(self) -> list[EPSSScore]:
        payload = self.load_json_payload()
        return EPSSEnricher.from_first_org_payload(payload)
