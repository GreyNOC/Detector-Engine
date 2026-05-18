from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detection_engine.models.source import SourceItem
from greynoc_detection_engine.utils.text import find_cve_ids, keyword_hits

DETECTION_RULE_TERMS = ("sigma", "yara", "suricata", "kql", "spl", "ioc")
EXPLOIT_FILE_TERMS = ("exploit", "poc", "proof-of-concept")


class GitHubMetadataSignals(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_ids: list[str] = Field(default_factory=list)
    detection_rule_terms: list[str] = Field(default_factory=list)
    exploit_terms: list[str] = Field(default_factory=list)
    stars: int | None = None
    forks: int | None = None
    open_issues: int | None = None


class GitHubMetadataEnricher:
    def extract(self, item: SourceItem) -> GitHubMetadataSignals:
        text = f"{item.title} {item.raw_content}"
        stars = item.metadata.get("stars")
        forks = item.metadata.get("forks")
        open_issues = item.metadata.get("open_issues")
        return GitHubMetadataSignals(
            cve_ids=find_cve_ids(text),
            detection_rule_terms=keyword_hits(text, DETECTION_RULE_TERMS),
            exploit_terms=keyword_hits(text, EXPLOIT_FILE_TERMS),
            stars=stars if isinstance(stars, int) else None,
            forks=forks if isinstance(forks, int) else None,
            open_issues=open_issues if isinstance(open_issues, int) else None,
        )
