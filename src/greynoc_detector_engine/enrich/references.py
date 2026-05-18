from __future__ import annotations

from greynoc_detector_engine.models.cve import CVERecord

EXPLOIT_URL_TERMS = (
    "exploit",
    "poc",
    "proof",
    "metasploit",
    "exploit-db",
    "packetstorm",
    "github.com",
)


def defensive_reference_tags(url: str) -> list[str]:
    lowered = url.lower()
    tags: list[str] = []
    if any(term in lowered for term in EXPLOIT_URL_TERMS):
        tags.append("public-exploit-reference")
    if "vendor" in lowered or "security" in lowered:
        tags.append("vendor-or-security-advisory")
    if "github.com" in lowered:
        tags.append("github-metadata-reference")
    return tags


def add_reference_context(cve: CVERecord) -> CVERecord:
    updated = cve.model_copy(deep=True)
    tags = set(updated.tags)
    for reference in updated.references:
        tags.update(defensive_reference_tags(reference))
    updated.tags = sorted(tags)
    return updated
