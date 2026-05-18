from __future__ import annotations

import re

from greynoc_detector_engine.models.prediction import ThreatActorProfile

# Curated, well-known public actor name patterns. Aliases come from public
# reporting (Mandiant, MS Threat Intel, Unit 42). Used only for attribution
# of *who is being discussed* in source text — never for offensive use.
ACTOR_CATALOG: dict[str, ThreatActorProfile] = {
    "apt28": ThreatActorProfile(
        actor_id="apt28",
        aliases=["Fancy Bear", "Sofacy", "Forest Blizzard", "Sednit", "Pawn Storm"],
        motivation="state-sponsored",
        sectors_targeted=["government", "defense", "media", "energy"],
        countries_targeted=["ukraine", "european union", "united states", "nato"],
        known_ttps=["spear-phishing", "credential harvesting", "zero-day exploitation"],
    ),
    "apt29": ThreatActorProfile(
        actor_id="apt29",
        aliases=["Cozy Bear", "Midnight Blizzard", "Nobelium", "The Dukes"],
        motivation="state-sponsored",
        sectors_targeted=["government", "diplomatic", "ngo", "technology"],
        known_ttps=["supply chain", "cloud abuse", "long-dwell intrusions"],
    ),
    "lazarus": ThreatActorProfile(
        actor_id="lazarus",
        aliases=["Hidden Cobra", "Diamond Sleet", "Labyrinth Chollima"],
        motivation="state-sponsored",
        sectors_targeted=["financial", "cryptocurrency", "defense"],
        known_ttps=["financial theft", "crypto theft", "destructive malware"],
    ),
    "fin7": ThreatActorProfile(
        actor_id="fin7",
        aliases=["Carbanak", "Sangria Tempest"],
        motivation="financial",
        sectors_targeted=["retail", "hospitality", "finance"],
        known_ttps=["point-of-sale malware", "spear-phishing"],
    ),
    "lockbit": ThreatActorProfile(
        actor_id="lockbit",
        aliases=["LockBit 3.0", "LockBit Black"],
        motivation="ransomware",
        sectors_targeted=["manufacturing", "healthcare", "professional-services"],
        known_ttps=["ransomware", "double extortion", "affiliate model"],
    ),
    "alphv": ThreatActorProfile(
        actor_id="alphv",
        aliases=["BlackCat", "Noberus"],
        motivation="ransomware",
        known_ttps=["ransomware", "double extortion", "Rust binaries"],
    ),
    "cl0p": ThreatActorProfile(
        actor_id="cl0p",
        aliases=["Clop", "TA505"],
        motivation="ransomware",
        known_ttps=["mass exploitation", "data extortion", "MOVEit", "GoAnywhere"],
    ),
    "scattered-spider": ThreatActorProfile(
        actor_id="scattered-spider",
        aliases=["Scattered Spider", "UNC3944", "Octo Tempest", "Muddled Libra"],
        motivation="financial",
        sectors_targeted=["hospitality", "telecom", "retail"],
        known_ttps=["sim swapping", "social engineering", "help-desk impersonation"],
    ),
    "volt-typhoon": ThreatActorProfile(
        actor_id="volt-typhoon",
        aliases=["Volt Typhoon", "Bronze Silhouette"],
        motivation="state-sponsored",
        sectors_targeted=["critical-infrastructure", "telecom", "utilities"],
        known_ttps=["living-off-the-land", "soho router compromise"],
    ),
}


class ThreatActorAttributor:
    """Identify which public threat actors are referenced in a piece of text."""

    def __init__(self, catalog: dict[str, ThreatActorProfile] | None = None) -> None:
        self.catalog = catalog or ACTOR_CATALOG
        self._patterns = {
            actor_id: re.compile(
                r"\b(" + "|".join(re.escape(a) for a in [actor_id, *profile.aliases]) + r")\b",
                re.IGNORECASE,
            )
            for actor_id, profile in self.catalog.items()
        }

    def attribute(self, text: str) -> list[ThreatActorProfile]:
        hay = text or ""
        hits: list[ThreatActorProfile] = []
        for actor_id, pattern in self._patterns.items():
            if pattern.search(hay):
                hits.append(self.catalog[actor_id])
        return hits

    def actor_ids(self, text: str) -> list[str]:
        return [profile.actor_id for profile in self.attribute(text)]
