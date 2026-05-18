from __future__ import annotations

import re
from collections.abc import Iterable

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def make_excerpt(value: str, max_chars: int = 1000) -> str:
    normalized = normalize_whitespace(value)
    if len(normalized) <= max_chars:
        return normalized
    return normalized[: max_chars - 3].rstrip() + "..."


def find_cve_ids(value: str) -> list[str]:
    return sorted({match.group(0).upper() for match in CVE_RE.finditer(value or "")})


def keyword_hits(value: str, keywords: Iterable[str]) -> list[str]:
    haystack = (value or "").lower()
    return sorted({keyword for keyword in keywords if keyword.lower() in haystack})
