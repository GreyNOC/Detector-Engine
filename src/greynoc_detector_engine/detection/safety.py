"""Sanitization helpers for detection-rule term interpolation.

Threat metadata is downstream of public feeds and therefore *attacker-influenced*.
Before we paste a term into a SPL / KQL / Sigma / YARA template we must
strip anything that could break the rule's syntax or smuggle malicious
clauses through to a SIEM that will eventually deploy it.
"""

from __future__ import annotations

import re

# Allow letters, digits, dot, dash, underscore, colon, slash. Anything else
# (quotes, brackets, semicolons, pipes, newlines, control chars) is dropped.
_TERM_SAFE = re.compile(r"[^A-Za-z0-9._\-:/ ]")

_MAX_TERM_LEN = 96


def sanitize_rule_term(term: str) -> str:
    """Return a syntactically-safe version of a term for SIEM rule templates."""
    if not term:
        return ""
    stripped = _TERM_SAFE.sub("", term).strip()
    if not stripped:
        return ""
    return stripped[:_MAX_TERM_LEN]


def sanitize_rule_terms(terms: list[str], *, max_terms: int = 25) -> list[str]:
    """Sanitize a batch of terms, drop empties, deduplicate, cap count."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in terms:
        clean = sanitize_rule_term(raw)
        if not clean or clean in seen:
            continue
        seen.add(clean)
        out.append(clean)
        if len(out) >= max_terms:
            break
    return out
