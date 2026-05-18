# Scoring Model

All scores return `numeric_score`, `label`, `reasons`,
`contributing_signals`, and `timestamp`.

## Exploitability Score

Factors:

- CVSS score contributes up to 50 points.
- Public exploit-oriented references contribute up to 20 points.
- CISA KEV presence contributes 30 points.
- Ransomware source context contributes 10 points.

## AI-Abuse Score

Factors:

- Explicit AI attack taxonomy classification contributes 60 points.
- Matched AI attack terms contribute up to 25 points.
- AI-specific observed indicators contribute up to 15 points.

## Signal Score

Factors:

- Independent sources, trusted sources, news mentions, GitHub mentions, and
  recency contribute to weak-signal confidence.

## Early-Warning Score

Default weights:

- KEV presence: 16.
- CVSS severity: 12.
- Exploit references: 12.
- GitHub velocity: 10.
- News velocity: 10.
- Trusted-source mentions: 10.
- Ransomware association: 8.
- Affected product popularity: 6.
- AI-enabled relevance: 6.
- Vendor emergency language: 5.
- Independent sources: 3.
- Recency: 2.

Example: a KEV-listed CVE with CVSS 9.8, public exploit references, ransomware
association, and multiple trusted mentions will usually score high or critical
depending on recency and source velocity.

