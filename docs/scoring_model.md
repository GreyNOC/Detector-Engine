# Scoring Model

## Labels

- `low`: 0-39
- `medium`: 40-69
- `high`: 70-84
- `critical`: 85-100

## Early-Warning Factors

Default weights are documented in `config/scoring.yaml`:

- KEV presence: 16.
- CVSS severity: 12.
- Exploit references: 12.
- Trusted source mentions: 10.
- News/RSS velocity: 10.
- GitHub metadata references: 10.
- Ransomware association: 8.
- AI relevance: 6.
- Vendor emergency language: 5.
- Independent source count: 3.
- Recency: 2.

## Reason Trail Format

Every score result contains:

- `score`: numeric value from 0 to 100.
- `label`: low, medium, high, or critical.
- `reasons`: analyst-readable explanation list.
- `contributing_signals`: structured factor inputs.
- `timestamp`: score generation time.

## Example

A KEV-listed CVE with CVSS 9.8, public exploit references, ransomware wording,
recent RSS mentions, and multiple trusted sources will receive a higher
early-warning score than a low-CVSS vulnerability with no public exploitation
or source velocity.

