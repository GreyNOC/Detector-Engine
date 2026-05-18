# Detection Generation

Detection generation creates drafts only. Each `GeneratedDetection` includes a
title, description, status, required telemetry, rule/query body,
false-positive notes, validation steps, assumptions, references, related threat
ID, and confidence.

Supported draft outputs:

- Sigma process-creation hunt template.
- YARA metadata-only template with `condition: false`.
- Suricata metadata-only template with no traffic-matching rule.
- Splunk SPL hunt query.
- Elastic KQL hunt query.
- Microsoft Defender Advanced Hunting KQL query.

Drafts must be validated with representative benign telemetry and confirmed
attack telemetry before production deployment.
