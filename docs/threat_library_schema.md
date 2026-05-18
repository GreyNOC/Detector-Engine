# Threat Library Schema

Threat records are represented by `ThreatRecord`.

- `threat_id`: stable local identifier.
- `title` and `summary`: human-readable triage context.
- `category`: vulnerability, emerging signal, AI-enabled threat, or other local
  category.
- `ai_attack_type`: optional taxonomy bucket.
- `affected_products`: normalized product/vendor strings.
- `related_cves` and `related_kev_entries`: cross-source relationships.
- `observed_indicators`: defensive indicators and extracted entities.
- `tactics_techniques_procedures`: high-level behavior notes.
- `mitre_attack_mapping`: optional ATT&CK mappings.
- `source_references`: provenance list with hashes and excerpts.
- `first_seen` and `last_seen`: observation window.
- `confidence` and `severity`: triage fields.
- `exploitability_score`, `early_warning_score`, and `ai_abuse_score`:
  explainable score objects.
- `recommended_soc_actions`: defensive next steps.
- `detection_opportunities`: hunt ideas awaiting validation.
- `generated_detections`: draft detections.
- `status`: new, monitoring, validated, or deprecated.
- `version` and `changelog`: local catalog versioning.

