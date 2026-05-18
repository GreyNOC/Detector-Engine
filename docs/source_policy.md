# Source Policy

## Configuration

Sources live in `src/greynoc_detection_engine/config/sources.yaml`. Each source
declares an ID, name, category, type, URL, enabled flag, reliability, and tags.
Python code selects sources by type and category instead of hardcoding source
lists.

## Stored Metadata

The engine stores source URL, title, source name, author when available,
published time, fetch time, content hash, confidence, bounded raw excerpt, and
source-specific metadata such as GitHub stars/forks. Raw untrusted code is not
stored as executable content.

## Unsafe Content Handling

Public exploit references are treated as defensive metadata. The engine records
that a reference exists and uses that fact for risk scoring, but it does not
copy exploit instructions into generated detections or execute referenced
material.

## GitHub Handling

GitHub monitoring collects repository metadata and defensive signals such as CVE
mentions, detection-rule terms, stars/forks, and recent activity. It does not
clone repositories, run files, install packages, or inspect code in a way that
would execute it.

