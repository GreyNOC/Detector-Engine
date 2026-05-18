# Source Policy

## Approved Source Types

The engine supports defensive metadata ingestion from:

- CVE JSON feeds.
- CISA KEV JSON feeds.
- RSS feeds for advisories, research, news, and blogs.
- GitHub repository/search metadata.
- Local fixtures for offline tests.

## Unsafe Content Handling

Exploit references are stored only as defensive signals. The engine may record a
URL, title, affected product, source confidence, excerpt, hash, and
exploit-availability context. It does not copy exploit instructions into
detections.

## No Untrusted Code Execution

GitHub monitoring is metadata-only. The engine does not clone repositories,
download artifacts, execute scripts, install packages, import untrusted modules,
or run source code from monitored repositories.

## Provenance Requirements

Every raw source item and normalized source reference preserves URL, title,
source, author when available, published timestamp, fetch timestamp, content
hash, confidence, and bounded raw excerpt.

