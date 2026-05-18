"""Engine self-diagnostic.

Two flavors:

  * **source health**: which feeds last ingested successfully, when, how
    many records. Surfaced by ``greynoc-detector doctor sources``.
  * **safety self-check**: assert the security defaults that
    ``docs/security_review.md`` documents are still in force. Surfaced
    by ``greynoc-detector doctor``.

Any failure is loud and the command exits non-zero so it can fence a
deployment.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from greynoc_detector_engine.spacestation.honeypot import HoneypotConfig
from greynoc_detector_engine.storage.sqlite import SQLiteStorage
from greynoc_detector_engine.utils.http import DEFAULT_MAX_BYTES, MAX_REDIRECTS


class HealthFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    severity: str  # "ok" | "warn" | "fail"
    detail: str


class DoctorReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[HealthFinding] = Field(default_factory=list)
    exit_code: int = 0

    def add(self, name: str, severity: str, detail: str) -> None:
        self.findings.append(HealthFinding(name=name, severity=severity, detail=detail))
        if severity == "fail":
            self.exit_code = max(self.exit_code, 2)
        elif severity == "warn":
            self.exit_code = max(self.exit_code, 1)


# ---------------------------------------------------------------------------
# Safety self-check
# ---------------------------------------------------------------------------


def run_safety_self_check() -> DoctorReport:
    report = DoctorReport()

    # Honeypot default bind must be loopback unless explicitly opted in.
    hp = HoneypotConfig(port=2222)
    if hp.bind_host in {"127.0.0.1", "::1", "localhost"} and not hp.allow_external_bind:
        report.add(
            "honeypot.default_bind",
            "ok",
            f"defaults to {hp.bind_host}; external bind requires explicit opt-in.",
        )
    else:
        report.add(
            "honeypot.default_bind",
            "fail",
            f"non-loopback default {hp.bind_host!r} without explicit allow_external_bind",
        )

    # HTTP client must have a body cap and a redirect cap.
    if DEFAULT_MAX_BYTES > 0:
        report.add("http.body_cap", "ok", f"{DEFAULT_MAX_BYTES} bytes")
    else:
        report.add("http.body_cap", "fail", "no body cap configured")
    if 0 < MAX_REDIRECTS <= 10:
        report.add("http.redirect_cap", "ok", f"{MAX_REDIRECTS} hops")
    else:
        report.add("http.redirect_cap", "fail", f"unreasonable cap {MAX_REDIRECTS}")

    return report


# ---------------------------------------------------------------------------
# Source health
# ---------------------------------------------------------------------------


def run_source_health(storage: SQLiteStorage) -> DoctorReport:
    """Look at recent source_runs and surface the worst-offender feeds."""
    report = DoctorReport()
    with storage._connect() as conn:
        rows = conn.execute(
            "SELECT source_id, status, message, created_at FROM source_runs "
            "ORDER BY created_at DESC LIMIT 200"
        ).fetchall()

    last_by_source: dict[str, tuple[str, str, str]] = {}
    counts: Counter[str] = Counter()
    for row in rows:
        sid = row["source_id"]
        counts[sid] += 1
        last_by_source.setdefault(sid, (row["status"], row["message"], row["created_at"]))

    if not last_by_source:
        report.add(
            "sources.observed",
            "warn",
            "no source_runs recorded; have you run ingest yet?",
        )
        return report

    for sid, (status, message, ts) in last_by_source.items():
        severity = "ok" if status == "ok" else "warn"
        report.add(f"source:{sid}", severity, f"last status={status!r} at {ts}: {message}")
    return report


def render_findings(findings: Iterable[HealthFinding]) -> str:
    lines: list[str] = []
    for f in findings:
        glyph = {"ok": "OK ", "warn": "WARN", "fail": "FAIL"}.get(f.severity, "?   ")
        lines.append(f"{glyph}  {f.name}: {f.detail}")
    return "\n".join(lines)
