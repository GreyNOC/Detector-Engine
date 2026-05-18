from __future__ import annotations

from greynoc_detector_engine.models.scoring import ScoreResult, score_label
from greynoc_detector_engine.storage.sqlite import SQLiteStorage


def test_sqlite_score_history_can_filter_by_target_and_type(tmp_path) -> None:  # type: ignore[no-untyped-def]
    storage = SQLiteStorage(tmp_path / "scores.sqlite")
    storage.initialize()
    score = ScoreResult(
        score=88,
        label=score_label(88),
        reasons=["high confidence test score"],
        contributing_signals={"source": "test"},
    )

    storage.record_score_event("thr-test", "risk", score)
    storage.record_score_event("thr-test", "exploitability", score)
    storage.record_score_event("thr-other", "risk", score)

    target_events = storage.list_score_events(target_id="thr-test")
    risk_events = storage.list_score_events(score_type="risk")
    exact_events = storage.list_score_events(target_id="thr-test", score_type="risk")

    assert len(target_events) == 2
    assert len(risk_events) == 2
    assert len(exact_events) == 1
    assert exact_events[0].target_id == "thr-test"
    assert exact_events[0].score_type == "risk"
    assert exact_events[0].score.score == 88
