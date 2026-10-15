import pytest

from siem.observability.metrics import Metrics


def test_metrics_start_at_zero() -> None:
    metrics = Metrics()

    snapshot = metrics.snapshot()

    assert snapshot["lines_processed"] == 0
    assert snapshot["alerts_generated"] == 0
    assert snapshot["notification_failures"] == 0


def test_increment_updates_counter() -> None:
    metrics = Metrics()

    metrics.increment("lines_processed")
    metrics.increment("lines_processed", 4)

    assert metrics.snapshot()["lines_processed"] == 5


def test_snapshot_does_not_modify_internal_state() -> None:
    metrics = Metrics()

    snapshot = metrics.snapshot()
    snapshot["lines_processed"] = 100

    assert metrics.snapshot()["lines_processed"] == 0


def test_unknown_metric_is_rejected() -> None:
    metrics = Metrics()

    with pytest.raises(ValueError, match="Unknown metric"):
        metrics.increment("line_processed")


def test_negative_increment_is_rejected() -> None:
    metrics = Metrics()

    with pytest.raises(ValueError, match="cannot be negative"):
        metrics.increment("lines_processed", -1)
