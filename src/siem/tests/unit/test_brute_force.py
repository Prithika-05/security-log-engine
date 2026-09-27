from datetime import datetime, timedelta

from siem.detection.brute_force import BruteForceDetector
from siem.models.log_entry import LogEntry


def make_failed_login(
    timestamp: datetime,
    ip: str = "10.0.0.5",
) -> LogEntry:
    return LogEntry(
        timestamp=timestamp,
        ip_address=ip,
        method="POST",
        path="/login",
        status_code=401,
    )


def test_brute_force_alert_after_threshold():
    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    start = datetime.fromisoformat("2026-09-25T10:00:00")

    alert = None

    for i in range(5):
        alert = detector.process(
            make_failed_login(
                start + timedelta(seconds=i)
            )
        )

    assert alert is not None
    assert alert.alert_type == "Brute Force Detected"
    assert alert.source_ip == "10.0.0.5"

def test_successful_login_does_not_trigger_alert():
    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60,
    )

    entry = LogEntry(
        timestamp=datetime.fromisoformat("2026-09-25T10:00:00"),
        ip_address="10.0.0.5",
        method="POST",
        path="/login",
        status_code=200,
    )

    assert detector.process(entry) is None