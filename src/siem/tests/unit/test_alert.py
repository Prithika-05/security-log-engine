from datetime import datetime

from siem.models.alert import SecurityAlert


def test_alert_generates_unique_ids():
    timestamp = datetime.fromisoformat("2026-09-24T10:00:00")

    first = SecurityAlert(
        timestamp=timestamp,
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="Repeated failed logins",
    )

    second = SecurityAlert(
        timestamp=timestamp,
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="Repeated failed logins",
    )

    assert first.alert_id != second.alert_id
