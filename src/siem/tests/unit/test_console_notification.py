from datetime import datetime

import pytest

from siem.alerting.console import ConsoleNotification
from siem.models.alert import SecurityAlert


@pytest.mark.asyncio
async def test_console_notification(capsys):
    notification = ConsoleNotification()

    alert = SecurityAlert(
        timestamp=datetime.fromisoformat("2026-10-01T10:00:00"),
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )

    await notification.send(alert)

    captured = capsys.readouterr()

    assert "BRUTE_FORCE" in captured.out
    assert "10.0.0.5" in captured.out
    assert "HIGH" in captured.out
