from datetime import datetime

import pytest

from siem.alerting.alert_manager import AlertManager
from siem.models.alert import SecurityAlert


@pytest.mark.asyncio
async def test_alert_manager_sends_alert(capsys):
    manager = AlertManager()

    alert = SecurityAlert(
        timestamp=datetime.fromisoformat("2026-09-25T10:00:00"),
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )

    await manager.send(alert)

    captured = capsys.readouterr()

    assert "BRUTE_FORCE" in captured.out
    assert "10.0.0.5" in captured.out