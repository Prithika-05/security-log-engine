from datetime import datetime
import pytest

from siem.tests.unit.test_rate_limiter import FakeClock
from siem.alerting.alert_manager import AlertManager
from siem.alerting.rate_limiter import RateLimiter
from siem.models.alert import SecurityAlert


@pytest.mark.asyncio
async def test_alert_manager_sends_alert(capsys):
    clock_time = datetime.fromisoformat("2026-09-30T10:00:00")
    limiter = RateLimiter(cooldown_seconds=60, clock=lambda: clock_time)
    manager = AlertManager(rate_limiter=limiter)

    alert = SecurityAlert(
        timestamp=clock_time,
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )

    await manager.send(alert)
    captured = capsys.readouterr()

    assert "BRUTE_FORCE" in captured.out
    assert "10.0.0.5" in captured.out


@pytest.mark.asyncio
async def test_alert_manager_rate_limits_same_ip(capsys):
    clock = FakeClock(datetime.fromisoformat("2026-09-30T10:00:00"))
    limiter = RateLimiter(cooldown_seconds=60, clock=clock.now)
    manager = AlertManager(rate_limiter=limiter)

    alert = SecurityAlert(
        timestamp=clock.current,
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )

    await manager.send(alert)
    await manager.send(alert)
    captured = capsys.readouterr()

    assert captured.out.count("BRUTE_FORCE") == 1
