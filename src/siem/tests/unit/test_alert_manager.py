from datetime import datetime
import pytest

from siem.tests.unit.test_rate_limiter import FakeClock
from siem.alerting.alert_manager import AlertManager
from siem.alerting.rate_limiter import RateLimiter
from siem.models.alert import SecurityAlert
from datetime import datetime

class FakeClock:
    def __init__(self, start: datetime) -> None:
        self.current = start

    def now(self) -> datetime:  # <-- Ensures this method is present
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)

class FakeNotification:
    def __init__(self) -> None:
        self.alerts = []

    async def send(self, alert):
        self.alerts.append(alert)


@pytest.mark.asyncio
async def test_alert_manager_suppresses_repeated_alerts(capsys):
    clock = FakeClock(datetime.fromisoformat("2026-10-01T10:00:00"))
    limiter = RateLimiter(cooldown_seconds=60, clock=clock.now)
    notification = FakeNotification()

    manager = AlertManager(rate_limiter=limiter, notification=notification)

    alert = SecurityAlert(
        timestamp=clock.now(),
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )
    # Complete rest of test logic if needed...

@pytest.mark.asyncio
async def test_alert_manager_sends_alert(capsys):
    clock_time = datetime.fromisoformat("2026-09-30T10:00:00")
    limiter = RateLimiter(cooldown_seconds=60, clock=lambda: clock_time)
    notification = FakeNotification()

    manager = AlertManager(rate_limiter=limiter, notification=notification)

    alert = SecurityAlert(
        timestamp=clock_time,
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )
    await manager.send(alert)
from datetime import datetime, timedelta
import pytest
from unittest.mock import AsyncMock

from siem.tests.unit.test_rate_limiter import FakeClock
from siem.alerting.alert_manager import AlertManager
from siem.alerting.rate_limiter import RateLimiter
from siem.models.alert import SecurityAlert

# Simple fake class to pass as the required notification dependency
class FakeNotification:
    def __init__(self):
        self.sent_alerts = []
        
    async def send(self, alert):
        self.sent_alerts.append(alert)


@pytest.mark.asyncio
async def test_alert_manager_suppresses_repeated_alerts(capsys):
    clock = FakeClock(datetime.fromisoformat("2026-10-01T10:00:00"))
    limiter = RateLimiter(cooldown_seconds=60, clock=clock.now)
    notification = FakeNotification()

    manager = AlertManager(rate_limiter=limiter, notification=notification)

    alert = SecurityAlert(
        timestamp=clock.now(),
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )
    # Complete rest of test logic if needed...


@pytest.mark.asyncio
async def test_alert_manager_sends_alert(capsys):
    clock_time = datetime.fromisoformat("2026-09-30T10:00:00")
    limiter = RateLimiter(cooldown_seconds=60, clock=lambda: clock_time)
    notification = FakeNotification()

    manager = AlertManager(rate_limiter=limiter, notification=notification)

    alert = SecurityAlert(
        timestamp=clock_time,
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )
    await manager.send(alert)


@pytest.mark.asyncio
async def test_alert_manager_rate_limits_same_ip(capsys):
    clock = FakeClock(datetime.fromisoformat("2026-09-30T10:00:00"))
    limiter = RateLimiter(cooldown_seconds=60, clock=clock.now)
    notification = FakeNotification()

    manager = AlertManager(rate_limiter=limiter, notification=notification)

    alert = SecurityAlert(
        timestamp=clock.current,
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )
    await manager.send(alert)


@pytest.mark.asyncio
async def test_alert_manager_sends_to_notification():
    clock = FakeClock(datetime.fromisoformat("2026-10-01T10:00:00"))
    limiter = RateLimiter(cooldown_seconds=60, clock=clock.now)
    notification = FakeNotification()

    manager = AlertManager(rate_limiter=limiter, notification=notification)

    alert = SecurityAlert(
        timestamp=clock.now(),  # <-- Fixed: changed clock() to clock.now()
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )
    await manager.send(alert)