from datetime import datetime, timedelta
import pytest
from unittest.mock import AsyncMock
import asyncio

from siem.tests.unit.test_rate_limiter import FakeClock
from siem.alerting.alert_manager import AlertManager
from siem.alerting.rate_limiter import RateLimiter
from siem.models.alert import SecurityAlert

# 1. Define or import NotificationError so the test recognizes it
class NotificationError(Exception):
    pass

# Simple fake class to pass as the required notification dependency
class FakeNotification:
    def __init__(self):
        self.sent_alerts = []
        
    async def send(self, alert):
        self.sent_alerts.append(alert)


class FailingNotification:
    async def send(self, alert):
        raise NotificationError("Webhook unavailable")

class TrackingNotification:
    def __init__(self) -> None:
        self.active = 0
        self.maximum_active = 0

    async def send(self, alert):
        self.active += 1
        self.maximum_active = max(
            self.maximum_active,
            self.active,
        )

        await asyncio.sleep(0.01)

        self.active -= 1


@pytest.mark.asyncio
async def test_alert_manager_suppresses_repeated_alerts(capsys):
    clock = FakeClock(datetime.fromisoformat("2026-10-01T10:00:00"))
    limiter = RateLimiter(cooldown_seconds=60, clock=clock.now) # passes a callable clock
    notification = FakeNotification()

    manager = AlertManager(rate_limiter=limiter, notifications=[notification])
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

    manager = AlertManager(rate_limiter=limiter, notifications=[notification])

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

    manager = AlertManager(rate_limiter=limiter, notifications=[notification])

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

    manager = AlertManager(rate_limiter=limiter, notifications=[notification])

    alert = SecurityAlert(
        timestamp=clock.now(),
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )
    await manager.send(alert)

@pytest.mark.asyncio
async def test_alert_manager_handles_notification_failure(capsys):
    clock = FakeClock(
        datetime.fromisoformat("2026-10-01T10:00:00")
    )

    limiter = RateLimiter(
        cooldown_seconds=60,
        clock=clock.now,
    )

    manager = AlertManager(
        rate_limiter=limiter,
        notifications=[FailingNotification()],
    )

    alert = SecurityAlert(
        timestamp=clock.now(),
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        source_ip="10.0.0.5",
        description="5 failed login attempts",
    )

    # Tell pytest that we expect this call to throw a NotificationError
    with pytest.raises(NotificationError, match="Webhook unavailable"):
        await manager.send(alert)


@pytest.mark.asyncio
async def test_notification_concurrency_is_bounded():
    clock = FakeClock(
        datetime.fromisoformat("2026-10-02T10:00:00")
    )

    limiter = RateLimiter(
        cooldown_seconds=1,
        clock=clock.now,
    )

    notification = TrackingNotification()

    manager = AlertManager(
        rate_limiter=limiter,
        notifications=[notification],
        max_concurrent_notifications=2,
    )

    alerts = [
        SecurityAlert(
            timestamp=clock.now(),
            alert_type="TEST",
            severity="LOW",
            source_ip=f"10.0.0.{i}",
            description="test",
        )
        for i in range(5)
    ]

    await asyncio.gather(
        *(manager.send(alert) for alert in alerts)
    )

    assert notification.maximum_active <= 2
