from datetime import datetime, timedelta
from siem.alerting.rate_limiter import RateLimiter

class FakeClock:
    def __init__(self, start: datetime) -> None:
        self.current = start

    # Ensure this method is present and named exactly 'now'
    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)

def test_first_alert_is_allowed():
    start = datetime.fromisoformat("2026-10-01T10:00:00")
    clock = FakeClock(start)

    limiter = RateLimiter(
        cooldown_seconds=60,
        clock=clock,
    )

    assert limiter.allowed() is True

def test_rate_limiter_is_per_key():
    start = datetime.fromisoformat("2026-09-30T10:00:00")
    clock = FakeClock(start)

    limiter = RateLimiter(
        cooldown_seconds=60,
        clock=clock.now,
    )

    assert limiter.allowed("10.0.0.5") is True
    clock.advance(20)
    
    # Same IP is still inside cooldown.
    assert limiter.allowed("10.0.0.5") is False
    
    # Different IP has its own cooldown.
    assert limiter.allowed("10.0.0.8") is True


def test_rate_limiter_allows_after_cooldown():
    start = datetime.fromisoformat("2026-09-30T10:00:00")
    clock = FakeClock(start)

    limiter = RateLimiter(
        cooldown_seconds=60,
        clock=clock.now,
    )

    assert limiter.allowed("10.0.0.5") is True
    clock.advance(59)
    assert limiter.allowed("10.0.0.5") is False
    clock.advance(1)
    assert limiter.allowed("10.0.0.5") is True

def test_alert_is_blocked_during_cooldown():
    start = datetime.fromisoformat("2026-10-01T10:00:00")
    clock = FakeClock(start)

    limiter = RateLimiter(
        cooldown_seconds=60,
        clock=clock,
    )

    assert limiter.allowed() is True

    clock.advance(20)

    assert limiter.allowed() is False

def test_alert_is_allowed_after_cooldown():
    start = datetime.fromisoformat("2026-10-01T10:00:00")
    clock = FakeClock(start)

    limiter = RateLimiter(
        cooldown_seconds=60,
        clock=clock,
    )

    assert limiter.allowed() is True

    clock.advance(60)

    assert limiter.allowed() is True

def test_alert_is_blocked_just_before_cooldown():
    start = datetime.fromisoformat("2026-10-01T10:00:00")
    clock = FakeClock(start)

    limiter = RateLimiter(
        cooldown_seconds=60,
        clock=clock,
    )

    assert limiter.allowed() is True

    clock.advance(59)

    assert limiter.allowed() is False