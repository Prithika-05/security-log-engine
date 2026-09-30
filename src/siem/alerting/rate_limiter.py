from collections.abc import Callable
from datetime import datetime, timedelta


class RateLimiter:
    def __init__(
        self,
        cooldown_seconds: int,
        clock: Callable[[], datetime],
    ) -> None:
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.clock = clock
        self.last_sent: datetime | None = None

    def allowed(self) -> bool:
        now = self.clock()

        if self.last_sent is None:
            self.last_sent = now
            return True

        if now - self.last_sent >= self.cooldown:
            self.last_sent = now
            return True

        return False