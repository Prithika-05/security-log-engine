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
        self.last_sent: dict[str, datetime] = {}

    def allowed(self, key: str) -> bool:
        now = self.clock()

        last_sent = self.last_sent.get(key)

        if last_sent is None:
            self.last_sent[key] = now
            return True

        if now - last_sent >= self.cooldown:
            self.last_sent[key] = now
            return True

        return False