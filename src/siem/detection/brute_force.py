from collections import defaultdict, deque
from datetime import timedelta

from siem.models.alert import SecurityAlert
from siem.models.log_entry import LogEntry


class BruteForceDetector:
    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
    ) -> None:
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.failed_attempts: dict[str, deque] = defaultdict(deque)

    def process(self, entry: LogEntry) -> SecurityAlert | None:
        ...